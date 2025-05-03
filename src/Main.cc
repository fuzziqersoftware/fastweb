#define _STDC_FORMAT_MACROS

#include <event2/buffer.h>
#include <event2/bufferevent_ssl.h>
#include <event2/http.h>
#include <event2/listener.h>
#include <inttypes.h>
#include <openssl/err.h>
#include <openssl/ssl.h>
#include <pwd.h>
#include <signal.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>

#include <phosg/Filesystem.hh>
#include <string>
#include <thread>
#include <unordered_set>
#include <vector>

#include <phosg/Network.hh>
#include <phosg/Strings.hh>
#include <phosg/Time.hh>

#include "FileResourceManager.hh"
#include "MIMEType.hh"
#include "MemoryResourceManager.hh"

using namespace std;

bool should_exit = false;
bool should_reload = false;
pid_t reload_pid = 0;

struct ServerConfiguration {
  string user;

  string ssl_cert_filename;
  string ssl_ca_cert_filename;
  string ssl_key_filename;
  uint64_t ssl_cert_mtime;
  uint64_t ssl_ca_cert_mtime;
  uint64_t ssl_key_mtime;

  vector<string> data_directories;
  string index_resource_name;
  string not_found_resource_name;
  bool log_requests;

  vector<pair<string, int>> listen_addrs;
  vector<pair<string, int>> ssl_listen_addrs;
  vector<phosg::scoped_fd> listen_fds;
  vector<phosg::scoped_fd> ssl_listen_fds;
  size_t num_threads;

  pid_t signal_parent_pid;

  int gzip_compress_level;
  uint64_t mtime_check_secs;

  SSL_CTX* ssl_ctx;

  shared_ptr<const ResourceManagerBase::Resource> index_resource;
  shared_ptr<const ResourceManagerBase::Resource> not_found_resource;
  unique_ptr<ResourceManagerBase> resource_manager;

  ServerConfiguration()
      : log_requests(false),
        num_threads(0),
        signal_parent_pid(0),
        gzip_compress_level(6),
        mtime_check_secs(60),
        ssl_ctx(nullptr),
        index_resource(nullptr),
        not_found_resource(nullptr) {}
};

static shared_ptr<const ResourceManagerBase::Resource> default_not_found_resource(
    new ResourceManagerBase::Resource("File not found", 0, "text/plain"));

static void print_evbuffer_contents(struct evbuffer* buf) {
  // Warning: this is slow; it copies the data
  size_t size = evbuffer_get_length(buf);
  if (size) {
    string data(size, 0);
    evbuffer_copyout(buf, const_cast<char*>(data.data()), data.size());
    phosg::print_data(stderr, data);
  }
}

void handle_request(struct evhttp_request* req, void* ctx) {
  const ServerConfiguration* state = (const ServerConfiguration*)ctx;

  struct evkeyvalq* out_headers = evhttp_request_get_output_headers(req);
  evhttp_add_header(out_headers, "Server", "fastweb");

  string log_prefix;
  if (state->log_requests) {
    static const unordered_map<enum evhttp_cmd_type, const char*> name_for_method({
        {EVHTTP_REQ_GET, "GET"},
        {EVHTTP_REQ_POST, "POST"},
        {EVHTTP_REQ_HEAD, "HEAD"},
        {EVHTTP_REQ_PUT, "PUT"},
        {EVHTTP_REQ_DELETE, "DELETE"},
        {EVHTTP_REQ_OPTIONS, "OPTIONS"},
        {EVHTTP_REQ_TRACE, "TRACE"},
        {EVHTTP_REQ_CONNECT, "CONNECT"},
        {EVHTTP_REQ_PATCH, "PATCH"},
    });

    try {
      log_prefix = name_for_method.at(evhttp_request_get_command(req));
    } catch (const out_of_range&) {
      log_prefix = "__UNKNOWN_METHOD__";
    }
    log_prefix += ' ';
    log_prefix += evhttp_request_get_uri(req);
  }

  if (evhttp_request_get_command(req) != EVHTTP_REQ_GET) {
    evhttp_add_header(out_headers, "Content-Type", "text/plain");
    evbuffer_add_reference(evhttp_request_get_output_buffer(req), "Invalid request method", 22, nullptr, nullptr);
    evhttp_send_reply(req, 405, "Method Not Allowed", nullptr);
    return;
  }

  int code;
  const char* filename = evhttp_request_get_uri(req);
  try {
    // Get the relevant resource object
    shared_ptr<const ResourceManagerBase::Resource> res;
    try {
      res = state->resource_manager->get_resource(filename);
      code = 200;

    } catch (const out_of_range& e) {
      // No such resource... check for index first, then fall back to 404 pages
      if (!strcmp(filename, "/") && state->index_resource) {
        res = state->index_resource;
        code = 200;

      } else if (state->not_found_resource) {
        res = state->not_found_resource;
        code = 404;

      } else {
        res = default_not_found_resource;
        code = 404;
      }
    }

    // At this point res and code are always valid

    if (res->mime_type) {
      struct evkeyvalq* in_headers = evhttp_request_get_input_headers(req);

      // If the client gave If-None-Match, we might be able to send a 304
      bool send_not_modified = false;
      if (code != 404) {
        const char* in_if_none_match = evhttp_find_header(in_headers, "If-None-Match");
        send_not_modified = in_if_none_match && (res->etag == in_if_none_match);
      }
      if (send_not_modified) {
        code = 304;
        evhttp_send_reply(req, 304, "Not Modified", nullptr);

        // No ETag, it didn't match, or it's a 404
      } else {
        evhttp_add_header(out_headers, "Content-Type", res->mime_type);
        // Don't send ETag for 404s
        if (code == 200) {
          evhttp_add_header(out_headers, "ETag", res->etag.c_str());
        }

        bool gzip_response_added = false;
        if (!res->gzip_data.empty()) {
          const char* in_accept_encoding = evhttp_find_header(in_headers, "Accept-Encoding");

          if (in_accept_encoding && (strchr(in_accept_encoding, '*') || strstr(in_accept_encoding, "gzip"))) {
            evhttp_add_header(out_headers, "Content-Encoding", "gzip");
            evbuffer_add_reference(evhttp_request_get_output_buffer(req),
                res->gzip_data.data(), res->gzip_data.size(), nullptr, nullptr);
            gzip_response_added = true;
          }
        }

        if (!gzip_response_added) {
          evbuffer_add_reference(evhttp_request_get_output_buffer(req),
              res->data.data(), res->data.size(), nullptr, nullptr);
        }
        evhttp_send_reply(req, code, (code == 404) ? "Not Found" : "OK", nullptr);
      }

    } else {
      // If the not found page is a redirect, make browsers not cache it by
      // sending a 302 (temporary) instead of 301 (permanent)
      evhttp_add_header(out_headers, "Location", res->data.c_str());
      evhttp_send_reply(req, (code == 404) ? 302 : 301, (code == 404) ? "Temporary Redirect" : "Moved Permanently", nullptr);
    }

    if (state->log_requests) {
      phosg::log_info("Request: %s => %d (res=%s)", log_prefix.c_str(), code, res ? res->etag.c_str() : "(none)");
      struct evbuffer* buf = evhttp_request_get_input_buffer(req);
      print_evbuffer_contents(buf);
    }

  } catch (const exception& e) {
    struct evbuffer* out_buffer = evhttp_request_get_output_buffer(req);
    evbuffer_drain(out_buffer, evbuffer_get_length(out_buffer));
    evbuffer_add_reference(out_buffer, "Internal server error", 21, nullptr, nullptr);
    evhttp_send_reply(req, 500, "Internal Server Error", nullptr);

    if (state->log_requests) {
      phosg::log_info("Request: %s => 500 (%s)", log_prefix.c_str(), e.what());
      struct evbuffer* buf = evhttp_request_get_input_buffer(req);
      print_evbuffer_contents(buf);
    }
  }
}

static struct bufferevent* on_ssl_connection(struct event_base* base, void* ctx) {
  SSL_CTX* ssl_ctx = reinterpret_cast<SSL_CTX*>(ctx);
  SSL* ssl = SSL_new(ssl_ctx);
  return bufferevent_openssl_socket_new(base, -1, ssl, BUFFEREVENT_SSL_ACCEPTING, BEV_OPT_CLOSE_ON_FREE);
}

void http_server_thread(const ServerConfiguration& state) {
  unique_ptr<struct event_base, void (*)(struct event_base*)> base(event_base_new(), event_base_free);
  if (!base) {
    phosg::log_error("Error: can\'t open event base for http server");
    return;
  }

  vector<unique_ptr<struct evhttp, void (*)(struct evhttp*)>> servers;

  servers.emplace_back(evhttp_new(base.get()), evhttp_free);
  auto& server = servers.back();
  if (!server) {
    phosg::log_error("Error: can\'t create http server");
    return;
  }
  evhttp_set_gencb(server.get(), handle_request, (void*)&state);
  for (int fd : state.listen_fds) {
    evhttp_accept_socket(server.get(), fd);
  }

  if (!state.ssl_listen_fds.empty()) {
    servers.emplace_back(evhttp_new(base.get()), evhttp_free);
    auto& ssl_server = servers.back();
    if (!ssl_server) {
      phosg::log_error("Error: can\'t create ssl http server");
      return;
    }

    evhttp_set_bevcb(ssl_server.get(), on_ssl_connection, state.ssl_ctx);

    evhttp_set_gencb(ssl_server.get(), handle_request, (void*)&state);
    for (int fd : state.ssl_listen_fds) {
      evhttp_accept_socket(ssl_server.get(), fd);
    }
  }

  auto check_for_thread_exit = [](evutil_socket_t, short, void* ctx) {
    if (should_exit) {
      // Technically we should wait for connections to drain here, but we expect
      // all requests to be very fast, so we don't bother
      event_base_loopexit((struct event_base*)ctx, nullptr);
    }
  };

  struct timeval tv = phosg::usecs_to_timeval(5000000);
  struct event* ev = event_new(base.get(), -1, EV_PERSIST,
      check_for_thread_exit, base.get());
  event_add(ev, &tv);
  event_base_dispatch(base.get());
  event_del(ev);
}

void signal_handler(int signum) {
  if ((signum == SIGTERM) || (signum == SIGINT)) {
    should_exit = true;
  } else if (signum == SIGHUP) {
    should_reload = true;
  } else if (signum == SIGCHLD) {
    reload_pid = -reload_pid;
  }
}

void print_usage(const char* argv0) {
  fprintf(stderr, "\
Usage: %s [options] [data-directory [data_directory ...]]\n\
\n\
Options:\n\
  --fd=N\n\
      Accept unencrypted connections on listening file descriptor N. This\n\
      option can be given multiple times.\n\
  --ssl-fd=N\n\
      Accept TLS connections on listening file descriptor N. This option can\n\
      be given multiple times)\n\
  --listen=PORT\n\
      Listen on TCP port PORT. This option can be given multiple times. You\n\
      will need to use sudo or otherwise gain root privileges to listen on\n\
      ports less than 1024.\n\
  --listen=ADDR:PORT\n\
      Listen on TCP port PORT on interface ADDR. This option can be given\n\
      multiple times. Like the above, you will need sudo for ports < 1024.\n\
  --listen=SOCKET_PATH\n\
      Listen on Unix socket SOCKET_PATH. This option can be given multiple\n\
      times.\n\
  --ssl-listen=...\n\
      Listen for TLS connections. This option has the same behaviors as\n\
      --listen, but accepted connections will be treated as encrypted.\n\
  --ssl-cert=FILENAME\n\
      Load SSL certificate from this .pem file. This option is required if\n\
      --ssl-fd or --ssl-listen is given.\n\
  --ssl-ca-cert=FILENAME\n\
      Load SSL CA certificate from this .pem file. This option is not required\n\
      if --ssl-fd or --ssl-listen is given, but should be used in most cases.\n\
  --ssl-key=FILENAME\n\
      Load SSL private key from this .pem file. This option is required if\n\
      --ssl-fd or --ssl-listen is given)\n\
  --threads=N\n\
      Use N threads to serve requests. If omitted, the default is to use as\n\
      many threads as there are CPU cores in the system.\n\
  --user=USERNAME\n\
      Drop privileges to the given user before serving any requests. If this\n\
      option is given and reloading is enabled, the SSL certificate and key and\n\
      all files in the data directories must be readable by the specified user.\n\
      In contrast, ports < 1024 may still be used if --user is given and do not\n\
      cause any problems when reloading because the already-open file\n\
      descriptor is passed directly to the new process during reloading.\n\
  --index=/NAME\n\
      Serve the given object for requests to /. The object name should be\n\
      relative to one of the data directories. Usually something like\n\
      /index.html is appropriate here.\n\
  --404=/NAME\n\
      Serve the given object in place of missing objects (but serve it with an\n\
      HTTP 404 response code instead of 200). Line --index, the object name\n\
      should be relative to one of the data directories.\n\
  --files\n\
      Don\'t preload resources; instead, read files at request time. This makes\n\
      fastweb significantly less fast, but saves a lot of memory and allows for\n\
      immediate change response (which is necessary when doing certbot\n\
      verifications, for example).\n\
  --gzip-level=N\n\
      Generate gzip-compressed versions of all resources with this compression\n\
      level (0-9). 9 gives the slowest compression and the smallest objects;\n\
      1 gives the fastest compression and much larger objects. 0 disables\n\
      compression entirely (this saves memory and startup time but increases\n\
      network throughput). In some rare cases, the compressed version of a file\n\
      is actually larger than the original file; when this happens, fastweb\n\
      serves the uncompressed file even when compression is enabled. The\n\
      default compression level is 6.\n\
  --mtime-check-secs=N\n\
      Check for changes to files on disk every N seconds and reload if needed.\n\
      This also enables monitoring for changes to the SSL certificate and\n\
      private key. If set to 0, disable all automatic reloading. The default is\n\
      to check for changes every 5 seconds. (These checks occur in the main\n\
      thread and do not block any request processing.)\n\
  --log-requests\n\
      Log all incoming requests and the response codes sent to them. Be warned:\n\
      this will make fastweb significantly less fast.\n\
\n\
At least one --fd/--listen or --ssl-fd/--ssl-listen option must be given.\n\
If no data directories are given, the current directory is used.\n",
      argv0);
}

int main(int argc, char** argv) {
  ServerConfiguration state;
  size_t num_bad_options = 0;

  auto add_listen_addr = [&](const char* arg, bool is_ssl) {
    auto& addrs = is_ssl ? state.ssl_listen_addrs : state.listen_addrs;
    auto parts = phosg::split(arg, ':');
    if (parts.size() == 1) {
      if (!parts[0].empty() && (parts[0][0] == '/')) {
        // It's a unix socket
        addrs.emplace_back(make_pair(parts[0], 0));
      } else {
        // It's a port number
        addrs.emplace_back(make_pair("", stoi(parts[0])));
      }
    } else if (parts.size() == 2) {
      // It's an addr:port pair
      addrs.emplace_back(make_pair(parts[0], stoi(parts[1])));
    } else {
      phosg::log_error("Bad netloc in command line: %s", arg);
      num_bad_options++;
    }
  };

  state.resource_manager.reset(new MemoryResourceManager());
  for (int x = 1; x < argc; x++) {
    if (!strncmp(argv[x], "--signal-parent=", 16)) {
      state.signal_parent_pid = atoi(&argv[x][16]);

    } else if (!strncmp(argv[x], "--fd=", 5)) {
      state.listen_fds.emplace_back(atoi(&argv[x][5]));

    } else if (!strncmp(argv[x], "--ssl-fd=", 9)) {
      state.ssl_listen_fds.emplace_back(atoi(&argv[x][9]));

    } else if (!strncmp(argv[x], "--ssl-cert=", 11)) {
      state.ssl_cert_filename = &argv[x][11];
      state.ssl_cert_mtime = phosg::stat(state.ssl_cert_filename).st_mtime;

    } else if (!strncmp(argv[x], "--ssl-ca-cert=", 14)) {
      state.ssl_ca_cert_filename = &argv[x][14];
      state.ssl_ca_cert_mtime = phosg::stat(state.ssl_ca_cert_filename).st_mtime;

    } else if (!strncmp(argv[x], "--ssl-key=", 10)) {
      state.ssl_key_filename = &argv[x][10];
      state.ssl_key_mtime = phosg::stat(state.ssl_key_filename).st_mtime;

    } else if (!strncmp(argv[x], "--threads=", 10)) {
      state.num_threads = atoi(&argv[x][10]);

    } else if (!strncmp(argv[x], "--user=", 7)) {
      state.user = &argv[x][7];

    } else if (!strncmp(argv[x], "--index=", 8)) {
      state.index_resource_name = &argv[x][8];

    } else if (!strncmp(argv[x], "--404=", 6)) {
      state.not_found_resource_name = &argv[x][6];

    } else if (!strcmp(argv[x], "--files")) {
      state.resource_manager.reset(new FileResourceManager());

    } else if (!strncmp(argv[x], "--gzip-level=", 13)) {
      state.gzip_compress_level = atoi(&argv[x][13]);

    } else if (!strncmp(argv[x], "--mtime-check-secs=", 19)) {
      state.mtime_check_secs = atoi(&argv[x][19]);

    } else if (!strncmp(argv[x], "--listen=", 9)) {
      add_listen_addr(&argv[x][9], false);

    } else if (!strncmp(argv[x], "--ssl-listen=", 9)) {
      add_listen_addr(&argv[x][13], true);

    } else if (!strcmp(argv[x], "--log-requests")) {
      state.log_requests = true;

    } else {
      state.data_directories.emplace_back(argv[x]);
    }
  }

  // Check command-line options
  if (num_bad_options) {
    print_usage(argv[0]);
    return 1;
  }
  if (state.listen_fds.empty() && state.ssl_listen_fds.empty() &&
      state.listen_addrs.empty() && state.ssl_listen_addrs.empty()) {
    phosg::log_error("No listening sockets or addresses given");
    print_usage(argv[0]);
    return 1;
  }
  if (state.data_directories.empty()) {
    state.data_directories.emplace_back("./");
    phosg::log_warning("No data directories given; using the current directory");
  }
  if ((!state.ssl_listen_fds.empty() || !state.ssl_listen_addrs.empty()) &&
      (state.ssl_cert_filename.empty() || state.ssl_key_filename.empty())) {
    phosg::log_error("An SSL certificate and key must be given if SSL listen sockets or addresses are given");
    print_usage(argv[0]);
    return 1;
  }
  if ((!state.ssl_listen_fds.empty() || !state.ssl_listen_addrs.empty()) &&
      state.ssl_ca_cert_filename.empty()) {
    phosg::log_warning("No CA certificate filename given; some clients may reject this server\'s certificate");
  }

  // Open listening sockets. This has to happen before dropping privileges so we
  // can listen on privileged ports; this doesn't cause problems with reloading
  // because fds are passed directly to the child process and it doesn't have to
  // call bind()
  for (int ssl = 0; ssl < 2; ssl++) {
    for (const auto& listen_addr : (ssl ? state.ssl_listen_addrs : state.listen_addrs)) {
      int fd = phosg::listen(listen_addr.first, listen_addr.second, SOMAXCONN);
      if (fd < 0) {
        phosg::log_error("Can\'t open listening socket; addr=%s, port=%d", listen_addr.first.c_str(), listen_addr.second);
        return 2;
      }

      evutil_make_socket_nonblocking(fd);
      if (ssl) {
        state.ssl_listen_fds.emplace_back(fd);
      } else {
        state.listen_fds.emplace_back(fd);
      }

      phosg::log_info("Opened listening socket %d: addr=%s, port=%d", fd, listen_addr.first.c_str(), listen_addr.second);
    }
  }

  // Drop privileges if requested. This happens before loading the data so we
  // can detect permissions problems at initial startup instead of at reload
  if (!state.user.empty()) {
    if ((getuid() != 0) || (getgid() != 0)) {
      phosg::log_error("Not started as root; can\'t switch to user %s", state.user.c_str());
      return 2;
    }

    struct passwd* pw = getpwnam(state.user.c_str());
    if (!pw) {
      string error = phosg::string_for_error(errno);
      phosg::log_error("User %s not found (%s)", state.user.c_str(), error.c_str());
      return 2;
    }

    if (setgid(pw->pw_gid) != 0) {
      string error = phosg::string_for_error(errno);
      phosg::log_error("Can\'t switch to group %d (%s)", pw->pw_gid, error.c_str());
      return 2;
    }
    if (setuid(pw->pw_uid) != 0) {
      string error = phosg::string_for_error(errno);
      phosg::log_error("Can\'t switch to user %d (%s)", pw->pw_uid, error.c_str());
      return 2;
    }
    phosg::log_info("Switched to user %s (%d:%d)", state.user.c_str(), pw->pw_uid, pw->pw_gid);
  }

  // Load data
  uint64_t load_start_time = phosg::now();
  for (const auto& directory : state.data_directories) {
    state.resource_manager->add_directory(directory, state.gzip_compress_level);
  }
  uint64_t load_end_time = phosg::now();
  phosg::log_info("Loaded %zu resources, including %zu files (%zu bytes, %zu compressed, %g%%), in %" PRIu64 " microseconds",
      state.resource_manager->resource_count(),
      state.resource_manager->file_count(),
      state.resource_manager->resource_bytes(),
      state.resource_manager->compressed_resource_bytes(),
      (static_cast<float>(state.resource_manager->compressed_resource_bytes()) / state.resource_manager->resource_bytes()) * 100,
      load_end_time - load_start_time);
  if (state.mtime_check_secs) {
    phosg::log_info("Checking for changes to these resources every %" PRIu64 " seconds", state.mtime_check_secs);
  }

  // Resolve special resources
  if (!state.index_resource_name.empty()) {
    try {
      state.index_resource = state.resource_manager->get_resource(state.index_resource_name);
    } catch (const out_of_range& e) {
      phosg::log_error("Index resource %s does not exist", state.index_resource_name.c_str());
      return 2;
    }
  }
  if (!state.not_found_resource_name.empty()) {
    try {
      state.not_found_resource = state.resource_manager->get_resource(state.not_found_resource_name);
    } catch (const out_of_range& e) {
      phosg::log_error("404 resource %s does not exist", state.not_found_resource_name.c_str());
      return 2;
    }
  }

  // Load the SSL context if needed
  if (!state.ssl_listen_fds.empty()) {
    SSL_load_error_strings();
    OpenSSL_add_ssl_algorithms();

    state.ssl_ctx = SSL_CTX_new(TLS_method());
    if (!state.ssl_ctx) {
      phosg::log_error("Can\'t create openssl context");
      ERR_print_errors_fp(stderr);
      return 2;
    }
    SSL_CTX_set_min_proto_version(state.ssl_ctx, TLS1_2_VERSION);
    SSL_CTX_set_cipher_list(state.ssl_ctx, "ECDH+AESGCM:ECDH+CHACHA20:DH+AESGCM:ECDH+AES256:DH+AES256:ECDH+AES128:DH+AES:RSA+AESGCM:RSA+AES:!aNULL:!MD5:!DSS:!AESCCM:!RSA");
    SSL_CTX_set_ecdh_auto(state.ssl_ctx, 1);
    if (!state.ssl_ca_cert_filename.empty()) {
      SSL_CTX_load_verify_locations(state.ssl_ctx, state.ssl_ca_cert_filename.c_str(), nullptr);
      phosg::log_info("Loaded ssl ca certificate from %s", state.ssl_ca_cert_filename.c_str());
    }
    if (SSL_CTX_use_certificate_file(state.ssl_ctx,
            state.ssl_cert_filename.c_str(), SSL_FILETYPE_PEM) <= 0) {
      phosg::log_error("Can\'t open %s", state.ssl_cert_filename.c_str());
      ERR_print_errors_fp(stderr);
      return 2;
    }
    phosg::log_info("Loaded ssl certificate from %s", state.ssl_cert_filename.c_str());
    if (SSL_CTX_use_PrivateKey_file(state.ssl_ctx,
            state.ssl_key_filename.c_str(), SSL_FILETYPE_PEM) <= 0) {
      phosg::log_error("Can\'t open %s", state.ssl_key_filename.c_str());
      ERR_print_errors_fp(stderr);
      return 2;
    }
    phosg::log_info("Loaded ssl private key from %s", state.ssl_key_filename.c_str());
  }

  // Start server threads
  if (state.num_threads == 0) {
    state.num_threads = thread::hardware_concurrency();
  }

  vector<thread> server_threads;
  while (server_threads.size() < state.num_threads) {
    server_threads.emplace_back(http_server_thread, cref(state));
  }
  phosg::log_info("Started %zu server threads", state.num_threads);

  // Register signal handlers
  signal(SIGPIPE, SIG_IGN);
  signal(SIGTERM, signal_handler);
  signal(SIGINT, signal_handler);
  signal(SIGHUP, signal_handler);
  signal(SIGCHLD, signal_handler);

  // Kill the parent if needed
  if (state.signal_parent_pid) {
    if (kill(state.signal_parent_pid, SIGTERM)) {
      phosg::log_error("Failed to kill parent process %d", state.signal_parent_pid);
      return 1;
    }
    phosg::log_info("Killed parent process %d", state.signal_parent_pid);
  }

  // Reloading is implemented as follows:
  // - Process receives a SIGHUP, which tells it to start reloading. It runs a
  //   child process, which loads the new dataset.
  // - When child process is ready and accepting connections, it sends a SIGTERM
  //   to the parent.
  // - If the child process fails for any reason before sending SIGTERM, it
  //   terminates with a nonzero exit code and the parent receives a SIGCHLD.
  sigset_t sigs;
  sigemptyset(&sigs);
  while (!should_exit) {
    if (state.mtime_check_secs) {
      usleep(state.mtime_check_secs * 1000 * 1000);

      bool files_changed = state.resource_manager->any_resource_changed();
      if (!files_changed && state.ssl_ctx) {
        files_changed |= (static_cast<uint64_t>(phosg::stat(state.ssl_cert_filename).st_mtime) != state.ssl_cert_mtime);
        files_changed |= !state.ssl_ca_cert_filename.empty() && (static_cast<uint64_t>(phosg::stat(state.ssl_ca_cert_filename).st_mtime) != state.ssl_ca_cert_mtime);
        files_changed |= (static_cast<uint64_t>(phosg::stat(state.ssl_key_filename).st_mtime) != state.ssl_key_mtime);
      }

      if (!should_exit && !reload_pid && !should_reload && files_changed) {
        should_reload = true;
        phosg::log_info("Some files were changed on disk; reloading");
      }
    } else {
      sigsuspend(&sigs);
    }

    if (should_exit) {
      phosg::log_info("Exit request received");
    }

    if (should_reload) {
      phosg::log_info("Reload request received");

      pid_t parent_pid = getpid();
      reload_pid = fork();
      if (reload_pid < 0) {
        string error = phosg::string_for_error(errno);
        phosg::log_error("Reload requested, but can\'t fork (%s)", error.c_str());

      } else if (reload_pid == 0) {
        // Child process: exec ourself with args to pass the listening fds down
        vector<string> args;
        args.emplace_back(argv[0]);
        args.emplace_back(phosg::string_printf("--signal-parent=%d", parent_pid));
        args.emplace_back(phosg::string_printf("--mtime-check-secs=%" PRIu64, state.mtime_check_secs));
        args.emplace_back(phosg::string_printf("--threads=%zu", state.num_threads));
        if (!state.index_resource_name.empty()) {
          args.emplace_back("--index=" + state.index_resource_name);
        }
        if (!state.not_found_resource_name.empty()) {
          args.emplace_back("--404=" + state.not_found_resource_name);
        }
        if (!state.ssl_cert_filename.empty()) {
          args.emplace_back("--ssl-cert=" + state.ssl_cert_filename);
        }
        if (!state.ssl_ca_cert_filename.empty()) {
          args.emplace_back("--ssl-ca-cert=" + state.ssl_ca_cert_filename);
        }
        if (!state.ssl_key_filename.empty()) {
          args.emplace_back("--ssl-key=" + state.ssl_key_filename);
        }
        for (int fd : state.listen_fds) {
          args.emplace_back(phosg::string_printf("--fd=%d", fd));
        }
        for (int fd : state.ssl_listen_fds) {
          args.emplace_back(phosg::string_printf("--ssl-fd=%d", fd));
        }
        if (state.log_requests) {
          args.emplace_back("--log-requests");
        }
        for (const string& directory : state.data_directories) {
          args.emplace_back(directory);
        }
        // Note: we don't have to pass --user because we're forking, so the
        // child process will have the same user already
        vector<char*> argv;
        argv.reserve(args.size() + 1);
        for (const string& arg : args) {
          argv.emplace_back(const_cast<char*>(arg.c_str()));
        }
        argv.emplace_back(nullptr);

        execvp(argv[0], argv.data());

        string error = phosg::string_for_error(errno);
        phosg::log_error("execvp returned (%s)", error.c_str());
        return 1;
      }

      should_reload = false;
    }

    if (reload_pid < 0) {
      phosg::log_info("Child process terminated; reload failed");

      // Reap all relevant zombies
      int exit_status;
      pid_t pid = waitpid(-1, &exit_status, WNOHANG);
      while (pid != -1) {
        if (WIFEXITED(exit_status)) {
          phosg::log_warning("Child process %d exited with code %d", pid, WEXITSTATUS(exit_status));
        } else if (WIFSIGNALED(exit_status)) {
          phosg::log_warning("Child process %d exited due to signal %d", pid, WTERMSIG(exit_status));
        } else {
          phosg::log_warning("Child process %d exited with status %d", pid, exit_status);
        }

        pid = waitpid(-1, &exit_status, WNOHANG);
      }
      if (errno != ECHILD) {
        string error = phosg::string_for_error(errno);
        phosg::log_warning("Failed to reap zombies: %s", error.c_str());
      }

      reload_pid = 0;
    }
  }

  // Close listening sockets, then wait for worker threads to terminate
  for (int fd : state.listen_fds) {
    close(fd);
  }
  for (int fd : state.ssl_listen_fds) {
    close(fd);
  }
  for (auto& t : server_threads) {
    t.join();
  }

  // Clean up openssl stuff
  if (state.ssl_ctx) {
    SSL_CTX_free(state.ssl_ctx);
    EVP_cleanup();
  }

  phosg::log_info("All threads exited");
  return 0;
}
