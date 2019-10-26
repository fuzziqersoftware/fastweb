#define _STDC_FORMAT_MACROS

#include <event2/listener.h>
#include <event2/buffer.h>
#include <event2/bufferevent_ssl.h>
#include <event2/http.h>
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

#include "MIMEType.hh"
#include "ResourceManager.hh"

using namespace std;



bool should_exit = false;
bool should_reload = false;
pid_t reload_pid = 0;

struct ServerConfiguration {
  string user;

  string ssl_cert_filename;
  string ssl_key_filename;
  uint64_t ssl_cert_mtime;
  uint64_t ssl_key_mtime;

  string index_resource_name;
  string not_found_resource_name;
  vector<string> data_directories;
  vector<pair<string, int>> listen_addrs;
  vector<pair<string, int>> ssl_listen_addrs;
  unordered_set<int> listen_fds;
  unordered_set<int> ssl_listen_fds;
  size_t num_threads;
  pid_t signal_parent_pid;
  int gzip_compress_level;
  uint64_t mtime_check_secs;

  SSL_CTX* ssl_ctx;

  const ResourceManager::Resource* index_resource;
  const ResourceManager::Resource* not_found_resource;
  ResourceManager resource_manager;

  ServerConfiguration() : num_threads(0), signal_parent_pid(0),
      gzip_compress_level(6), mtime_check_secs(60), ssl_ctx(NULL),
      index_resource(NULL), not_found_resource(NULL) { }
};

static ResourceManager::Resource default_not_found_resource(
    "File not found", 0, "text/plain");



void handle_request(struct evhttp_request* req, void* ctx) {

  const ServerConfiguration* state = (const ServerConfiguration*)ctx;

  struct evkeyvalq* out_headers = evhttp_request_get_output_headers(req);
  evhttp_add_header(out_headers, "Server", "fastweb");

  int code;

  const char* filename = evhttp_request_get_uri(req);
  try {
    // get the relevant resource object
    const ResourceManager::Resource* res = NULL;
    try {
      res = &state->resource_manager.get_resource(filename);
      code = 200;

    } catch (const out_of_range& e) {
      // no such resource... check for index first, then fall back to 404 pages
      if (!strcmp(filename, "/") && state->index_resource) {
        res = state->index_resource;
        code = 200;

      } else if (state->not_found_resource) {
        res = state->not_found_resource;
        code = 404;

      } else {
        res = &default_not_found_resource;
        code = 404;
      }
    }

    // at this point res and code are always valid

    if (res->mime_type) {
      struct evkeyvalq* in_headers = evhttp_request_get_input_headers(req);

      // if the client gave If-None-Match, we might be able to send a 304
      bool send_not_modified = false;
      if (code != 404) {
        const char* in_if_none_match = evhttp_find_header(in_headers,
            "If-None-Match");
        send_not_modified = in_if_none_match &&
            !strcmp(in_if_none_match, res->etag);
      }
      if (send_not_modified) {
        evhttp_send_reply(req, 304, "Not Modified", NULL);

      // no ETag, it didn't match, or it's a 404
      } else {
        evhttp_add_header(out_headers, "Content-Type", res->mime_type);
        // don't send ETag for 404s
        if (code == 200) {
          evhttp_add_header(out_headers, "ETag", res->etag);
        }

        bool gzip_response_added = false;
        if (!res->gzip_data.empty()) {
          const char* in_accept_encoding = evhttp_find_header(in_headers,
              "Accept-Encoding");

          if (in_accept_encoding &&
              (strchr(in_accept_encoding, '*') ||
               strstr(in_accept_encoding, "gzip"))) {
            evhttp_add_header(out_headers, "Content-Encoding", "gzip");
            evbuffer_add_reference(evhttp_request_get_output_buffer(req),
                res->gzip_data.data(), res->gzip_data.size(), NULL, NULL);
            gzip_response_added = true;
          }
        }

        if (!gzip_response_added) {
          evbuffer_add_reference(evhttp_request_get_output_buffer(req),
              res->data.data(), res->data.size(), NULL, NULL);
        }
        evhttp_send_reply(req, code, (code == 404) ? "Not Found" : "OK", NULL);
      }

    } else {
      // if the not found page is a redirect, make browsers not cache it by
      // sending a 302 (temporary) instead of 301 (permanent)
      evhttp_add_header(out_headers, "Location", res->data.c_str());
      evhttp_send_reply(req, (code == 404) ? 302 : 301,
          (code == 404) ? "Temporary Redirect" : "Moved Permanently", NULL);
    }

  } catch (...) {
    struct evbuffer* out_buffer = evhttp_request_get_output_buffer(req);
    evbuffer_drain(out_buffer, evbuffer_get_length(out_buffer));
    evbuffer_add_reference(out_buffer, "Internal server error", 21, NULL, NULL);
    evhttp_send_reply(req, 500, "Internal Server Error", NULL);
  }
}



static struct bufferevent* on_ssl_connection(struct event_base* base, void* ctx) {
  SSL_CTX* ssl_ctx = reinterpret_cast<SSL_CTX*>(ctx);
  SSL* ssl = SSL_new(ssl_ctx);
  return bufferevent_openssl_socket_new(base, -1, ssl,
      BUFFEREVENT_SSL_ACCEPTING, BEV_OPT_CLOSE_ON_FREE);
}

void http_server_thread(const ServerConfiguration& state) {

  unique_ptr<struct event_base, void(*)(struct event_base*)> base(
      event_base_new(), event_base_free);
  if (!base) {
    log(ERROR, "error: can\'t open event base for http server");
    return;
  }

  vector<unique_ptr<struct evhttp, void(*)(struct evhttp*)>> servers;

  servers.emplace_back(evhttp_new(base.get()), evhttp_free);
  auto& server = servers.back();
  if (!server) {
    log(ERROR, "error: can\'t create http server");
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
      log(ERROR, "error: can\'t create ssl http server");
      return;
    }

    evhttp_set_bevcb(ssl_server.get(), on_ssl_connection, state.ssl_ctx);

    evhttp_set_gencb(ssl_server.get(), handle_request, (void*)&state);
    for (int fd : state.ssl_listen_fds) {
      evhttp_accept_socket(ssl_server.get(), fd);
    }
  }

  auto check_for_thread_exit = [](evutil_socket_t fd, short what, void* ctx) {
    if (should_exit) {
      // technically we should wait for connections to drain here, but we expect
      // all requests to be very fast, so we don't bother
      event_base_loopexit((struct event_base*)ctx, NULL);
    }
  };

  struct timeval tv = usecs_to_timeval(5000000);
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
\n\
At least one --fd/--listen or --ssl-fd/--ssl-listen option must be given.\n\
If no data directories are given, the current directory is used.\n", argv0);
}

int main(int argc, char **argv) {

  log(INFO, "fuzziqer software fastweb");

  ServerConfiguration state;
  size_t num_bad_options = 0;

  auto add_listen_addr = [&](const char* arg, bool is_ssl) {
    auto& addrs = is_ssl ? state.ssl_listen_addrs : state.listen_addrs;
    auto parts = split(arg, ':');
    if (parts.size() == 1) {
      if (!parts[0].empty() && (parts[0][0] == '/')) {
        // it's a unix socket
        addrs.emplace_back(make_pair(parts[0], 0));
      } else {
        // it's a port number
        addrs.emplace_back(make_pair("", stoi(parts[0])));
      }
    } else if (parts.size() == 2) {
      // it's an addr:port pair
      addrs.emplace_back(make_pair(parts[0], stoi(parts[1])));
    } else {
      log(ERROR, "bad netloc in command line: %s", arg);
      num_bad_options++;
    }
  };

  for (int x = 1; x < argc; x++) {
    if (!strncmp(argv[x], "--signal-parent=", 16)) {
      state.signal_parent_pid = atoi(&argv[x][16]);

    } else if (!strncmp(argv[x], "--fd=", 5)) {
      state.listen_fds.emplace(atoi(&argv[x][5]));

    } else if (!strncmp(argv[x], "--ssl-fd=", 9)) {
      state.ssl_listen_fds.emplace(atoi(&argv[x][9]));

    } else if (!strncmp(argv[x], "--ssl-cert=", 11)) {
      state.ssl_cert_filename = &argv[x][11];
      state.ssl_cert_mtime = stat(state.ssl_cert_filename).st_mtime;

    } else if (!strncmp(argv[x], "--ssl-key=", 10)) {
      state.ssl_key_filename = &argv[x][10];
      state.ssl_key_mtime = stat(state.ssl_key_filename).st_mtime;

    } else if (!strncmp(argv[x], "--threads=", 10)) {
      state.num_threads = atoi(&argv[x][10]);

    } else if (!strncmp(argv[x], "--user=", 7)) {
      state.user = &argv[x][7];

    } else if (!strncmp(argv[x], "--index=", 8)) {
      state.index_resource_name = &argv[x][8];

    } else if (!strncmp(argv[x], "--404=", 6)) {
      state.not_found_resource_name = &argv[x][6];

    } else if (!strncmp(argv[x], "--gzip-level=", 13)) {
      state.gzip_compress_level = atoi(&argv[x][13]);

    } else if (!strncmp(argv[x], "--mtime-check-secs=", 19)) {
      state.mtime_check_secs = atoi(&argv[x][19]);

    } else if (!strncmp(argv[x], "--listen=", 9)) {
      add_listen_addr(&argv[x][9], false);

    } else if (!strncmp(argv[x], "--ssl-listen=", 9)) {
      add_listen_addr(&argv[x][13], true);

    } else {
      state.data_directories.emplace_back(argv[x]);
    }
  }

  // check command-line options
  if (num_bad_options) {
    print_usage(argv[0]);
    return 1;
  }
  if (state.listen_fds.empty() && state.ssl_listen_fds.empty() &&
      state.listen_addrs.empty() && state.ssl_listen_addrs.empty()) {
    log(ERROR, "no listening sockets or addresses given");
    print_usage(argv[0]);
    return 1;
  }
  if (state.data_directories.empty()) {
    state.data_directories.emplace_back("./");
    log(WARNING, "no data directories given; using the current directory");
  }
  if ((!state.ssl_listen_fds.empty() || !state.ssl_listen_addrs.empty()) &&
      (state.ssl_cert_filename.empty() || state.ssl_key_filename.empty())) {
    log(ERROR, "an SSL certificate and key must be given if SSL listen sockets or addresses are given");
    print_usage(argv[0]);
    return 1;
  }

  // load data
  uint64_t load_start_time = now();
  for (const auto& directory : state.data_directories) {
    state.resource_manager.add_directory(directory, state.gzip_compress_level);
  }
  uint64_t load_end_time = now();
  log(INFO, "loaded %zu resources, including %zu files (%zu bytes, %zu compressed, %g%%), in %" PRIu64 " microseconds",
      state.resource_manager.resource_count(),
      state.resource_manager.file_count(),
      state.resource_manager.resource_bytes(),
      state.resource_manager.compressed_resource_bytes(),
      ((float)state.resource_manager.compressed_resource_bytes() / state.resource_manager.resource_bytes()) * 100,
      load_end_time - load_start_time);
  if (state.mtime_check_secs) {
    log(INFO, "checking for changes to these resources every %" PRIu64 " seconds", state.mtime_check_secs);
  }

  // resolve special resources
  if (!state.index_resource_name.empty()) {
    try {
      state.index_resource = &state.resource_manager.get_resource(state.index_resource_name);
    } catch (const out_of_range& e) {
      log(ERROR, "index resource %s does not exist", state.index_resource_name.c_str());
      return 2;
    }
  }
  if (!state.not_found_resource_name.empty()) {
    try {
      state.not_found_resource = &state.resource_manager.get_resource(state.not_found_resource_name);
    } catch (const out_of_range& e) {
      log(ERROR, "404 resource %s does not exist", state.not_found_resource_name.c_str());
      return 2;
    }
  }

  // open listening sockets
  for (int ssl = 0; ssl < 2; ssl++) {
    for (const auto& listen_addr : (ssl ? state.ssl_listen_addrs : state.listen_addrs)) {
      int fd = listen(listen_addr.first, listen_addr.second, SOMAXCONN);
      if (fd < 0) {
        log(ERROR, "can\'t open listening socket; addr=%s, port=%d",
            listen_addr.first.c_str(), listen_addr.second);
        return 2;
      }

      evutil_make_socket_nonblocking(fd);
      if (ssl) {
        state.ssl_listen_fds.emplace(fd);
      } else {
        state.listen_fds.emplace(fd);
      }

      log(INFO, "opened listening socket %d: addr=%s, port=%d",
          fd, listen_addr.first.c_str(), listen_addr.second);
    }
  }

  // load the ssl context if needed
  if (!state.ssl_listen_fds.empty()) {
    SSL_load_error_strings();
    OpenSSL_add_ssl_algorithms();

    state.ssl_ctx = SSL_CTX_new(TLS_method());
    if (!state.ssl_ctx) {
      log(ERROR, "can\'t create openssl context");
      ERR_print_errors_fp(stderr);
      return 2;
    }
    SSL_CTX_set_min_proto_version(state.ssl_ctx, TLS1_2_VERSION);
    SSL_CTX_set_ecdh_auto(state.ssl_ctx, 1);
    if (SSL_CTX_use_certificate_file(state.ssl_ctx,
        state.ssl_cert_filename.c_str(), SSL_FILETYPE_PEM) <= 0) {
      log(ERROR, "can\'t open %s", state.ssl_cert_filename.c_str());
      ERR_print_errors_fp(stderr);
      return 2;
    }
    log(INFO, "loaded ssl certificate from %s", state.ssl_cert_filename.c_str());
    if (SSL_CTX_use_PrivateKey_file(state.ssl_ctx,
        state.ssl_key_filename.c_str(), SSL_FILETYPE_PEM) <= 0) {
      log(ERROR, "can\'t open %s", state.ssl_key_filename.c_str());
      ERR_print_errors_fp(stderr);
      return 2;
    }
    log(INFO, "loaded ssl private key from %s", state.ssl_key_filename.c_str());
  }

  // drop privileges if requested
  if (!state.user.empty()) {
    if ((getuid() != 0) || (getgid() != 0)) {
      log(ERROR, "not started as root; can\'t switch to user %s", state.user.c_str());
      return 2;
    }

    struct passwd* pw = getpwnam(state.user.c_str());
    if (!pw) {
      string error = string_for_error(errno);
      log(ERROR, "user %s not found (%s)", state.user.c_str(), error.c_str());
      return 2;
    }

    if (setgid(pw->pw_gid) != 0) {
      string error = string_for_error(errno);
      log(ERROR, "can\'t switch to group %d (%s)", pw->pw_gid, error.c_str());
      return 2;
    }
    if (setuid(pw->pw_uid) != 0) {
      string error = string_for_error(errno);
      log(ERROR, "can\'t switch to user %d (%s)", pw->pw_uid, error.c_str());
      return 2;
    }
    log(INFO, "switched to user %s (%d:%d)",  state.user.c_str(), pw->pw_uid,
        pw->pw_gid);
  }

  // start server threads
  if (state.num_threads == 0) {
    state.num_threads = thread::hardware_concurrency();
  }

  vector<thread> server_threads;
  while (server_threads.size() < state.num_threads) {
    server_threads.emplace_back(http_server_thread, cref(state));
  }
  log(INFO, "started %d server threads", state.num_threads);

  // register signal handlers
  signal(SIGPIPE, SIG_IGN);
  signal(SIGTERM, signal_handler);
  signal(SIGINT, signal_handler);
  signal(SIGHUP, signal_handler);
  signal(SIGCHLD, signal_handler);

  // kill the parent if needed
  if (state.signal_parent_pid) {
    if (kill(state.signal_parent_pid, SIGTERM)) {
      log(ERROR, "failed to kill parent process %d", state.signal_parent_pid);
      return 1;
    }
    log(INFO, "killed parent process %d", state.signal_parent_pid);
  }

  // reloading is implemented as follows:
  // - process receives a SIGHUP, which tells it to start reloading. it runs a
  //   child process, which loads the new dataset.
  // - when child process is ready and accepting connections, it sends a SIGTERM
  //   to the parent.
  // - if the child process fails for any reason before sending SIGTERM, it
  //   terminates with a nonzero exit code and the parent receives a SIGCHLD.
  sigset_t sigs;
  sigemptyset(&sigs);
  while (!should_exit) {
    if (state.mtime_check_secs) {
      usleep(state.mtime_check_secs * 1000 * 1000);

      bool files_changed = state.resource_manager.any_resource_changed();
      if (!files_changed && state.ssl_ctx) {
        files_changed |= (static_cast<uint64_t>(stat(state.ssl_cert_filename).st_mtime) != state.ssl_cert_mtime);
        files_changed |= (static_cast<uint64_t>(stat(state.ssl_key_filename).st_mtime) != state.ssl_key_mtime);
      }

      if (!should_exit && !reload_pid && !should_reload && files_changed) {
        should_reload = true;
        log(INFO, "some files were changed on disk; reloading");
      }
    } else {
      sigsuspend(&sigs);
    }

    if (should_exit) {
      log(INFO, "exit request received");
    }

    if (should_reload) {
      log(INFO, "reload request received");

      pid_t parent_pid = getpid();
      reload_pid = fork();
      if (reload_pid < 0) {
        string error = string_for_error(errno);
        log(ERROR, "reload requested, but can\'t fork (%s)", error.c_str());

      } else if (reload_pid == 0) {
        // child process: exec ourself with args to pass the listening fds down
        vector<string> args;
        args.emplace_back(argv[0]);
        args.emplace_back(string_printf("--signal-parent=%d", parent_pid));
        args.emplace_back(string_printf("--mtime-check-secs=%" PRIu64,
            state.mtime_check_secs));
        args.emplace_back(string_printf("--threads=%" PRIu64,
            state.num_threads));
        if (!state.index_resource_name.empty()) {
          args.emplace_back("--index=" + state.index_resource_name);
        }
        if (!state.not_found_resource_name.empty()) {
          args.emplace_back("--404=" + state.not_found_resource_name);
        }
        if (!state.ssl_cert_filename.empty()) {
          args.emplace_back("--ssl-cert=" + state.ssl_cert_filename);
        }
        if (!state.ssl_key_filename.empty()) {
          args.emplace_back("--ssl-key=" + state.ssl_key_filename);
        }
        for (int fd : state.listen_fds) {
          args.emplace_back(string_printf("--fd=%d", fd));
        }
        for (int fd : state.ssl_listen_fds) {
          args.emplace_back(string_printf("--ssl-fd=%d", fd));
        }
        for (const string& directory : state.data_directories) {
          args.emplace_back(directory);
        }
        // note: we don't have to pass --user because we're forking, so the
        // child process will have the same user already
        vector<char*> argv;
        argv.reserve(args.size() + 1);
        for (const string& arg : args) {
          argv.emplace_back(const_cast<char*>(arg.c_str()));
        }
        argv.emplace_back(nullptr);

        execvp(argv[0], argv.data());

        string error = string_for_error(errno);
        log(ERROR, "execvp returned (%s)", error.c_str());
        return 1;
      }

      should_reload = false;
    }

    if (reload_pid < 0) {
      log(INFO, "child process terminated; reload failed");

      // reap all relevant zombies
      int exit_status;
      pid_t pid = waitpid(-1, &exit_status, WNOHANG);
      while (pid != -1) {
        if (WIFEXITED(exit_status)) {
          log(WARNING, "child process %d exited with code %d", pid,
              WEXITSTATUS(exit_status));
        } else if (WIFSIGNALED(exit_status)) {
          log(WARNING, "child process %d exited due to signal %d", pid,
              WTERMSIG(exit_status));
        } else {
          log(WARNING, "child process %d exited with status %d", pid,
              exit_status);
        }

        pid = waitpid(-1, &exit_status, WNOHANG);
      }
      if (errno != ECHILD) {
        string error = string_for_error(errno);
        log(WARNING, "failed to reap zombies: %s", error.c_str());
      }

      reload_pid = 0;
    }
  }

  // close listening sockets, then wait for worker threads to terminate
  for (int fd : state.listen_fds) {
    close(fd);
  }
  for (int fd : state.ssl_listen_fds) {
    close(fd);
  }
  for (auto& t : server_threads) {
    t.join();
  }

  // clean up openssl stuff
  if (state.ssl_ctx) {
    SSL_CTX_free(state.ssl_ctx);
    EVP_cleanup();
  }

  log(INFO, "all threads exited");
  return 0;
}
