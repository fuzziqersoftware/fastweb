#define _STDC_FORMAT_MACROS

#include <event2/listener.h>
#include <event2/buffer.h>
#include <event2/http.h>
#include <inttypes.h>
#include <pwd.h>
#include <signal.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>

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


struct ServerConfiguration {
  const ResourceManager::Resource* index_resource;
  const ResourceManager::Resource* not_found_resource;
  ResourceManager resource_manager;

  ServerConfiguration() : index_resource(NULL), not_found_resource(NULL) { }
};

static ResourceManager::Resource default_not_found_resource(
    "File not found", 0, "text/plain");

void handle_request(struct evhttp_request* req, void* ctx) {

  const ServerConfiguration* state = (const ServerConfiguration*)ctx;

  struct evkeyvalq* out_headers = evhttp_request_get_output_headers(req);
  evhttp_add_header(out_headers, "Server", "fastweb");

  unique_ptr<struct evbuffer, void(*)(struct evbuffer*)> out_buffer(
      evbuffer_new(), evbuffer_free);

  int code;
  const char* explanation;

  const char* filename = evhttp_request_get_uri(req);
  try {
    // get the relevant resource object
    const ResourceManager::Resource* res = NULL;
    try {
      res = &state->resource_manager.get_resource(filename);
      code = 200;
      explanation = "OK";

    } catch (const out_of_range& e) {
      // no such resource... check for index first, then fall back to 404 pages
      if (!strcmp(filename, "/") && state->index_resource) {
        res = state->index_resource;
        code = 200;
        explanation = "OK";

      } else if (state->not_found_resource) {
        res = state->not_found_resource;
        code = 404;
        explanation = "Not Found";

      } else {
        res = &default_not_found_resource;
        code = 404;
        explanation = "Not Found";
      }
    }

    // at this point res, code, and explanation are always valid

    if (res->mime_type) {
      evhttp_add_header(out_headers, "Content-Type", res->mime_type);

      bool gzip_response_added = false;
      if (!res->gzip_data.empty()) {
        struct evkeyvalq* in_headers = evhttp_request_get_input_headers(req);
        const char* in_accept_encoding = evhttp_find_header(in_headers, "Accept-Encoding");

        if (in_accept_encoding &&
            (strchr(in_accept_encoding, '*') || strstr(in_accept_encoding, "gzip"))) {
          evhttp_add_header(out_headers, "Content-Encoding", "gzip");
          evbuffer_add_reference(out_buffer.get(), res->gzip_data.data(),
              res->gzip_data.size(), NULL, NULL);
          gzip_response_added = true;
        }
      }

      if (!gzip_response_added) {
        evbuffer_add_reference(out_buffer.get(), res->data.data(),
            res->data.size(), NULL, NULL);
      }

    } else {
      evhttp_add_header(out_headers, "Location", res->data.c_str());

      // if the not found page is a redirect, make browsers not cache it
      code = (code == 404) ? 302 : 301;
      explanation = "Moved Permanently";
    }

  } catch (...) {
    evbuffer_drain(out_buffer.get(), evbuffer_get_length(out_buffer.get()));
    evbuffer_add_reference(out_buffer.get(), "Internal server error", 21, NULL, NULL);
    code = 500;
    explanation = "Internal Server Error";
  }

  evhttp_send_reply(req, code, explanation, out_buffer.get());
}


bool should_exit = false;
bool should_reload = false;
pid_t reload_pid = 0;

void http_server_thread(const unordered_set<int>& listen_fds,
    const ServerConfiguration& state) {

  unique_ptr<struct event_base, void(*)(struct event_base*)> base(
      event_base_new(), event_base_free);
  if (!base) {
    log(ERROR, "error: can\'t open event base for http server");
    return;
  }

  unique_ptr<struct evhttp, void(*)(struct evhttp*)> server(
      evhttp_new(base.get()), evhttp_free);
  if (!server) {
    log(ERROR, "error: can\'t create http server");
    return;
  }

  evhttp_set_gencb(server.get(), handle_request, (void*)&state);
  for (int fd : listen_fds) {
    evhttp_accept_socket(server.get(), fd);
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
  fprintf(stderr,
      "usage: %s [options] [data-directory [data_directory ...]]\n"
      "\n"
      "options:\n"
      "  --fd=N\n"
      "      accept connections on listening file descriptor N (can be given\n"
      "      multiple times)\n"
      "  --listen=PORT\n"
      "      listen on TCP port PORT (can be given multiple times)\n"
      "  --listen=ADDR:PORT\n"
      "      listen on TCP port PORT on interface ADDR (can be given multiple times)\n"
      "  --listen=SOCKET_PATH\n"
      "      listen on Unix socket SOCKET_PATH (can be given multiple times)\n"
      "  --threads=N\n"
      "      use N threads to serve requests (default: # of cores)\n"
      "  --user=USERNAME\n"
      "      drop privileges to the given user\n"
      "  --index=/NAME\n"
      "      serve the given object for requests to /. the object name should be\n"
      "      relative to one of the data directories.\n"
      "  --404=/NAME\n"
      "      serve the given object in place of missing objects (with an HTTP 404\n"
      "      code). the object name should be relative to one of the data directories.\n"
      "  --gzip-level=N\n"
      "      generate compressed gzip versions of all resources with this compression\n"
      "      level (0-9); default 6. 9 means slowest compression, smallest objects;\n"
      "      1 means fastest compression, larger objects; 0 means compression disabled\n"
      "      (this saves memory and startup time but increases network throughput)\n"
      "  --mtime-check-secs=N\n"
      "      check for changes to files on disk every N seconds and reload if needed.\n"
      "      if set to 0, disable automatic reloading.\n"
      "\n"
      "at least one --fd or --listen option must be given.\n"
      "if no data directories are given, the current directory is used.\n", argv0);
}

int main(int argc, char **argv) {

  log(INFO, "fuzziqer software fastweb");

  string index_resource_name;
  string not_found_resource_name;
  vector<string> data_directories;
  vector<pair<string, int>> listen_addrs;
  unordered_set<int> listen_fds;
  size_t num_threads = 0;
  int num_bad_options = 0;
  pid_t signal_parent_pid = 0;
  int gzip_compress_level = 6;
  uint64_t mtime_check_secs = 60;

  const char* user = NULL;
  for (int x = 1; x < argc; x++) {

    if (!strncmp(argv[x], "--signal-parent=", 16)) {
      signal_parent_pid = atoi(&argv[x][16]);

    } else if (!strncmp(argv[x], "--fd=", 5)) {
      listen_fds.emplace(atoi(&argv[x][5]));

    } else if (!strncmp(argv[x], "--threads=", 10)) {
      num_threads = atoi(&argv[x][10]);

    } else if (!strncmp(argv[x], "--user=", 7)) {
      user = &argv[x][7];

    } else if (!strncmp(argv[x], "--index=", 8)) {
      index_resource_name = &argv[x][8];

    } else if (!strncmp(argv[x], "--404=", 6)) {
      not_found_resource_name = &argv[x][6];

    } else if (!strncmp(argv[x], "--gzip-level=", 13)) {
      gzip_compress_level = atoi(&argv[x][13]);

    } else if (!strncmp(argv[x], "--mtime-check-secs=", 19)) {
      mtime_check_secs = atoi(&argv[x][19]);

    } else if (!strncmp(argv[x], "--listen=", 9)) {
      auto parts = split(&argv[x][9], ':');
      if (parts.size() == 1) {
        if (!parts[0].empty() && (parts[0][0] == '/')) {
          // it's a unix socket
          listen_addrs.emplace_back(make_pair(parts[0], 0));
        } else {
          // it's a port number
          listen_addrs.emplace_back(make_pair("", stoi(parts[0])));
        }
      } else if (parts.size() == 2) {
        // it's an addr:port pair
        listen_addrs.emplace_back(make_pair(parts[0], stoi(parts[1])));
      } else {
        log(ERROR, "bad netloc in command line: %s", &argv[x][9]);
        num_bad_options++;
      }

    } else {
      data_directories.emplace_back(argv[x]);
    }
  }

  // check command-line options
  if (num_bad_options) {
    print_usage(argv[0]);
    return 1;
  }
  if (listen_fds.empty() && listen_addrs.empty()) {
    log(ERROR, "no listening sockets or addresses given");
    print_usage(argv[0]);
    return 1;
  }
  if (data_directories.empty()) {
    data_directories.emplace_back("./");
    log(WARNING, "no data directories given; using the current directory");
  }

  // load data
  uint64_t load_start_time = now();
  ServerConfiguration state;
  for (const auto& directory : data_directories) {
    state.resource_manager.add_directory(directory, gzip_compress_level);
  }
  uint64_t load_end_time = now();
  log(INFO, "loaded %zu resources, including %zu files (%zu bytes, %zu compressed, %g%%), in %" PRIu64 " microseconds",
      state.resource_manager.resource_count(),
      state.resource_manager.file_count(),
      state.resource_manager.resource_bytes(),
      state.resource_manager.compressed_resource_bytes(),
      ((float)state.resource_manager.compressed_resource_bytes() / state.resource_manager.resource_bytes()) * 100,
      load_end_time - load_start_time);
  if (mtime_check_secs) {
    log(INFO, "checking for changes to these resources every %" PRIu64 " seconds", mtime_check_secs);
  }

  // resolve special resources
  if (!index_resource_name.empty()) {
    try {
      state.index_resource = &state.resource_manager.get_resource(index_resource_name);
    } catch (const out_of_range& e) {
      log(ERROR, "index resource %s does not exist", index_resource_name.c_str());
      return 2;
    }
  }
  if (!not_found_resource_name.empty()) {
    try {
      state.not_found_resource = &state.resource_manager.get_resource(not_found_resource_name);
    } catch (const out_of_range& e) {
      log(ERROR, "404 resource %s does not exist", not_found_resource_name.c_str());
      return 2;
    }
  }

  // open listening sockets
  for (const auto& listen_addr : listen_addrs) {

    int fd = listen(listen_addr.first, listen_addr.second, SOMAXCONN);
    if (fd < 0) {
      log(ERROR, "can\'t open listening socket; addr=%s, port=%d",
          listen_addr.first.c_str(), listen_addr.second);
      return 2;
    }

    evutil_make_socket_nonblocking(fd);
    listen_fds.emplace(fd);

    log(INFO, "opened listening socket %d: addr=%s, port=%d",
        fd, listen_addr.first.c_str(), listen_addr.second);
  }

  // drop privileges if requested
  if (user) {
    if ((getuid() != 0) || (getgid() != 0)) {
      log(ERROR, "not started as root; can\'t switch to user %s", user);
      return 2;
    }

    struct passwd* pw = getpwnam(user);
    if (!pw) {
      string error = string_for_error(errno);
      log(ERROR, "user %s not found (%s)", user, error.c_str());
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
    log(INFO, "switched to user %s (%d:%d)", user, pw->pw_uid, pw->pw_gid);
  }

  // start server threads
  if (num_threads == 0) {
    num_threads = thread::hardware_concurrency();
  }

  vector<thread> server_threads;
  while (server_threads.size() < num_threads) {
    server_threads.emplace_back(http_server_thread, cref(listen_fds),
        cref(state));
  }
  log(INFO, "started %d server threads", num_threads);

  // register signal handlers
  signal(SIGPIPE, SIG_IGN);
  signal(SIGTERM, signal_handler);
  signal(SIGINT, signal_handler);
  signal(SIGHUP, signal_handler);
  signal(SIGCHLD, signal_handler);

  // kill the parent if needed
  if (signal_parent_pid) {
    if (kill(signal_parent_pid, SIGTERM)) {
      log(ERROR, "failed to kill parent process %d", signal_parent_pid);
      return 1;
    }
    log(INFO, "killed parent process %d", signal_parent_pid);
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
    if (mtime_check_secs) {
      usleep(mtime_check_secs * 1000 * 1000);
      if (!should_exit && !reload_pid && !should_reload &&
          state.resource_manager.any_resource_changed()) {
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
        args.reserve(3 + listen_fds.size() + data_directories.size());
        args.emplace_back(argv[0]);
        args.emplace_back(string_printf("--signal-parent=%d", parent_pid));
        args.emplace_back(string_printf("--mtime-check-secs=%" PRIu64,
            mtime_check_secs));
        for (int fd : listen_fds) {
          args.emplace_back(string_printf("--fd=%d", fd));
        }
        for (const string& directory : data_directories) {
          args.emplace_back(directory);
        }

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
  for (int fd : listen_fds) {
    close(fd);
  }
  for (auto& t : server_threads) {
    t.join();
  }

  log(INFO, "all threads exited");
  return 0;
}
