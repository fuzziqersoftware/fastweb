# fastweb

fastweb is a very simple HTTP server for static files.

fastweb is designed to serve a small amount of static data to a large number of clients. On startup, it loads all the files in all the given data directories into memory so they can be served without any unnecessary data copying. It also generates compressed versions of each file for fast responses to clients that support the gzip content encoding.

fastweb supports reloading the dataset and updating the executable with no downtime. To do so, send the existing server process a SIGHUP. It will also check the data directories for changes periodically (by default once per minute) and reload if anything has changed.

## Building

1. Build and install phosg (https://github.com/fuzziqersoftware/phosg).
2. Run `make`.

## Running

Run fastweb with no arguments to see how to use it. For most use cases, the following arguments suffice: `/path/to/fastweb --listen=$PORT $DATA_DIRECTORY`. You might want to give the `--index` or `--404` options to set the index and error page contents.

The contents of the data directories as of the server's startup time will be available at the root. For example, if the data directory is `/home/fuzziqersoftware/fastweb-data` and this directory contains `dir1/file1.txt`, then the contents of this file will be available at `http://server-address:port/dir1/file1.txt`. fastweb automatically guesses the MIME type based on the file extension and should support most common file types.

fastweb supports static redirects and aliases using symbolic links. If a symlink points to an existing file in any data directory, the same data will be available at the file's path and the symlink path. If a symlink points to a file outside any of the data directories, that file is accessible only at the symlink path. If a symlink is broken, it's served as a 301 redirect - external redirects can be implemented this way by just making symlinks to e.g. `http://example.com/target/path`. (These symlinks will be unresolvable/broken on the local filesystem, of course.)
