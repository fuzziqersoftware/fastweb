# fastweb

fastweb is a very simple HTTP and HTTPS server for static files.

fastweb is designed to serve a small amount of rarely-changing data to a large number of clients. On startup, it loads all the files in all the given data directories into memory so they can be served without any unnecessary data copying. It also generates compressed versions of each file for fast responses to clients that support the gzip content encoding.

fastweb supports reloading the dataset and updating the executable with no downtime. To do so, send the existing server process a SIGHUP. It will also check the data directories and SSL certificate and key (if provided) for changes periodically and reload if anything has changed.

## Building

0. Make sure libevent, zlib, and OpenSSL are installed.
1. Build and install [phosg](https://github.com/fuzziqersoftware/phosg).
2. Run `make`.

## Running

Run fastweb with no arguments to see how to use it. For most use cases, the following arguments suffice: `/path/to/fastweb --listen=$PORT $DATA_DIRECTORY`. You might want to give the `--index` or `--404` options to set the index and error page contents.

The contents of the data directories as of the server's startup time will be available at the root. For example, if the data directory is `/home/fuzziqersoftware/fastweb-data` and this directory contains `dir1/file1.txt`, then the contents of this file will be available at `http://server-address:port/dir1/file1.txt`. fastweb automatically guesses the MIME type based on the file extension and supports many common file types.

fastweb supports static redirects and aliases using symbolic links. If a symlink points to an existing file in any data directory, the same data will be available at the file's path and the symlink path. If a symlink points to a file outside any of the data directories, that file is accessible only at the symlink path. If a symlink is broken, it's served as a 301 redirect - external redirects can be implemented this way by just making symlinks to e.g. `http://example.com/target/path`. (These symlinks will be unresolvable/broken on the local filesystem, of course.)

### SSL setup

If you want to serve HTTPS traffic, you'll have to do a little more work. Get an SSL certificate and private key (you can use [Let's Encrypt](https://letsencrypt.org/) for this, for example), and put them somewhere where fastweb can read them. (But don't put them in any of your public data directories!) Then run fastweb with the --ssl-cert and --ssl-key options pointing to the relevant filenames, and use --ssl-listen or --ssl-fd to open an SSL port. fastweb will serve the same data over HTTP and HTTPS, so if you want to serve both protocols but have different data available via each, you'll have to run two instances of fastweb.

If you use Let's Encrypt (and Certbot), you can set up a deploy hook so that fastweb's certificate gets automatically updated when Certbot automatically renews it. Just put a script like this in the `/etc/letsencrypt/renewal-hooks/deploy` directory and `chmod +x` it:

    #!/bin/sh

    set -e

    for domain in $RENEWED_DOMAINS; do
      # Change this to the directory where you want to keep fastweb's SSL files
      DESTINATION_DIR=/etc/fastweb
      umask 077
      cp "$RENEWED_LINEAGE/fullchain.pem" "$DESTINATION_DIR/cert.pem"
      cp "$RENEWED_LINEAGE/privkey.pem" "$DESTINATION_DIR/key.pem"
      chown www-data "$DESTINATION_DIR/cert.pem" "$DESTINATION_DIR/key.pem"
      chmod 400 "$DESTINATION_DIR/cert.pem" "$DESTINATION_DIR/key.pem"

      # fastweb automatically reloads when its ssl cert/key files change, so we
      # don't need to do anything else here
    done

This script only works if you have a single certificate, but that certificate can be for multiple domains.

During the reload procedure, fastweb cannot get root privileges again. This means that if reloading is enabled (as it is by default) and you use the --user option, then the SSL key and certificate must be readable by the specified user, and not only by root. (Similarly, all files in the data directories must be readable by the specified user.)

### Example

This is how I run fastweb for my personal website.

    sudo fastweb \
        --user=www-data \
        --listen=80 \
        --ssl-listen=443 \
        --ssl-cert=/fastweb-data/ssl/cert.pem \
        --ssl-key=/fastweb-data/ssl/key.pem \
        --index=/index.html \
        --404=/404.txt \
        --mtime-check-secs=5 \
        /fastweb-data/public

`sudo` is only needed so that fastweb can listen on ports 80 and 443; it drops privileges to `www-data` before accepting any connections. Everything in /fastweb-data is chown'd to www-data:www-data.