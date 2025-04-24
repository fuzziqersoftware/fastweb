#define _STDC_FORMAT_MACROS

#include "ResourceManagerBase.hh"

#include <inttypes.h>
#include <zlib.h>

#include <phosg/Filesystem.hh>
#include <phosg/Hash.hh>
#include <phosg/Strings.hh>

#include "MIMEType.hh"

using namespace std;

class inefficient_compression : public runtime_error {
public:
  inefficient_compression() : runtime_error("inefficient compression") {}
};

static string gzip_compress(const string& data, int level) {

  z_stream zs;
  zs.zalloc = Z_NULL;
  zs.zfree = Z_NULL;
  zs.opaque = Z_NULL;

  if (deflateInit2(&zs, level, Z_DEFLATED, 15 + 16, 9, Z_DEFAULT_STRATEGY) != Z_OK) {
    throw runtime_error("can\'t create gzip compressor");
  }

  string result_data(data.size(), 0);

  zs.avail_in = data.size();
  zs.next_in = (unsigned char*)data.data();
  zs.avail_out = result_data.size();
  zs.next_out = (unsigned char*)result_data.data();

  int retcode = deflate(&zs, Z_FINISH);
  deflateEnd(&zs);
  if (retcode == Z_BUF_ERROR || retcode == Z_OK) {
    throw inefficient_compression();
  } else if (retcode != Z_STREAM_END) {
    throw runtime_error("gzip compression failed: " + to_string(retcode));
  }
  if (zs.avail_in != 0) {
    throw inefficient_compression();
  }
  if (zs.avail_out > data.size()) {
    throw runtime_error("invalid output buffer state after compression");
  }

  result_data.resize(result_data.size() - zs.avail_out);
  result_data.shrink_to_fit();
  return result_data;
}

ResourceManagerBase::~ResourceManagerBase() {}

ResourceManagerBase::Resource::Resource(
    string&& data,
    uint64_t modification_time,
    const char* mime_type,
    int gzip_compress_level)
    : data(std::move(data)),
      gzip_data(),
      modification_time(modification_time),
      hash(phosg::fnv1a64(this->data)),
      mime_type(mime_type) {
  this->etag = phosg::string_printf("%016" PRIX64, this->hash);

  // If it's not a redirect and compression is enabled, try to compress it
  if (this->mime_type && gzip_compress_level) {
    try {
      this->gzip_data = gzip_compress(this->data, gzip_compress_level);
    } catch (const inefficient_compression& e) {
    }
  }
}
