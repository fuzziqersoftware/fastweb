#include "ResourceManager.hh"

#include <zlib.h>

#include <phosg/Filesystem.hh>
#include <phosg/Strings.hh>

#include "MIMEType.hh"

using namespace std;


class inefficient_compression : public runtime_error {
public:
  inefficient_compression() : runtime_error("inefficient compression") { }
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


ResourceManager::ResourceManager() : total_bytes(0) { }

ResourceManager::Resource::Resource(const string& data, const char* mime_type) :
    data(data), mime_type(mime_type) {
  if (!this->mime_type) {
    this->gzip_data = ""; // no compression for redirects
  } else {
    try {
      this->gzip_data = gzip_compress(this->data, 9);
    } catch (const inefficient_compression& e) {
      this->gzip_data = "";
    }
  }
}

void ResourceManager::add_directory(const string& directory) {
  this->add_directory_recursive(directory, directory);
}

const ResourceManager::Resource& ResourceManager::get_resource(
    const string& name) const {
  return *this->name_to_resource.at(name);
}

size_t ResourceManager::resource_count() const {
  return this->name_to_resource.size();
}

size_t ResourceManager::resource_bytes() const {
  return this->total_bytes;
}

size_t ResourceManager::file_count() const {
  return this->path_to_resource.size();
}

void ResourceManager::add_directory_recursive(const string& base_path,
    const string& full_path) {

  for (const string& item : list_directory(full_path)) {

    string item_full_path = full_path + "/" + item;
    int type = lstat(item_full_path).st_mode & S_IFMT;

    string real_item_full_path;
    if (type == S_IFLNK) {
      try {
        real_item_full_path = realpath(item_full_path);
        // if realpath doesn't throw, the link is valid; process the target
        type = stat(item).st_mode & S_IFMT;

      } catch (const cannot_stat_file& e) {
        // the link is not valid; treat it as an external redirect
        string item_relative_path = item_full_path.substr(base_path.size());
        string target = readlink(item_full_path);
        shared_ptr<Resource> res(new Resource(target, nullptr));
        log(INFO, "adding name %s", item_relative_path.c_str());
        this->name_to_resource.emplace(item_relative_path, res);
        continue;
      }
    }

    if (type == S_IFDIR) {
      this->add_directory_recursive(base_path, item_full_path);

    } else if (type == S_IFREG) {
      string item_relative_path = item_full_path.substr(base_path.size());
      if (real_item_full_path.empty()) {
        real_item_full_path = realpath(item_full_path);
      }

      // the resource may already be in path_to_resource if there was a
      // symlink to it
      auto existing_file_it = this->path_to_resource.find(real_item_full_path);
      if (existing_file_it == this->path_to_resource.end()) {
        // resource doesn't exist; create a new one
        shared_ptr<Resource> res(new Resource(
            load_file(item_full_path), mime_type_for_filename(item)));
        log(INFO, "adding name %s", item_relative_path.c_str());
        this->path_to_resource.emplace(real_item_full_path, res);
        this->name_to_resource.emplace(item_relative_path, res);
        this->total_bytes += res->data.size();

      } else {
        // make an alias for this resource
        log(INFO, "adding name %s", item_relative_path.c_str());
        this->name_to_resource.emplace(
            item_relative_path, existing_file_it->second);
      }

    } else {
      throw runtime_error("can\'t load resource (invalid type): " + full_path);
    }
  }
}
