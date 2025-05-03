#define _STDC_FORMAT_MACROS

#include "MemoryResourceManager.hh"

#include <inttypes.h>
#include <zlib.h>

#include <phosg/Filesystem.hh>
#include <phosg/Hash.hh>
#include <phosg/Strings.hh>

#include "MIMEType.hh"

using namespace std;

MemoryResourceManager::MemoryResourceManager()
    : total_bytes(0), compressed_bytes(0) {}

void MemoryResourceManager::add_directory(
    const string& directory, int gzip_compress_level) {
  this->add_directory_recursive(
      directory, directory, phosg::stat(directory).st_mtime, gzip_compress_level);
}

shared_ptr<const ResourceManagerBase::Resource> MemoryResourceManager::get_resource(
    const string& name) const {
  return this->name_to_resource.at(name);
}

bool MemoryResourceManager::any_resource_changed() const {
  for (const auto& it : this->directory_path_to_mtime) {
    try {
      if ((uint64_t)phosg::stat(it.first).st_mtime != it.second) {
        return true;
      }
    } catch (phosg::cannot_stat_file& e) {
      return true; // it was likely deleted
    }
  }

  for (const auto& it : this->path_to_resource) {
    try {
      if ((uint64_t)phosg::stat(it.first).st_mtime != it.second->modification_time) {
        return true;
      }
    } catch (phosg::cannot_stat_file& e) {
      return true; // it was likely deleted
    }
  }

  return false;
}

size_t MemoryResourceManager::resource_count() const {
  return this->name_to_resource.size();
}

size_t MemoryResourceManager::resource_bytes() const {
  return this->total_bytes;
}

size_t MemoryResourceManager::compressed_resource_bytes() const {
  return this->compressed_bytes;
}

size_t MemoryResourceManager::file_count() const {
  return this->path_to_resource.size();
}

void MemoryResourceManager::add_directory_recursive(
    const string& base_path,
    const string& full_path,
    uint64_t directory_mtime,
    int gzip_compress_level) {

  this->directory_path_to_mtime.emplace(full_path, directory_mtime);

  for (const string& item : phosg::list_directory(full_path)) {

    string item_full_path = full_path + "/" + item;
    auto st = phosg::lstat(item_full_path);
    int type = st.st_mode & S_IFMT;

    string real_item_full_path;
    if (type == S_IFLNK) {
      try {
        real_item_full_path = phosg::realpath(item_full_path);
        // if realpath doesn't throw, the link is valid; process the target
        st = phosg::stat(real_item_full_path);
        type = st.st_mode & S_IFMT;

      } catch (const phosg::cannot_stat_file& e) {
        // the link is not valid; treat it as an external redirect
        string item_relative_path = item_full_path.substr(base_path.size());
        string target = phosg::readlink(item_full_path);
        shared_ptr<Resource> res(new Resource(std::move(target), st.st_mtime));
        this->name_to_resource.emplace(item_relative_path, res);
        continue;
      }
    }

    if (type == S_IFDIR) {
      this->add_directory_recursive(base_path, item_full_path, st.st_mtime,
          gzip_compress_level);

    } else if (type == S_IFREG) {
      string item_relative_path = item_full_path.substr(base_path.size());
      if (real_item_full_path.empty()) {
        real_item_full_path = phosg::realpath(item_full_path);
      }

      // the resource may already be in path_to_resource if there was a
      // symlink to it
      auto existing_file_it = this->path_to_resource.find(real_item_full_path);
      if (existing_file_it == this->path_to_resource.end()) {
        // resource doesn't exist; create a new one
        shared_ptr<Resource> res(new Resource(phosg::load_file(item_full_path),
            st.st_mtime, mime_type_for_filename(item), gzip_compress_level));
        this->path_to_resource.emplace(real_item_full_path, res);
        this->name_to_resource.emplace(item_relative_path, res);
        this->total_bytes += res->data.size();
        this->compressed_bytes += res->gzip_data.size();

      } else {
        // make an alias for this resource
        this->name_to_resource.emplace(
            item_relative_path, existing_file_it->second);
      }

    } else {
      throw runtime_error("can\'t load resource (invalid type): " + full_path);
    }
  }
}
