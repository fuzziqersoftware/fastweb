#define _STDC_FORMAT_MACROS

#include "FileResourceManager.hh"

#include <inttypes.h>
#include <zlib.h>

#include <phosg/Filesystem.hh>
#include <phosg/Hash.hh>
#include <phosg/Strings.hh>

#include "MIMEType.hh"

using namespace std;



void FileResourceManager::add_directory(
    const string& directory, int gzip_compress_level) {
  this->root_directories.emplace_back(directory, gzip_compress_level);
}

shared_ptr<const ResourceManagerBase::Resource>
FileResourceManager::get_resource(const string& name) const {
  if (!name.starts_with("/")) {
    throw std::out_of_range("file not found");
  }
  if (name.find("/../") != string::npos) {
    throw std::out_of_range("file not found");
  }

  for (const auto& root_it : this->root_directories) {
    try {
      auto data = load_file(root_it.first + name);
      return shared_ptr<Resource>(new Resource(
          move(data), 0, mime_type_for_filename(name), root_it.second));
    } catch (const runtime_error&) { }
  }
  throw std::out_of_range("file not found");
}

bool FileResourceManager::any_resource_changed() const {
  return false;
}

size_t FileResourceManager::resource_count() const {
  return 0;
}

size_t FileResourceManager::resource_bytes() const {
  return 0;
}

size_t FileResourceManager::compressed_resource_bytes() const {
  return 0;
}

size_t FileResourceManager::file_count() const {
  return 0;
}
