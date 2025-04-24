#pragma once

#include <stdint.h>

#include <memory>
#include <string>
#include <unordered_map>
#include <vector>

#include "ResourceManagerBase.hh"

class FileResourceManager : public ResourceManagerBase {
public:
  FileResourceManager() = default;
  FileResourceManager(const FileResourceManager&) = delete;
  FileResourceManager(FileResourceManager&&) = delete;
  FileResourceManager& operator=(const FileResourceManager&) = delete;
  FileResourceManager& operator=(FileResourceManager&&) = delete;
  virtual ~FileResourceManager() = default;

  virtual void add_directory(
      const std::string& directory, int gzip_compress_level = 6);

  virtual std::shared_ptr<const Resource> get_resource(
      const std::string& name) const;

  virtual bool any_resource_changed() const;

  virtual size_t resource_count() const;
  virtual size_t resource_bytes() const;
  virtual size_t compressed_resource_bytes() const;
  virtual size_t file_count() const;

private:
  std::vector<std::pair<std::string, size_t>> root_directories;
};
