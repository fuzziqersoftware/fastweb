#pragma once

#include <stdint.h>

#include <memory>
#include <string>
#include <unordered_map>

#include "ResourceManagerBase.hh"



class MemoryResourceManager : public ResourceManagerBase {
public:
  MemoryResourceManager();
  MemoryResourceManager(const MemoryResourceManager&) = delete;
  MemoryResourceManager(MemoryResourceManager&&) = delete;
  MemoryResourceManager& operator=(const MemoryResourceManager&) = delete;
  MemoryResourceManager& operator=(MemoryResourceManager&&) = delete;
  virtual ~MemoryResourceManager() = default;

  virtual void add_directory(const std::string& directory, int gzip_compress_level = 6);

  virtual std::shared_ptr<const Resource> get_resource(
      const std::string& name) const;

  virtual bool any_resource_changed() const;

  virtual size_t resource_count() const;
  virtual size_t resource_bytes() const;
  virtual size_t compressed_resource_bytes() const;
  virtual size_t file_count() const;

private:
  void add_directory_recursive(const std::string& base_path,
      const std::string& full_path, uint64_t directory_mtime,
      int gzip_compress_level);

  std::unordered_map<std::string, std::shared_ptr<Resource>> name_to_resource;
  std::unordered_map<std::string, std::shared_ptr<Resource>> path_to_resource;
  std::unordered_map<std::string, uint64_t> directory_path_to_mtime;
  size_t total_bytes;
  size_t compressed_bytes;
};
