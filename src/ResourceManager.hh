#pragma once

#include <stdint.h>

#include <memory>
#include <string>
#include <unordered_map>


class ResourceManager {
public:
  ResourceManager();
  ResourceManager(const ResourceManager&) = delete;
  ResourceManager(ResourceManager&&) = delete;
  ~ResourceManager() = default;

  struct Resource {
    std::string data;
    std::string gzip_data; // if blank, compressed is larger than original
    uint64_t modification_time;
    uint64_t hash;
    char etag[20];
    const char* mime_type; // if null, it's a redirect

    Resource(const std::string& data, uint64_t modification_time = 0,
        const char* mime_type = nullptr, int gzip_compress_level = 6);
  };

  void add_directory(const std::string& directory, int gzip_compress_level = 6);

  const Resource& get_resource(const std::string& name) const;

  bool any_resource_changed() const;

  size_t resource_count() const;
  size_t resource_bytes() const;
  size_t compressed_resource_bytes() const;
  size_t file_count() const;

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
