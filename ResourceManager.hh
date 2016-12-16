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
    const char* mime_type; // if NULL, it's a redirect

    Resource(const std::string& data, const char* mime_type);
  };

  void add_directory(const std::string& directory);

  const Resource& get_resource(const std::string& name) const;

  size_t resource_count() const;
  size_t resource_bytes() const;
  size_t file_count() const;

private:
  void add_directory_recursive(const std::string& base_path,
      const std::string& full_path);

  std::unordered_map<std::string, std::shared_ptr<Resource>> name_to_resource;
  std::unordered_map<std::string, std::shared_ptr<Resource>> path_to_resource;
  size_t total_bytes;
};
