#pragma once

#include <stdint.h>

#include <memory>
#include <string>
#include <unordered_map>

class ResourceManagerBase {
protected:
  ResourceManagerBase() = default;
  ResourceManagerBase(const ResourceManagerBase&) = delete;
  ResourceManagerBase(ResourceManagerBase&&) = delete;
  ResourceManagerBase& operator=(const ResourceManagerBase&) = delete;
  ResourceManagerBase& operator=(ResourceManagerBase&&) = delete;

public:
  virtual ~ResourceManagerBase();

  struct Resource {
    std::string data;
    std::string gzip_data; // if blank, compressed is larger than original
    uint64_t modification_time;
    uint64_t hash;
    std::string etag;
    const char* mime_type; // if null, it's a redirect

    Resource(
        std::string&& data,
        uint64_t modification_time = 0,
        const char* mime_type = nullptr,
        int gzip_compress_level = 6);
  };

  virtual void add_directory(const std::string& directory, int gzip_compress_level = 6) = 0;

  virtual std::shared_ptr<const Resource> get_resource(
      const std::string& name) const = 0;

  virtual bool any_resource_changed() const = 0;

  virtual size_t resource_count() const = 0;
  virtual size_t resource_bytes() const = 0;
  virtual size_t compressed_resource_bytes() const = 0;
  virtual size_t file_count() const = 0;
};
