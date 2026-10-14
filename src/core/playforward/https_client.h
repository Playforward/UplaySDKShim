#pragma once

#include <cstddef>

namespace playforward::https {

constexpr size_t kBodyCapacity = 1024;

struct Response {
    unsigned long status = 0;  // the HTTP status, or 0 when no answer came
    char body[kBodyCapacity] = {};
};

bool post_json(const char* base_url, const char* path, const char* json, Response& response);
bool url_allowed(const char* base_url);
}
