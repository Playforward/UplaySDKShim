#pragma once

#include <cstddef>

namespace farcry3::launch {
inline constexpr const char* kLoginOption = "-login";
bool with_login_name(const char* command_line, const char* login_name, char* out, size_t capacity);
}
