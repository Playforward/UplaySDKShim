#pragma once

#include <cstddef>
#include <cstdio>

namespace config_line {
constexpr size_t kCapacity = 640;
bool read(FILE* file, char (&out)[kCapacity], bool& too_long);
}
