#pragma once
#include <windows.h>

#include <cstddef>
#include <cstdint>

namespace farcry3 {

// A byte signature in "55 8B EC ?? ??" form: hex bytes, "??" for any byte.
struct Pattern {
    static constexpr size_t kCapacity = 128;
    uint8_t bytes[kCapacity];
    bool wild[kCapacity];
    size_t length = 0;
};

Pattern parse_pattern(const char* text);
bool pattern_matches(const uint8_t* at, const Pattern& pattern);

size_t find_all(HMODULE module, const Pattern& pattern, const uint8_t** out, size_t capacity);

size_t find_all_with_tail(HMODULE module, const Pattern& head, size_t tail_offset, const Pattern& tail,
                          const uint8_t** out, size_t capacity);

const uint8_t* call_target(const uint8_t* call);

}
