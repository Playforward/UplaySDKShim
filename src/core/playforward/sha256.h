#pragma once

#include <cstddef>
#include <cstdint>

namespace playforward {

constexpr size_t kSha256Length = 32;

void sha256(const uint8_t* data, size_t length, uint8_t out[kSha256Length]);

void hmac_sha256(const uint8_t* key, size_t key_length, const uint8_t* data, size_t length,
                 uint8_t out[kSha256Length]);

}
