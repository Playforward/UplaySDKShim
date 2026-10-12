#include "core/playforward/launch_envelope.h"

#include "core/playforward/sha256.h"

#include <cstring>

namespace playforward::envelope {
namespace {

constexpr uint8_t kMagic[4] = {'P', 'F', 'W', 'D'};
constexpr uint8_t kVersion = 1;

enum Kind : uint8_t { kHello = 1, kChallenge = 2, kProof = 3, kBound = 4 };

constexpr size_t kMagicOffset = 0;
constexpr size_t kVersionOffset = 4;
constexpr size_t kKindOffset = 5;
constexpr size_t kIdOffset = 6;
constexpr size_t kBodyOffset = kHeaderLength;

constexpr char kProofPrefix[] = "playforward-launch-proof";
constexpr char kBoundPrefix[] = "playforward-launch-bound";
constexpr size_t kPrefixLength = sizeof(kProofPrefix) - 1;
static_assert(sizeof(kBoundPrefix) == sizeof(kProofPrefix), "the two prefixes are the same width");

void header(Kind kind, const Launch& launch, uint8_t* out) {
    memcpy(out + kMagicOffset, kMagic, sizeof(kMagic));
    out[kVersionOffset] = kVersion;
    out[kKindOffset] = kind;
    memcpy(out + kIdOffset, launch.id, kLaunchIdLength);
}

bool header_matches(const uint8_t* datagram, size_t length, size_t expected_length, Kind kind, const Launch& launch) {
    return length == expected_length &&
           memcmp(datagram + kMagicOffset, kMagic, sizeof(kMagic)) == 0 &&
           datagram[kVersionOffset] == kVersion &&
           datagram[kKindOffset] == kind &&
           memcmp(datagram + kIdOffset, launch.id, kLaunchIdLength) == 0;
}

void mac(const char* prefix, const Launch& launch, const uint8_t challenge[kChallengeLength], uint8_t out[kMacLength]) {
    uint8_t input[kPrefixLength + kLaunchIdLength + kChallengeLength];
    memcpy(input, prefix, kPrefixLength);
    memcpy(input + kPrefixLength, launch.id, kLaunchIdLength);
    memcpy(input + kPrefixLength + kLaunchIdLength, challenge, kChallengeLength);
    hmac_sha256(launch.key, kKeyLength, input, sizeof(input), out);
}

bool constant_time_equal(const uint8_t* a, const uint8_t* b, size_t length) {
    uint8_t difference = 0;
    for (size_t i = 0; i < length; ++i) difference |= uint8_t(a[i] ^ b[i]);
    return difference == 0;
}

int hex_value(char c) {
    if (c >= '0' && c <= '9') return c - '0';
    if (c >= 'a' && c <= 'f') return c - 'a' + 10;
    if (c >= 'A' && c <= 'F') return c - 'A' + 10;
    return -1;
}

bool decode_hex(const char* text, uint8_t* out, size_t length, const char** end) {
    for (size_t i = 0; i < length; ++i) {
        const int high = hex_value(text[i * 2]);
        const int low = high < 0 ? -1 : hex_value(text[i * 2 + 1]);
        if (low < 0) return false;
        out[i] = uint8_t(high << 4 | low);
    }
    *end = text + length * 2;
    return **end == 0 || **end == ' ';
}

}

void hello(const Launch& launch, uint8_t* out) { header(kHello, launch, out); }

bool read_challenge(const uint8_t* datagram, size_t length, const Launch& launch, uint8_t challenge[kChallengeLength]) {
    if (!header_matches(datagram, length, kChallengeDatagramLength, kChallenge, launch)) return false;
    memcpy(challenge, datagram + kBodyOffset, kChallengeLength);
    return true;
}

void proof(const Launch& launch, const uint8_t challenge[kChallengeLength], uint8_t* out) {
    header(kProof, launch, out);
    mac(kProofPrefix, launch, challenge, out + kBodyOffset);
}

bool read_bound(const uint8_t* datagram, size_t length, const Launch& launch, const uint8_t challenge[kChallengeLength]) {
    if (!header_matches(datagram, length, kBoundLength, kBound, launch)) return false;
    uint8_t expected[kMacLength];
    mac(kBoundPrefix, launch, challenge, expected);
    return constant_time_equal(datagram + kBodyOffset, expected, kMacLength);
}

bool parse_bridge_reply(const char* line, Launch& launch) {
    constexpr char kPrefix[] = "LAUNCH ";
    constexpr size_t kPrefixLen = sizeof(kPrefix) - 1;
    if (!line || strncmp(line, kPrefix, kPrefixLen) != 0) return false;

    const char* cursor = line + kPrefixLen;
    const char* end = nullptr;
    if (!decode_hex(cursor, launch.id, kLaunchIdLength, &end) || *end != ' ') return false;
    cursor = end + 1;
    if (!decode_hex(cursor, launch.key, kKeyLength, &end) || *end != 0) return false;
    return true;
}

void format_id(const Launch& launch, char* out) {
    constexpr char kDigits[] = "0123456789abcdef";
    for (size_t i = 0; i < kLaunchIdLength; ++i) {
        out[i * 2] = kDigits[launch.id[i] >> 4];
        out[i * 2 + 1] = kDigits[launch.id[i] & 0x0f];
    }
    out[kLaunchIdLength * 2] = 0;
}

}
