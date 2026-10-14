#include "core/playforward/launch_envelope.h"

#include "core/playforward/sha256.h"

#include <cstring>

namespace playforward::envelope {
namespace {

constexpr uint8_t kMagic[4] = {'P', 'F', 'W', 'D'};
constexpr uint8_t kVersion = 1;

enum Kind : uint8_t { kHello = 1, kChallenge = 2, kProof = 3, kBound = 4, kKeep = 5 };

constexpr size_t kMagicOffset = 0;
constexpr size_t kVersionOffset = 4;
constexpr size_t kKindOffset = 5;
constexpr size_t kIdOffset = 6;
constexpr size_t kBodyOffset = kHeaderLength;

constexpr char kProofPrefix[] = "playforward-launch-proof";
constexpr char kBoundPrefix[] = "playforward-launch-bound";
constexpr size_t kPrefixLength = sizeof(kProofPrefix) - 1;
static_assert(sizeof(kBoundPrefix) == sizeof(kProofPrefix), "the two prefixes are the same width");
constexpr char kKeepPrefix[] = "playforward-launch-keep";
constexpr char kRenewPrefix[] = "playforward-launch-renew";
constexpr char kCheckPrefix[] = "playforward-launch-check";

constexpr size_t kMaxMacInput = sizeof(kRenewPrefix) + kLaunchIdLength + kTokenIdCapacity;

void mac_over(const char* prefix, const Launch& launch, const uint8_t* data, size_t data_length, uint8_t out[kMacLength]) {
    const size_t prefix_length = strlen(prefix);
    uint8_t input[kMaxMacInput];
    memcpy(input, prefix, prefix_length);
    memcpy(input + prefix_length, launch.id, kLaunchIdLength);
    if (data_length) memcpy(input + prefix_length + kLaunchIdLength, data, data_length);
    hmac_sha256(launch.key, kKeyLength, input, prefix_length + kLaunchIdLength + data_length, out);
}

void write_hex(const uint8_t* bytes, size_t length, char* out) {
    constexpr char kDigits[] = "0123456789abcdef";
    for (size_t i = 0; i < length; ++i) {
        out[i * 2] = kDigits[bytes[i] >> 4];
        out[i * 2 + 1] = kDigits[bytes[i] & 0x0f];
    }
    out[length * 2] = 0;
}

bool at_line_end(const char* text) {
    while (*text == ' ' || *text == '\r' || *text == '\n' || *text == '\t') ++text;
    return *text == 0;
}

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
    // Ends a field: a space before the next, or the end of the line, which
    // the server's lines end with an LF (a CRLF through some proxies).
    return **end == 0 || **end == ' ' || **end == '\r' || **end == '\n';
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

void format_id(const Launch& launch, char* out) { write_hex(launch.id, kLaunchIdLength, out); }

void keep(const Launch& launch, uint64_t counter, uint8_t* out) {
    header(kKeep, launch, out);
    uint8_t* counter_bytes = out + kBodyOffset;
    for (size_t i = 0; i < kCounterLength; ++i) counter_bytes[i] = uint8_t(counter >> (8 * i));
    mac_over(kKeepPrefix, launch, counter_bytes, kCounterLength, out + kBodyOffset + kCounterLength);
}

void renewal_proof_hex(const Launch& old_launch, const char* token_id, char* out) {
    const size_t length = strnlen(token_id, kTokenIdCapacity - 1);
    uint8_t digest[kMacLength];
    mac_over(kRenewPrefix, old_launch, reinterpret_cast<const uint8_t*>(token_id), length, digest);
    write_hex(digest, kMacLength, out);
}

bool parse_launch_line(const char* line, Grant& grant) {
    constexpr char kPrefix[] = "LAUNCH ";
    constexpr size_t kPrefixLen = sizeof(kPrefix) - 1;
    if (!line || strncmp(line, kPrefix, kPrefixLen) != 0) return false;

    const char* cursor = line + kPrefixLen;
    const char* end = nullptr;
    if (!decode_hex(cursor, grant.launch.id, kLaunchIdLength, &end) || *end != ' ') return false;
    cursor = end + 1;
    if (!decode_hex(cursor, grant.launch.key, kKeyLength, &end) || *end != ' ') return false;
    cursor = end + 1;

    unsigned long seconds = 0;
    const char* digits = cursor;
    while (*cursor >= '0' && *cursor <= '9') seconds = seconds * 10 + unsigned(*cursor++ - '0');
    if (cursor == digits || *cursor != ' ') return false;
    grant.expires_in_seconds = seconds;
    ++cursor;

    uint8_t boot[kBootIdLength];
    if (!decode_hex(cursor, boot, kBootIdLength, &end) || !at_line_end(end)) return false;
    write_hex(boot, kBootIdLength, grant.boot_id);
    return true;
}

void check_proof_hex(const Launch& launch, char* out) {
    uint8_t digest[kMacLength];
    mac_over(kCheckPrefix, launch, nullptr, 0, digest);
    write_hex(digest, kMacLength, out);
}

bool parse_check_line(const char* line, bool& live) {
    constexpr char kLive[] = "LIVE";
    constexpr char kGone[] = "GONE";
    if (!line) return false;
    if (strncmp(line, kLive, sizeof(kLive) - 1) == 0 && at_line_end(line + sizeof(kLive) - 1)) {
        live = true;
        return true;
    }
    if (strncmp(line, kGone, sizeof(kGone) - 1) == 0 && at_line_end(line + sizeof(kGone) - 1)) {
        live = false;
        return true;
    }
    return false;
}

bool parse_token_line(const char* line, Token& token) {
    constexpr char kPrefix[] = "TOKEN ";
    constexpr size_t kPrefixLen = sizeof(kPrefix) - 1;
    if (!line || strncmp(line, kPrefix, kPrefixLen) != 0) return false;

    // Three space-separated fields, none of them empty or longer than its buffer.
    char* fields[] = {token.url, token.token_id, token.token};
    const size_t capacities[] = {sizeof(token.url), sizeof(token.token_id), sizeof(token.token)};
    const char* cursor = line + kPrefixLen;
    for (size_t field = 0; field < 3; ++field) {
        size_t length = 0;
        while (cursor[length] && cursor[length] != ' ' && cursor[length] != '\r' && cursor[length] != '\n') ++length;
        if (length == 0 || length >= capacities[field]) return false;
        memcpy(fields[field], cursor, length);
        fields[field][length] = 0;
        cursor += length;
        if (field < 2) {
            if (*cursor != ' ') return false;
            ++cursor;
        }
    }
    return at_line_end(cursor);
}

}
