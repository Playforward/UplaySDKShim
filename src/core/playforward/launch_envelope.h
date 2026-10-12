#pragma once

#include <cstddef>
#include <cstdint>

namespace playforward::envelope {

constexpr size_t kLaunchIdLength = 16;
constexpr size_t kKeyLength = 32;
constexpr size_t kChallengeLength = 32;
constexpr size_t kMacLength = 32;

constexpr size_t kHeaderLength = 4 + 1 + 1 + kLaunchIdLength;  // magic, version, kind, id
constexpr size_t kHelloLength = kHeaderLength;
constexpr size_t kChallengeDatagramLength = kHeaderLength + kChallengeLength;
constexpr size_t kProofLength = kHeaderLength + kMacLength;
constexpr size_t kBoundLength = kHeaderLength + kMacLength;

constexpr size_t kMaxDatagramLength = kChallengeDatagramLength;

struct Launch {
    uint8_t id[kLaunchIdLength];
    uint8_t key[kKeyLength];
};

void hello(const Launch& launch, uint8_t* out);

bool read_challenge(const uint8_t* datagram, size_t length, const Launch& launch, uint8_t challenge[kChallengeLength]);

void proof(const Launch& launch, const uint8_t challenge[kChallengeLength], uint8_t* out);

bool read_bound(const uint8_t* datagram, size_t length, const Launch& launch, const uint8_t challenge[kChallengeLength]);

bool parse_bridge_reply(const char* line, Launch& launch);

void format_id(const Launch& launch, char* out);

}
