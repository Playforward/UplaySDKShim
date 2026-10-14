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

// A KEEP's counter: u64, little-endian, rising within a launch so the server
// refuses one read off the wire and sent again.
constexpr size_t kCounterLength = 8;
constexpr size_t kKeepLength = kHeaderLength + kCounterLength + kMacLength;

constexpr size_t kMaxDatagramLength = kChallengeDatagramLength;

// The server's run, as the hex it is sent in: a different one means it
// restarted and forgot every launch and binding. Logged, not checked: the
// launch check finds a forgotten launch whatever the reason.
constexpr size_t kBootIdLength = 16;
constexpr size_t kBootIdTextLength = kBootIdLength * 2;

struct Launch {
    uint8_t id[kLaunchIdLength];
    uint8_t key[kKeyLength];
};

// A launch as the game server's pre-launch or renew answers it over HTTPS.
struct Grant {
    Launch launch;
    unsigned long expires_in_seconds;
    char boot_id[kBootIdTextLength + 1];
};

// What the desktop client's bridge answers `token <title>` with: the game
// server's URL, the token's id (jti, which a renewal proof covers) and the
// token itself. Sized for a URL and a JWT the accounts service mints.
constexpr size_t kUrlCapacity = 256;
constexpr size_t kTokenIdCapacity = 64;
constexpr size_t kTokenCapacity = 2048;
struct Token {
    char url[kUrlCapacity];
    char token_id[kTokenIdCapacity];
    char token[kTokenCapacity];
};

void hello(const Launch& launch, uint8_t* out);

bool read_challenge(const uint8_t* datagram, size_t length, const Launch& launch, uint8_t challenge[kChallengeLength]);

void proof(const Launch& launch, const uint8_t challenge[kChallengeLength], uint8_t* out);

bool read_bound(const uint8_t* datagram, size_t length, const Launch& launch, const uint8_t challenge[kChallengeLength]);

bool parse_bridge_reply(const char* line, Launch& launch);

void format_id(const Launch& launch, char* out);

// One-way, from the game's socket while the game runs: see the server's
// LaunchEnvelope.Kind.Keep. Writes kKeepLength bytes.
void keep(const Launch& launch, uint64_t counter, uint8_t* out);

// The HMAC a renewal carries: under the old launch's key, over its id and the
// new token's jti. Written as kMacLength * 2 lowercase hex digits and a NUL.
void renewal_proof_hex(const Launch& old_launch, const char* token_id, char* out);

// `LAUNCH <id hex> <key hex> <seconds left> <boot id hex>`, as the game
// server answers a shim that asks for text/plain. Trailing whitespace allowed.
bool parse_launch_line(const char* line, Grant& grant);

// The HMAC a launch check carries: under the launch's key, over its id alone.
// Written as kMacLength * 2 lowercase hex digits and a NUL.
void check_proof_hex(const Launch& launch, char* out);

// `LIVE` or `GONE`, as /playforward/launch-check answers in text/plain.
// Trailing whitespace allowed. False for anything else.
bool parse_check_line(const char* line, bool& live);

// `TOKEN <url> <jti> <token>`, as the desktop client's bridge answers.
bool parse_token_line(const char* line, Token& token);

}
