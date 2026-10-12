#pragma once

#include <cstddef>
#include <cstdint>
#include <vector>

namespace tls_pin {

constexpr size_t kPinLength = 32;
struct Pin {
    uint8_t bytes[kPinLength];
};

bool parse_pins(const char* text, Pin* out, size_t capacity, size_t& count);

bool subject_public_key_info(const uint8_t* der, size_t length, const uint8_t*& spki, size_t& spki_length);

bool pin_of_certificate(const uint8_t* der, size_t length, Pin& out);

enum class Verdict {
    Pending,   // still reading the server's first flight
    NotTls,    // the connection is not TLS; nothing to check
    Pinned,    // the server presented a pinned key
    Mismatch,  // the server presented a key that is not pinned
    Refused,   // the handshake cannot be checked, so it is not trusted
};

class ServerFlight {
public:
    Verdict feed(const uint8_t* data, size_t length, const Pin* pins, size_t pin_count);
    Verdict verdict() const { return verdict_; }
    const char* reason() const { return reason_; }

private:
    Verdict settle(Verdict verdict, const char* reason);
    Verdict read_handshake(const Pin* pins, size_t pin_count);
    Verdict read_server_hello(const uint8_t* body, size_t length);
    Verdict read_certificate(const uint8_t* body, size_t length, const Pin* pins, size_t pin_count);

    Verdict verdict_ = Verdict::Pending;
    const char* reason_ = "";
    bool first_record_ = true;
    bool saw_server_hello_ = false;
    std::vector<uint8_t> records_;    // received bytes not yet a whole record
    std::vector<uint8_t> handshake_;  // handshake bytes not yet a whole message
};

}
