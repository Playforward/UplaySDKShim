#include "core/networking/tls_pin.h"

#include "core/playforward/sha256.h"

#include <cstring>

namespace tls_pin {
namespace {

// TLS framing (RFC 5246).
constexpr uint8_t kRecordChangeCipherSpec = 20;
constexpr uint8_t kRecordAlert = 21;
constexpr uint8_t kRecordHandshake = 22;
constexpr uint8_t kRecordApplicationData = 23;
constexpr size_t kRecordHeaderLength = 5;
constexpr size_t kMaxRecordLength = 16384 + 2048;
constexpr uint8_t kSslMajorVersion = 3;
constexpr uint16_t kLowestAcceptedVersion = 0x0301;
constexpr uint16_t kTls13Version = 0x0304;
constexpr uint16_t kExtensionSupportedVersions = 43;

constexpr uint8_t kHandshakeHelloRequest = 0;
constexpr uint8_t kHandshakeServerHello = 2;
constexpr uint8_t kHandshakeCertificate = 11;
constexpr size_t kHandshakeHeaderLength = 4;
constexpr size_t kServerRandomLength = 32;
constexpr size_t kMaxHandshakeBuffer = 64 * 1024;

constexpr uint8_t kDerSequence = 0x30;
constexpr uint8_t kDerContextVersion = 0xA0;

uint32_t read_u16(const uint8_t* p) { return (uint32_t(p[0]) << 8) | p[1]; }
uint32_t read_u24(const uint8_t* p) { return (uint32_t(p[0]) << 16) | (uint32_t(p[1]) << 8) | p[2]; }

struct DerElement {
    uint8_t tag;
    const uint8_t* start;    // the tag byte
    const uint8_t* content;
    size_t content_length;
    size_t total_length;     // tag, length and content
};

bool read_der(const uint8_t* at, const uint8_t* end, DerElement& element) {
    if (end - at < 2) return false;
    element.tag = at[0];
    element.start = at;
    const uint8_t* cursor = at + 1;
    size_t length = *cursor++;
    if (length & 0x80) {
        const size_t octets = length & 0x7F;
        if (octets == 0 || octets > 4 || end - cursor < static_cast<ptrdiff_t>(octets)) return false;
        length = 0;
        for (size_t i = 0; i < octets; ++i) length = (length << 8) | *cursor++;
    }
    if (static_cast<size_t>(end - cursor) < length) return false;
    element.content = cursor;
    element.content_length = length;
    element.total_length = static_cast<size_t>(cursor - at) + length;
    return true;
}

int base64_value(char c) {
    if (c >= 'A' && c <= 'Z') return c - 'A';
    if (c >= 'a' && c <= 'z') return c - 'a' + 26;
    if (c >= '0' && c <= '9') return c - '0' + 52;
    if (c == '+') return 62;
    if (c == '/') return 63;
    return -1;
}

bool decode_pin(const char* text, size_t length, Pin& out) {
    while (length && text[length - 1] == '=') --length;
    size_t written = 0;
    uint32_t accumulator = 0;
    int bits = 0;
    for (size_t i = 0; i < length; ++i) {
        const int value = base64_value(text[i]);
        if (value < 0) return false;
        accumulator = (accumulator << 6) | static_cast<uint32_t>(value);
        bits += 6;
        if (bits >= 8) {
            bits -= 8;
            if (written == kPinLength) return false;
            out.bytes[written++] = static_cast<uint8_t>(accumulator >> bits);
        }
    }
    return written == kPinLength;
}

bool is_pinned(const Pin& pin, const Pin* pins, size_t pin_count) {
    for (size_t i = 0; i < pin_count; ++i)
        if (memcmp(pin.bytes, pins[i].bytes, kPinLength) == 0) return true;
    return false;
}
}

bool parse_pins(const char* text, Pin* out, size_t capacity, size_t& count) {
    count = 0;
    const char* cursor = text;
    while (*cursor) {
        while (*cursor == ' ' || *cursor == ',') ++cursor;
        if (!*cursor) break;
        const char* end = cursor;
        while (*end && *end != ',' && *end != ' ') ++end;
        if (count == capacity || !decode_pin(cursor, static_cast<size_t>(end - cursor), out[count])) return false;
        ++count;
        cursor = end;
    }
    return true;
}

bool subject_public_key_info(const uint8_t* der, size_t length, const uint8_t*& spki, size_t& spki_length) {
    const uint8_t* end = der + length;
    DerElement certificate{}, tbs{};
    if (!read_der(der, end, certificate) || certificate.tag != kDerSequence) return false;
    if (!read_der(certificate.content, certificate.content + certificate.content_length, tbs) ||
        tbs.tag != kDerSequence) return false;

    const uint8_t* cursor = tbs.content;
    const uint8_t* tbs_end = tbs.content + tbs.content_length;
    DerElement field{};
    if (!read_der(cursor, tbs_end, field)) return false;
    if (field.tag == kDerContextVersion) {
        cursor += field.total_length;
        if (!read_der(cursor, tbs_end, field)) return false;
    }
    constexpr int kFieldsBeforeKey = 5;
    for (int skipped = 0; skipped < kFieldsBeforeKey; ++skipped) {
        cursor += field.total_length;
        if (!read_der(cursor, tbs_end, field)) return false;
    }
    if (field.tag != kDerSequence) return false;
    spki = field.start;
    spki_length = field.total_length;
    return true;
}

bool pin_of_certificate(const uint8_t* der, size_t length, Pin& out) {
    const uint8_t* spki = nullptr;
    size_t spki_length = 0;
    if (!subject_public_key_info(der, length, spki, spki_length)) return false;
    playforward::sha256(spki, spki_length, out.bytes);
    return true;
}

Verdict ServerFlight::settle(Verdict verdict, const char* reason) {
    verdict_ = verdict;
    reason_ = reason;
    std::vector<uint8_t>().swap(records_);
    std::vector<uint8_t>().swap(handshake_);
    return verdict_;
}

Verdict ServerFlight::feed(const uint8_t* data, size_t length, const Pin* pins, size_t pin_count) {
    if (verdict_ != Verdict::Pending) return verdict_;
    records_.insert(records_.end(), data, data + length);

    size_t offset = 0;
    while (verdict_ == Verdict::Pending && records_.size() - offset >= kRecordHeaderLength) {
        const uint8_t* header = records_.data() + offset;
        const uint8_t type = header[0];
        const bool looks_like_tls = type >= kRecordChangeCipherSpec && type <= kRecordApplicationData &&
                                    header[1] == kSslMajorVersion;
        if (first_record_ && !looks_like_tls) return settle(Verdict::NotTls, "");
        first_record_ = false;
        if (!looks_like_tls) return settle(Verdict::Refused, "a record that is not TLS");
        const size_t record_length = read_u16(header + 3);
        if (record_length > kMaxRecordLength) return settle(Verdict::Refused, "an oversized TLS record");
        if (records_.size() - offset < kRecordHeaderLength + record_length) break;

        const uint8_t* body = header + kRecordHeaderLength;
        if (type == kRecordHandshake) {
            if (handshake_.size() + record_length > kMaxHandshakeBuffer)
                return settle(Verdict::Refused, "a handshake too large to be a certificate");
            handshake_.insert(handshake_.end(), body, body + record_length);
            read_handshake(pins, pin_count);
        } else if (type == kRecordChangeCipherSpec) {
            return settle(Verdict::Refused, "encryption before any certificate");
        } else if (type != kRecordAlert) {
            return settle(Verdict::Refused, "data before the server's certificate");
        }
        offset += kRecordHeaderLength + record_length;
    }
    if (verdict_ == Verdict::Pending) records_.erase(records_.begin(), records_.begin() + static_cast<ptrdiff_t>(offset));
    return verdict_;
}

Verdict ServerFlight::read_handshake(const Pin* pins, size_t pin_count) {
    size_t offset = 0;
    while (verdict_ == Verdict::Pending && handshake_.size() - offset >= kHandshakeHeaderLength) {
        const uint8_t* message = handshake_.data() + offset;
        const size_t body_length = read_u24(message + 1);
        if (handshake_.size() - offset < kHandshakeHeaderLength + body_length) break;
        const uint8_t* body = message + kHandshakeHeaderLength;

        switch (message[0]) {
        case kHandshakeHelloRequest:
            break;
        case kHandshakeServerHello:
            read_server_hello(body, body_length);
            break;
        case kHandshakeCertificate:
            if (!saw_server_hello_) return settle(Verdict::Refused, "a certificate before the server said hello");
            return read_certificate(body, body_length, pins, pin_count);
        default:
            return settle(Verdict::Refused, "a handshake with no server certificate");
        }
        offset += kHandshakeHeaderLength + body_length;
    }
    if (verdict_ == Verdict::Pending) handshake_.erase(handshake_.begin(), handshake_.begin() + static_cast<ptrdiff_t>(offset));
    return verdict_;
}

Verdict ServerFlight::read_server_hello(const uint8_t* body, size_t length) {
    const uint8_t* end = body + length;
    const uint8_t* cursor = body;
    if (end - cursor < 2 + static_cast<ptrdiff_t>(kServerRandomLength) + 1)
        return settle(Verdict::Refused, "a malformed ServerHello");
    const uint16_t version = static_cast<uint16_t>(read_u16(cursor));
    if (version < kLowestAcceptedVersion) return settle(Verdict::Refused, "SSL 3.0");
    if (version >= kTls13Version) return settle(Verdict::Refused, "TLS 1.3, which hides the certificate");
    cursor += 2 + kServerRandomLength;
    const size_t session_id_length = *cursor++;
    if (end - cursor < static_cast<ptrdiff_t>(session_id_length + 3)) return settle(Verdict::Refused, "a malformed ServerHello");
    cursor += session_id_length + 3;

    if (end - cursor >= 2) {
        const uint8_t* extensions_end = cursor + 2 + read_u16(cursor);
        if (extensions_end > end) return settle(Verdict::Refused, "a malformed ServerHello");
        cursor += 2;
        while (extensions_end - cursor >= 4) {
            const uint32_t type = read_u16(cursor);
            const size_t extension_length = read_u16(cursor + 2);
            if (type == kExtensionSupportedVersions)
                return settle(Verdict::Refused, "TLS 1.3, which hides the certificate");
            cursor += 4 + extension_length;
        }
    }
    saw_server_hello_ = true;
    return verdict_;
}

Verdict ServerFlight::read_certificate(const uint8_t* body, size_t length, const Pin* pins, size_t pin_count) {
    if (length < 6) return settle(Verdict::Refused, "an empty certificate list");
    const size_t leaf_length = read_u24(body + 3);
    if (leaf_length == 0 || leaf_length > length - 6) return settle(Verdict::Refused, "a malformed certificate list");

    Pin pin{};
    if (!pin_of_certificate(body + 6, leaf_length, pin)) return settle(Verdict::Refused, "a certificate that does not parse");
    return is_pinned(pin, pins, pin_count)
        ? settle(Verdict::Pinned, "")
        : settle(Verdict::Mismatch, "a certificate whose key is not pinned");
}

}
