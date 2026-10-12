#include "core/networking/tls_observer.h"

#include "core/config.h"
#include "core/logging.h"
#include "core/networking/tls.h"
#include "core/networking/tls_pin.h"

#include <ws2tcpip.h>
#include <cstdio>
#include <unordered_map>

namespace tls_observer {
namespace {

struct Watched {
    tls_pin::ServerFlight flight;
    // An overlapped read posted and not yet seen to complete.
    bool read_outstanding = false;
};

// A game opens a handful of TCP connections. Past this many unanswered ones
// something is wrong, and a new connection simply goes unwatched -- which
// means its certificate check falls to the game, not that it is trusted.
constexpr size_t kMaxWatchedSockets = 256;

std::unordered_map<SOCKET, Watched> g_watched;
SRWLOCK g_lock = SRWLOCK_INIT;

void describe_peer(SOCKET socket, char* out, size_t capacity) {
    sockaddr_storage address{};
    int length = sizeof(address);
    if (getpeername(socket, reinterpret_cast<sockaddr*>(&address), &length) == 0 && address.ss_family == AF_INET) {
        const auto& ipv4 = reinterpret_cast<const sockaddr_in&>(address);
        const auto* bytes = reinterpret_cast<const unsigned char*>(&ipv4.sin_addr);
        snprintf(out, capacity, "%u.%u.%u.%u:%u", bytes[0], bytes[1], bytes[2], bytes[3], ntohs(ipv4.sin_port));
    } else {
        snprintf(out, capacity, "socket %llu", static_cast<unsigned long long>(socket));
    }
}

bool is_stream(SOCKET socket) {
    int type = 0;
    int length = sizeof(type);
    return getsockopt(socket, SOL_SOCKET, SO_TYPE, reinterpret_cast<char*>(&type), &length) == 0 &&
           type == SOCK_STREAM;
}

// Called with the lock held; the entry is gone when this returns.
void stop_watching_blind(SOCKET socket, const char* why) {
    g_watched.erase(socket);
    char peer[64];
    describe_peer(socket, peer, sizeof(peer));
    shim_log("[tls] cannot read the certificate on the connection to %s (%s); the game's own verifier will decide it",
             peer, why);
}
}

void on_connect(SOCKET socket) {
    if (!tls_pinning_armed() || !is_stream(socket)) return;
    AcquireSRWLockExclusive(&g_lock);
    if (g_watched.size() < kMaxWatchedSockets || g_watched.count(socket)) g_watched[socket] = Watched{};
    else shim_log("[tls] %u connections are already waiting for a certificate; not watching another",
                  static_cast<unsigned>(kMaxWatchedSockets));
    ReleaseSRWLockExclusive(&g_lock);
}

bool watching(SOCKET socket) {
    if (!tls_pinning_armed()) return false;
    AcquireSRWLockShared(&g_lock);
    const bool found = g_watched.count(socket) != 0;
    ReleaseSRWLockShared(&g_lock);
    return found;
}

bool on_received(SOCKET socket, const WSABUF* buffers, DWORD buffer_count, DWORD bytes) {
    if (!tls_pinning_armed() || !buffers || !bytes) return true;
    const HookConfig& config = hook_config();

    AcquireSRWLockExclusive(&g_lock);
    auto it = g_watched.find(socket);
    if (it == g_watched.end()) { ReleaseSRWLockExclusive(&g_lock); return true; }
    it->second.read_outstanding = false;
    tls_pin::ServerFlight& flight = it->second.flight;
    DWORD remaining = bytes;
    for (DWORD i = 0; i < buffer_count && remaining && flight.verdict() == tls_pin::Verdict::Pending; ++i) {
        const DWORD take = buffers[i].len < remaining ? buffers[i].len : remaining;
        flight.feed(reinterpret_cast<const uint8_t*>(buffers[i].buf), take, config.tls_pins, config.tls_pin_count);
        remaining -= take;
    }
    const tls_pin::Verdict verdict = flight.verdict();
    const char* reason = flight.reason();
    if (verdict != tls_pin::Verdict::Pending) g_watched.erase(it);
    ReleaseSRWLockExclusive(&g_lock);

    char peer[64];
    switch (verdict) {
    case tls_pin::Verdict::Pending:
    case tls_pin::Verdict::NotTls:
        return true;
    case tls_pin::Verdict::Pinned:
        describe_peer(socket, peer, sizeof(peer));
        shim_log("[tls] %s presented the pinned server key", peer);
        tls_trust_pinned_handshake();
        return true;
    case tls_pin::Verdict::Mismatch:
    case tls_pin::Verdict::Refused:
        break;
    }
    // Shut down before the game's TLS code sees the rest of the flight: the
    // read that carried it fails, and so does everything after it.
    describe_peer(socket, peer, sizeof(peer));
    shim_log("[tls] refused the connection to %s: %s. If this is your server, its key is not in tls_pin_sha256",
             peer, reason);
    shutdown(socket, SD_BOTH);
    return false;
}

void on_read_posted(SOCKET socket, bool has_completion_routine) {
    AcquireSRWLockExclusive(&g_lock);
    auto it = g_watched.find(socket);
    if (it != g_watched.end()) {
        if (has_completion_routine) stop_watching_blind(socket, "its reads complete through a routine the shim does not see");
        else if (it->second.read_outstanding) stop_watching_blind(socket, "a read completed where the shim does not look");
        else it->second.read_outstanding = true;
    }
    ReleaseSRWLockExclusive(&g_lock);
}

void on_read_finished(SOCKET socket) {
    AcquireSRWLockExclusive(&g_lock);
    auto it = g_watched.find(socket);
    if (it != g_watched.end()) it->second.read_outstanding = false;
    ReleaseSRWLockExclusive(&g_lock);
}

void on_close(SOCKET socket) {
    AcquireSRWLockExclusive(&g_lock);
    g_watched.erase(socket);
    ReleaseSRWLockExclusive(&g_lock);
}

}
