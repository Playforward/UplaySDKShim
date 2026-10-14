#include "core/playforward/launch_session.h"

#include "core/game_adapter.h"
#include "core/logging.h"
#include "core/playforward/bridge_client.h"
#include "core/playforward/https_client.h"

#include <cstdio>
#include <cstring>

namespace playforward::session {
namespace {

#ifndef PLAYFORWARD_KEEP_INTERVAL_MS
#define PLAYFORWARD_KEEP_INTERVAL_MS (60 * 1000)
#endif
constexpr DWORD kKeepIntervalMs = PLAYFORWARD_KEEP_INTERVAL_MS;

constexpr unsigned kRenewAtNumerator = 3;
constexpr unsigned kRenewAtDenominator = 4;

constexpr ULONGLONG kMillisecondsPerSecond = 1000;

constexpr char kPreLaunchPath[] = "/playforward/pre-launch";
constexpr char kRenewPath[] = "/playforward/renew";
constexpr char kLaunchCheckPath[] = "/playforward/launch-check";
constexpr unsigned long kHttpOk = 200;

constexpr size_t kReplyCapacity = envelope::kTokenCapacity + envelope::kUrlCapacity + envelope::kTokenIdCapacity + 16;
constexpr size_t kRequestCapacity = 128;
constexpr size_t kBodyCapacity = envelope::kTokenCapacity + 256;

struct State {
    bool renewable = false;
    envelope::Grant grant{};
    char url[envelope::kUrlCapacity] = {};
    ULONGLONG granted_at = 0;
    SOCKET socket = INVALID_SOCKET;
    sockaddr_in server{};
    uint64_t counter = 0;
};

State g_state;
SRWLOCK g_lock = SRWLOCK_INIT;
volatile LONG g_keeper_started = 0;

const char* title() {
    const GameAdapter& game = game_adapter();
    return game.playforward_title ? game.playforward_title : game.id;
}
enum class Acquired { Granted, ClientPredatesTokens, Failed };

Acquired ask_token(envelope::Token& token) {
    char request[kRequestCapacity];
    snprintf(request, sizeof(request), "token %s\n", title());
    char reply[kReplyCapacity];
    if (!bridge::request(request, reply, sizeof(reply))) {
        shim_log("[playforward] no desktop client bridge to ask for a token; logging in by the client's address binding, if any");
        return Acquired::Failed;
    }
    if (envelope::parse_token_line(reply, token)) return Acquired::Granted;
    if (strncmp(reply, "ERROR ", 6) == 0) {
        shim_log("[playforward] the desktop client refused a token: %s", reply + 6);
        report("failed", "refused");
        return Acquired::Failed;
    }
    return Acquired::ClientPredatesTokens;
}

bool grant_from_server(const char* url, const char* path, const char* body, envelope::Grant& grant) {
    https::Response response;
    if (!https::post_json(url, path, body, response)) {
        report("failed", "unreachable");
        return false;
    }
    if (response.status == kHttpOk && envelope::parse_launch_line(response.body, grant)) return true;
    shim_log("[playforward] %s%s answered %lu, not a launch", url, path, response.status);
    report("failed", "refused");
    return false;
}

void store(const envelope::Token& token, const envelope::Grant& grant) {
    AcquireSRWLockExclusive(&g_lock);
    g_state.renewable = true;
    g_state.grant = grant;
    strncpy(g_state.url, token.url, sizeof(g_state.url) - 1);
    g_state.granted_at = GetTickCount64();
    g_state.counter = 0;
    ReleaseSRWLockExclusive(&g_lock);
}

Acquired acquire_fresh(envelope::Grant& grant) {
    envelope::Token token;
    const Acquired asked = ask_token(token);
    if (asked != Acquired::Granted) return asked;
    if (!https::url_allowed(token.url)) {
        report("failed", "insecure");
        return Acquired::Failed;
    }

    char body[kBodyCapacity];
    snprintf(body, sizeof(body), "{\"token\":\"%s\"}", token.token);
    if (!grant_from_server(token.url, kPreLaunchPath, body, grant)) return Acquired::Failed;
    store(token, grant);
    return Acquired::Granted;
}

bool acquire_from_client(envelope::Launch& launch) {
    char request[kRequestCapacity];
    snprintf(request, sizeof(request), "launch %s\n", title());
    char reply[kReplyCapacity];
    if (!bridge::request(request, reply, sizeof(reply)) || !envelope::parse_bridge_reply(reply, launch)) {
        shim_log("[playforward] the desktop client did not issue a launch: %s", reply[0] ? reply : "(no answer)");
        return false;
    }
    shim_log("[playforward] the desktop client predates tokens on the bridge; this launch will be kept, not renewed");
    AcquireSRWLockExclusive(&g_lock);
    g_state = State{};
    memcpy(&g_state.grant.launch, &launch, sizeof(launch));
    ReleaseSRWLockExclusive(&g_lock);
    return true;
}

void send_keep() {
    AcquireSRWLockExclusive(&g_lock);
    const SOCKET socket = g_state.socket;
    const sockaddr_in server = g_state.server;
    const envelope::Launch launch = g_state.grant.launch;
    const uint64_t counter = ++g_state.counter;
    ReleaseSRWLockExclusive(&g_lock);
    if (socket == INVALID_SOCKET) return;

    uint8_t datagram[envelope::kKeepLength];
    envelope::keep(launch, counter, datagram);
    if (sendto(socket, reinterpret_cast<const char*>(datagram), sizeof(datagram), 0,
               reinterpret_cast<const sockaddr*>(&server), sizeof(server)) == SOCKET_ERROR) {
        const int error = WSAGetLastError();
        if (error == WSAENOTSOCK) {
            AcquireSRWLockExclusive(&g_lock);
            if (g_state.socket == socket) g_state.socket = INVALID_SOCKET;
            ReleaseSRWLockExclusive(&g_lock);
            shim_log("[playforward] the game closed its socket; keeping nothing until it opens another");
        } else {
            shim_log("[playforward] could not send a KEEP (error %d); trying again in a minute", error);
        }
    }
}

void recover(const char* why) {
    shim_log("[playforward] %s; acquiring a fresh launch", why);
    envelope::Grant grant;
    if (acquire_fresh(grant) != Acquired::Granted) return;
    send_keep();
    char id[envelope::kLaunchIdLength * 2 + 1];
    envelope::format_id(grant.launch, id);
    shim_log("[playforward] binding fresh launch %s, from game server run %s", id, grant.boot_id);
    report("rebound");
}

void renew() {
    AcquireSRWLockShared(&g_lock);
    const envelope::Launch old = g_state.grant.launch;
    ReleaseSRWLockShared(&g_lock);

    envelope::Token token;
    if (ask_token(token) != Acquired::Granted || !https::url_allowed(token.url)) return;

    char old_id[envelope::kLaunchIdLength * 2 + 1];
    envelope::format_id(old, old_id);
    char proof[envelope::kMacLength * 2 + 1];
    envelope::renewal_proof_hex(old, token.token_id, proof);

    char body[kBodyCapacity];
    snprintf(body, sizeof(body), "{\"token\":\"%s\",\"launch\":\"%s\",\"proof\":\"%s\"}", token.token, old_id, proof);
    envelope::Grant grant;
    if (!grant_from_server(token.url, kRenewPath, body, grant)) {
        recover("the server refused to renew this launch");
        return;
    }
    store(token, grant);
    char id[envelope::kLaunchIdLength * 2 + 1];
    envelope::format_id(grant.launch, id);
    shim_log("[playforward] renewed the launch as %s", id);
    report("renewed");
}

bool server_forgot(const char* url, const envelope::Launch& launch) {
    char id[envelope::kLaunchIdLength * 2 + 1];
    envelope::format_id(launch, id);
    char proof[envelope::kMacLength * 2 + 1];
    envelope::check_proof_hex(launch, proof);
    char body[kBodyCapacity];
    snprintf(body, sizeof(body), "{\"launch\":\"%s\",\"proof\":\"%s\"}", id, proof);

    https::Response response;
    bool live = true;
    if (!https::post_json(url, kLaunchCheckPath, body, response) || response.status != kHttpOk ||
        !envelope::parse_check_line(response.body, live))
        return false;
    return !live;
}

DWORD WINAPI keeper(LPVOID) {
    for (;;) {
        Sleep(kKeepIntervalMs);

        AcquireSRWLockShared(&g_lock);
        const bool has_socket = g_state.socket != INVALID_SOCKET;
        const bool renewable = g_state.renewable;
        char url[envelope::kUrlCapacity];
        strncpy(url, g_state.url, sizeof(url));
        const envelope::Launch launch = g_state.grant.launch;
        const ULONGLONG age = GetTickCount64() - g_state.granted_at;
        const ULONGLONG life = ULONGLONG(g_state.grant.expires_in_seconds) * kMillisecondsPerSecond;
        ReleaseSRWLockShared(&g_lock);
        if (!has_socket) continue;

        if (renewable) {
            if (server_forgot(url, launch)) {
                recover("the game server no longer holds this launch");
                continue;
            }
            if (age >= life) recover("this launch reached its ceiling unrenewed");
            else if (age >= life * kRenewAtNumerator / kRenewAtDenominator) renew();
        }
        send_keep();
    }
}

void keep_socket(SOCKET socket, const sockaddr_in& server, const envelope::Launch& launch) {
    AcquireSRWLockExclusive(&g_lock);
    g_state.socket = socket;
    g_state.server = server;
    memcpy(&g_state.grant.launch, &launch, sizeof(launch));
    g_state.counter = 0;
    ReleaseSRWLockExclusive(&g_lock);

    if (InterlockedCompareExchange(&g_keeper_started, 1, 0) == 0) {
        HANDLE thread = CreateThread(nullptr, 0, keeper, nullptr, 0, nullptr);
        if (thread) CloseHandle(thread);
        else shim_log("[playforward] could not start keeping the launch (error %lu); it lasts until the server's idle timeout", GetLastError());
    }
}

}

bool acquire(envelope::Launch& launch) {
    envelope::Grant grant;
    switch (acquire_fresh(grant)) {
    case Acquired::Granted:
        launch = grant.launch;
        report("launched");
        return true;
    case Acquired::ClientPredatesTokens:
        return acquire_from_client(launch);
    case Acquired::Failed:
        break;
    }
    return false;
}

void bound(SOCKET socket, const sockaddr_in& server, const envelope::Launch& launch) {
    keep_socket(socket, server, launch);
    report("bound");
}

void unproved(SOCKET socket, const sockaddr_in& server, const envelope::Launch& launch) {
    shim_log("[playforward] keeping the unproved launch on this socket; its next KEEP binds it once the server hears it");
    report("failed", "unproved");
    keep_socket(socket, server, launch);
}

void report(const char* event, const char* detail) {
    char line[kRequestCapacity];
    snprintf(line, sizeof(line), detail ? "report %s %s %s\n" : "report %s %s\n", title(), event, detail);
    char reply[kRequestCapacity];
    bridge::request(line, reply, sizeof(reply), true);
}

}
