#include "core/playforward/launch_proof.h"

#include "core/config.h"
#include "core/game_adapter.h"
#include "core/logging.h"
#include "core/playforward/launch_envelope.h"
#include "core/playforward/launch_session.h"

#include <ws2tcpip.h>
#include <cstdio>
#include <cstring>

namespace playforward {
namespace {

constexpr DWORD kReplyTimeoutMs = 1000;

constexpr int kAttempts = 3;

int receive_from_server(SOCKET socket, const sockaddr_in& server, uint8_t* buffer, size_t capacity) {
    for (;;) {
        fd_set readable;
        FD_ZERO(&readable);
        FD_SET(socket, &readable);
        timeval timeout{static_cast<long>(kReplyTimeoutMs / 1000), static_cast<long>((kReplyTimeoutMs % 1000) * 1000)};
        const int ready = select(0, &readable, nullptr, nullptr, &timeout);
        if (ready == 0) return 0;
        if (ready == SOCKET_ERROR) return -1;

        sockaddr_in from{};
        int from_length = sizeof(from);
        const int length = recvfrom(socket, reinterpret_cast<char*>(buffer), static_cast<int>(capacity), 0,
                                    reinterpret_cast<sockaddr*>(&from), &from_length);
        if (length == SOCKET_ERROR) {
            if (WSAGetLastError() == WSAEMSGSIZE) continue;
            return -1;
        }
        if (from.sin_addr.s_addr == server.sin_addr.s_addr && from.sin_port == server.sin_port) return length;
    }
}

bool send_to_server(SOCKET socket, const sockaddr_in& server, const uint8_t* data, size_t length) {
    return sendto(socket, reinterpret_cast<const char*>(data), static_cast<int>(length), 0,
                  reinterpret_cast<const sockaddr*>(&server), sizeof(server)) == static_cast<int>(length);
}

}

uint16_t launch_port() {
    if (hook_config().launch_port) return hook_config().launch_port;
    return game_adapter().launch_port;
}

void prove_launch(SOCKET socket) {
    const HookConfig& config = hook_config();
    if (!config.playforward_launch || !config.redirect_ip_be) return;
    const uint16_t port = launch_port();
    if (!port) {
        shim_log("[playforward] no launch_port for this title; set launch_port in hook.config to its RendezVous authentication port");
        return;
    }

    envelope::Launch launch;
    if (!session::acquire(launch)) return;
    char id[envelope::kLaunchIdLength * 2 + 1];
    envelope::format_id(launch, id);
    shim_log("[playforward] acquired launch %s", id);

    sockaddr_in server{};
    server.sin_family = AF_INET;
    server.sin_port = htons(port);
    server.sin_addr.s_addr = config.redirect_ip_be;

    uint8_t buffer[envelope::kMaxDatagramLength + 1];
    uint8_t challenge[envelope::kChallengeLength];
    uint8_t outgoing[envelope::kProofLength];

    for (int attempt = 1; attempt <= kAttempts; ++attempt) {
        envelope::hello(launch, outgoing);
        if (!send_to_server(socket, server, outgoing, envelope::kHelloLength)) {
            shim_log("[playforward] could not send HELLO to %s:%u (error %d)", config.redirect_ip, port, WSAGetLastError());
            session::unproved(socket, server, launch);
            return;
        }

        int length = receive_from_server(socket, server, buffer, sizeof(buffer));
        if (length < 0) {
            if (WSAGetLastError() == WSAECONNRESET)
                shim_log("[playforward] nothing is listening at %s:%u; the game's own login will not reach it either", config.redirect_ip, port);
            else
                shim_log("[playforward] socket error waiting for CHALLENGE (%d)", WSAGetLastError());
            session::unproved(socket, server, launch);
            return;
        }
        if (length == 0) continue;
        if (!envelope::read_challenge(buffer, static_cast<size_t>(length), launch, challenge)) {
            shim_log("[playforward] the server answered HELLO with %d bytes that are not a CHALLENGE for this launch", length);
            return;
        }

        envelope::proof(launch, challenge, outgoing);
        if (!send_to_server(socket, server, outgoing, envelope::kProofLength)) {
            shim_log("[playforward] could not send PROOF (error %d)", WSAGetLastError());
            session::unproved(socket, server, launch);
            return;
        }

        length = receive_from_server(socket, server, buffer, sizeof(buffer));
        if (length < 0) {
            shim_log("[playforward] socket error waiting for BOUND (%d)", WSAGetLastError());
            session::unproved(socket, server, launch);
            return;
        }
        if (length == 0) {
            shim_log("[playforward] the server did not answer the PROOF (attempt %d)", attempt);
            session::unproved(socket, server, launch);
            return;
        }
        if (!envelope::read_bound(buffer, static_cast<size_t>(length), launch, challenge)) {
            shim_log("[playforward] the server's BOUND reply (%d bytes) is not for this launch and challenge, or its MAC is wrong", length);
            session::report("failed", "unproved");
            return;
        }

        sockaddr_in local{};
        int local_length = sizeof(local);
        getsockname(socket, reinterpret_cast<sockaddr*>(&local), &local_length);
        shim_log("[playforward] launch proved from local port %u to %s:%u; this socket's login is this player",
                 ntohs(local.sin_port), config.redirect_ip, port);
        session::bound(socket, server, launch);
        return;
    }

    shim_log("[playforward] no CHALLENGE after %d HELLOs to %s:%u; is Playforward login enabled on that server?",
             kAttempts, config.redirect_ip, port);
    session::unproved(socket, server, launch);
}

}
