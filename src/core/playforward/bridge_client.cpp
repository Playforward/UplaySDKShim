#include "core/playforward/bridge_client.h"

#include "core/config.h"
#include "core/logging.h"

#include <ws2tcpip.h>
#include <cstdio>
#include <cstring>

namespace playforward::bridge {
namespace {

constexpr DWORD kPipeBusyWaitMs = 3000;

constexpr DWORD kConnectTimeoutMs = 1000;
constexpr DWORD kReplyTimeoutMs = 5000;

// SO_RCVTIMEO's value for "wait as long as it takes".
constexpr DWORD kNoTimeout = 0;

timeval to_timeval(DWORD ms) {
    return timeval{static_cast<long>(ms / 1000), static_cast<long>((ms % 1000) * 1000)};
}

void set_receive_timeout(SOCKET s, DWORD ms) {
    setsockopt(s, SOL_SOCKET, SO_RCVTIMEO, reinterpret_cast<const char*>(&ms), sizeof(ms));
}

SOCKET connect_local(uint16_t port) {
    SOCKET s = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    if (s == INVALID_SOCKET) return INVALID_SOCKET;

    sockaddr_in address{};
    address.sin_family = AF_INET;
    address.sin_port = htons(port);
    address.sin_addr.s_addr = htonl(INADDR_LOOPBACK);

    u_long non_blocking = 1;
    ioctlsocket(s, FIONBIO, &non_blocking);
    if (connect(s, reinterpret_cast<const sockaddr*>(&address), sizeof(address)) == SOCKET_ERROR) {
        if (WSAGetLastError() != WSAEWOULDBLOCK) {
            closesocket(s);
            return INVALID_SOCKET;
        }
        fd_set writable, failed;
        FD_ZERO(&writable); FD_SET(s, &writable);
        FD_ZERO(&failed); FD_SET(s, &failed);
        timeval timeout = to_timeval(kConnectTimeoutMs);
        if (select(0, nullptr, &writable, &failed, &timeout) <= 0 || !FD_ISSET(s, &writable)) {
            closesocket(s);
            return INVALID_SOCKET;
        }
    }

    non_blocking = 0;
    ioctlsocket(s, FIONBIO, &non_blocking);
    set_receive_timeout(s, kReplyTimeoutMs);
    DWORD send_timeout = kReplyTimeoutMs;
    setsockopt(s, SOL_SOCKET, SO_SNDTIMEO, reinterpret_cast<const char*>(&send_timeout), sizeof(send_timeout));
    return s;
}

}

Connection::~Connection() { close(); }

bool Connection::open(bool quiet) {
    close();
    return open_pipe(quiet) || open_socket();
}

bool Connection::open_pipe(bool quiet) {
    snprintf(where_, sizeof(where_), "\\\\.\\pipe\\%s", hook_config().launch_pipe);
    for (;;) {
        pipe_ = CreateFileA(where_, GENERIC_READ | GENERIC_WRITE, 0, nullptr, OPEN_EXISTING, 0, nullptr);
        if (pipe_ != INVALID_HANDLE_VALUE) break;
        const DWORD error = GetLastError();
        if (error == ERROR_PIPE_BUSY && WaitNamedPipeA(where_, kPipeBusyWaitMs)) continue;
        if (error != ERROR_FILE_NOT_FOUND && !quiet)
            shim_log("[playforward] could not open the desktop client bridge at %s (error %lu)", where_, error);
        return false;
    }
    return true;
}

bool Connection::open_socket() {
    const uint16_t port = hook_config().bridge_port;
    if (!port) return false;
    snprintf(where_, sizeof(where_), "127.0.0.1:%u", static_cast<unsigned>(port));
    socket_ = connect_local(port);
    return socket_ != INVALID_SOCKET;
}

bool Connection::send_line(const char* line) {
    const size_t length = strlen(line);
    if (pipe_ != INVALID_HANDLE_VALUE) {
        DWORD written = 0;
        if (WriteFile(pipe_, line, DWORD(length), &written, nullptr) && written == DWORD(length)) return true;
        shim_log("[playforward] could not write to the bridge at %s (error %lu)", where_, GetLastError());
        return false;
    }
    if (socket_ != INVALID_SOCKET) {
        if (send(socket_, line, static_cast<int>(length), 0) == static_cast<int>(length)) return true;
        shim_log("[playforward] could not write to the bridge on %s (error %d)", where_, WSAGetLastError());
    }
    return false;
}

size_t Connection::read_line(char* out, size_t capacity) {
    size_t length = 0;
    while (length < capacity - 1) {
        bool got = false;
        if (pipe_ != INVALID_HANDLE_VALUE) {
            DWORD read = 0;
            got = ReadFile(pipe_, out + length, 1, &read, nullptr) && read == 1;
        } else if (socket_ != INVALID_SOCKET) {
            got = recv(socket_, out + length, 1, 0) == 1;
        }
        if (!got || out[length] == '\n') break;
        ++length;
    }
    out[length] = 0;
    if (length && out[length - 1] == '\r') out[--length] = 0;
    return length;
}

void Connection::wait_until_closed() {
    char discarded[64];
    if (pipe_ != INVALID_HANDLE_VALUE) {
        DWORD read = 0;
        while (ReadFile(pipe_, discarded, sizeof(discarded), &read, nullptr) && read > 0) {}
    } else if (socket_ != INVALID_SOCKET) {
        set_receive_timeout(socket_, kNoTimeout);
        while (recv(socket_, discarded, sizeof(discarded), 0) > 0) {}
    }
}

void Connection::close() {
    if (pipe_ != INVALID_HANDLE_VALUE) CloseHandle(pipe_);
    if (socket_ != INVALID_SOCKET) closesocket(socket_);
    pipe_ = INVALID_HANDLE_VALUE;
    socket_ = INVALID_SOCKET;
}

bool request(const char* line, char* reply, size_t capacity, bool quiet) {
    reply[0] = 0;
    Connection bridge;
    if (!bridge.open(quiet) || !bridge.send_line(line)) return false;
    return bridge.read_line(reply, capacity) > 0;
}

}
