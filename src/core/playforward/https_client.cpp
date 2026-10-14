#include "core/playforward/https_client.h"

#include "core/logging.h"

#include <winsock2.h>
#include <ws2tcpip.h>
#include <windows.h>
#include <winhttp.h>

#include <cstdint>
#include <cstdio>
#include <cstring>

namespace playforward::https {
namespace {

constexpr int kResolveTimeoutMs = 5000;
constexpr int kConnectTimeoutMs = 5000;
constexpr int kSendTimeoutMs = 5000;
constexpr int kReceiveTimeoutMs = 10000;

constexpr size_t kUrlCapacity = 512;
constexpr size_t kHostCapacity = 256;
constexpr size_t kPathCapacity = 256;

constexpr wchar_t kUserAgent[] = L"Playforward shim";
constexpr wchar_t kRequestHeaders[] = L"Content-Type: application/json\r\nAccept: text/plain\r\n";

bool is_private_or_loopback(const char* host) {
    if (_stricmp(host, "localhost") == 0) return true;
    in_addr address{};
    if (inet_pton(AF_INET, host, &address) != 1) return false;
    const uint32_t ip = ntohl(address.s_addr);
    return (ip >> 24) == 127 ||                // 127.0.0.0/8
           (ip >> 24) == 10 ||                 // 10.0.0.0/8
           (ip >> 20) == ((172u << 4) | 1) ||  // 172.16.0.0/12
           (ip >> 16) == ((192u << 8) | 168);  // 192.168.0.0/16
}

struct Target {
    bool secure;
    wchar_t host[kHostCapacity];
    INTERNET_PORT port;
    wchar_t path[kPathCapacity];
};

bool parse(const char* base_url, const char* path, Target& target) {
    char joined[kUrlCapacity];
    size_t base_length = strlen(base_url);
    while (base_length && base_url[base_length - 1] == '/') --base_length;
    if (snprintf(joined, sizeof(joined), "%.*s%s", static_cast<int>(base_length), base_url, path) >= int(sizeof(joined)))
        return false;

    wchar_t wide[kUrlCapacity];
    if (!MultiByteToWideChar(CP_UTF8, 0, joined, -1, wide, kUrlCapacity)) return false;

    URL_COMPONENTS parts{};
    parts.dwStructSize = sizeof(parts);
    parts.lpszHostName = target.host;
    parts.dwHostNameLength = kHostCapacity;
    parts.lpszUrlPath = target.path;
    parts.dwUrlPathLength = kPathCapacity;
    if (!WinHttpCrackUrl(wide, 0, 0, &parts)) return false;
    if (parts.nScheme != INTERNET_SCHEME_HTTPS && parts.nScheme != INTERNET_SCHEME_HTTP) return false;
    target.secure = parts.nScheme == INTERNET_SCHEME_HTTPS;
    target.port = parts.nPort;
    return true;
}

bool send(const char* method_name, const char* base_url, const char* path, const char* body, Response& response) {
    response = Response{};
    if (!url_allowed(base_url)) return false;

    Target target{};
    if (!parse(base_url, path, target)) {
        shim_log("[playforward] the game server's address %s%s is not a URL this shim can call", base_url, path);
        return false;
    }

    wchar_t method[8];
    MultiByteToWideChar(CP_UTF8, 0, method_name, -1, method, 8);

    bool answered = false;
    HINTERNET session = WinHttpOpen(kUserAgent, WINHTTP_ACCESS_TYPE_DEFAULT_PROXY, WINHTTP_NO_PROXY_NAME, WINHTTP_NO_PROXY_BYPASS, 0);
    HINTERNET connection = session ? WinHttpConnect(session, target.host, target.port, 0) : nullptr;
    HINTERNET request = connection
        ? WinHttpOpenRequest(connection, method, target.path, nullptr, WINHTTP_NO_REFERER, WINHTTP_DEFAULT_ACCEPT_TYPES,
                             target.secure ? WINHTTP_FLAG_SECURE : 0)
        : nullptr;

    if (request) {
        WinHttpSetTimeouts(request, kResolveTimeoutMs, kConnectTimeoutMs, kSendTimeoutMs, kReceiveTimeoutMs);
        DWORD disable = WINHTTP_DISABLE_REDIRECTS;
        WinHttpSetOption(request, WINHTTP_OPTION_DISABLE_FEATURE, &disable, sizeof(disable));

        const DWORD body_length = static_cast<DWORD>(strlen(body));
        if (WinHttpSendRequest(request, kRequestHeaders, static_cast<DWORD>(-1L), const_cast<char*>(body), body_length, body_length, 0) &&
            WinHttpReceiveResponse(request, nullptr)) {
            DWORD status = 0, size = sizeof(status);
            WinHttpQueryHeaders(request, WINHTTP_QUERY_STATUS_CODE | WINHTTP_QUERY_FLAG_NUMBER, WINHTTP_HEADER_NAME_BY_INDEX,
                                &status, &size, WINHTTP_NO_HEADER_INDEX);
            response.status = status;

            size_t used = 0;
            DWORD read = 0;
            while (used < kBodyCapacity - 1 &&
                   WinHttpReadData(request, response.body + used, static_cast<DWORD>(kBodyCapacity - 1 - used), &read) && read) {
                used += read;
            }
            response.body[used] = 0;
            answered = true;
        } else {
            shim_log("[playforward] %s %s%s got no answer (WinHTTP error %lu)", method_name, base_url, path, GetLastError());
        }
    }

    if (request) WinHttpCloseHandle(request);
    if (connection) WinHttpCloseHandle(connection);
    if (session) WinHttpCloseHandle(session);
    return answered;
}

}

bool url_allowed(const char* base_url) {
    if (_strnicmp(base_url, "https://", 8) == 0) return true;
    if (_strnicmp(base_url, "http://", 7) != 0) {
        shim_log("[playforward] refusing game server address %s: not an http(s) URL", base_url);
        return false;
    }

    char host[kHostCapacity];
    const char* start = base_url + 7;
    size_t length = strcspn(start, ":/");
    if (length == 0 || length >= sizeof(host)) return false;
    memcpy(host, start, length);
    host[length] = 0;
    if (is_private_or_loopback(host)) return true;

    shim_log("[playforward] refusing to send a token to %s over plain http: only https is allowed outside the LAN", base_url);
    return false;
}

bool post_json(const char* base_url, const char* path, const char* json, Response& response) {
    return send("POST", base_url, path, json, response);
}

}
