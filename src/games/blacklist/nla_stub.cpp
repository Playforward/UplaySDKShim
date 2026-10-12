#include "games/blacklist/nla_stub.h"

#include "core/hooking/iat.h"
#include "core/logging.h"

#include <cstdint>
#include <cstring>
#include <winsock2.h>
#include <ws2spi.h>

namespace blacklist {
namespace {

using BeginFn = INT (WSAAPI*)(LPWSAQUERYSETA, DWORD, LPHANDLE);
using NextFn  = INT (WSAAPI*)(HANDLE, DWORD, LPDWORD, LPWSAQUERYSETA);
using EndFn   = INT (WSAAPI*)(HANDLE);

BeginFn g_begin = nullptr;
NextFn  g_next = nullptr;
EndFn   g_end = nullptr;

HANDLE  kOurHandle = reinterpret_cast<HANDLE>(static_cast<uintptr_t>(0x4E4C4100));  // "NLA\0"
bool    g_delivered = false;

struct NlaConnectivityBlob {
    uint32_t type;          // NLA_CONNECTIVITY
    uint32_t size;
    uint32_t next_offset;   // zero: the only blob in the chain
    uint32_t link_type;
    uint32_t internet;      // NLA_INTERNET_YES
};

constexpr uint32_t kNlaConnectivity = 3;
constexpr uint32_t kNlaInternetYes = 2;
constexpr uint32_t kNlaLinkWan = 2;

NlaConnectivityBlob g_blob{};
BLOB g_blob_header{};
char g_network_name[] = "Network";

INT WSAAPI hooked_begin(LPWSAQUERYSETA restrictions, DWORD flags, LPHANDLE lookup) {
    const bool is_nla = restrictions != nullptr && restrictions->dwNameSpace == NS_NLA;
    if (!is_nla) return g_begin(restrictions, flags, lookup);
    if (lookup == nullptr) {
        WSASetLastError(WSAEFAULT);
        return SOCKET_ERROR;
    }
    *lookup = kOurHandle;
    g_delivered = false;
    shim_log("[nla] answering the game's connectivity query as connected");
    return 0;
}

INT WSAAPI hooked_next(HANDLE lookup, DWORD flags, LPDWORD length, LPWSAQUERYSETA results) {
    if (lookup != kOurHandle) return g_next(lookup, flags, length, results);

    if (g_delivered) {
        WSASetLastError(WSA_E_NO_MORE);
        return SOCKET_ERROR;
    }
    const DWORD needed = sizeof(WSAQUERYSETA);
    if (length == nullptr || results == nullptr) {
        WSASetLastError(WSAEFAULT);
        return SOCKET_ERROR;
    }
    if (*length < needed) {
        *length = needed;
        WSASetLastError(WSAEFAULT);
        return SOCKET_ERROR;
    }

    g_blob = NlaConnectivityBlob{kNlaConnectivity, sizeof(NlaConnectivityBlob), 0,
                                 kNlaLinkWan, kNlaInternetYes};
    g_blob_header.cbSize = sizeof(g_blob);
    g_blob_header.pBlobData = reinterpret_cast<BYTE*>(&g_blob);

    std::memset(results, 0, sizeof(*results));
    results->dwSize = sizeof(WSAQUERYSETA);
    results->dwNameSpace = NS_NLA;
    results->lpszServiceInstanceName = g_network_name;
    results->lpBlob = &g_blob_header;
    *length = needed;

    g_delivered = true;
    return 0;
}

INT WSAAPI hooked_end(HANDLE lookup) {
    if (lookup != kOurHandle) return g_end(lookup);
    g_delivered = false;
    return 0;
}

}  // namespace

void install_nla_stub(HMODULE game_module) {
    g_begin = reinterpret_cast<BeginFn>(
        patch_iat(game_module, "WS2_32.dll", "WSALookupServiceBeginA", reinterpret_cast<void*>(&hooked_begin)));
    g_next = reinterpret_cast<NextFn>(
        patch_iat(game_module, "WS2_32.dll", "WSALookupServiceNextA", reinterpret_cast<void*>(&hooked_next)));
    g_end = reinterpret_cast<EndFn>(
        patch_iat(game_module, "WS2_32.dll", "WSALookupServiceEnd", reinterpret_cast<void*>(&hooked_end)));
    shim_log("[nla] connectivity answer installed (begin=%p next=%p end=%p)", g_begin, g_next, g_end);
}

}  // namespace blacklist
