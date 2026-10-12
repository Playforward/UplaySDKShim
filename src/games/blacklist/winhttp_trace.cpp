#include "games/blacklist/winhttp_trace.h"

#include "core/config.h"
#include "core/hooking/iat.h"
#include "core/logging.h"

#include <winhttp.h>

namespace blacklist {
namespace {

using OpenFn = HINTERNET (WINAPI*)(LPCWSTR, DWORD, LPCWSTR, LPCWSTR, DWORD);
using ConnectFn = HINTERNET (WINAPI*)(HINTERNET, LPCWSTR, INTERNET_PORT, DWORD);
using OpenRequestFn = HINTERNET (WINAPI*)(HINTERNET, LPCWSTR, LPCWSTR, LPCWSTR, LPCWSTR, LPCWSTR*, DWORD);
using SendRequestFn = BOOL (WINAPI*)(HINTERNET, LPCWSTR, DWORD, LPVOID, DWORD, DWORD, DWORD_PTR);
using ReceiveResponseFn = BOOL (WINAPI*)(HINTERNET, LPVOID);
using QueryDataAvailableFn = BOOL (WINAPI*)(HINTERNET, LPDWORD);
using CloseHandleFn = BOOL (WINAPI*)(HINTERNET);
using GetProxyForUrlFn = BOOL (WINAPI*)(HINTERNET, LPCWSTR, WINHTTP_AUTOPROXY_OPTIONS*, WINHTTP_PROXY_INFO*);
using GetIEProxyConfigFn = BOOL (WINAPI*)(WINHTTP_CURRENT_USER_IE_PROXY_CONFIG*);
using SetStatusCallbackFn = WINHTTP_STATUS_CALLBACK (WINAPI*)(HINTERNET, WINHTTP_STATUS_CALLBACK, DWORD, DWORD_PTR);

OpenFn g_open = nullptr;
ConnectFn g_connect = nullptr;
OpenRequestFn g_open_request = nullptr;
SendRequestFn g_send_request = nullptr;
ReceiveResponseFn g_receive_response = nullptr;
QueryDataAvailableFn g_query_data_available = nullptr;
CloseHandleFn g_close_handle = nullptr;
GetProxyForUrlFn g_get_proxy_for_url = nullptr;
GetIEProxyConfigFn g_get_ie_proxy_config = nullptr;
SetStatusCallbackFn g_set_status_callback = nullptr;
WINHTTP_STATUS_CALLBACK g_game_callback = nullptr;

const wchar_t* text(LPCWSTR value) { return value ? value : L"(null)"; }

HINTERNET WINAPI hooked_open(LPCWSTR agent, DWORD access, LPCWSTR proxy, LPCWSTR bypass, DWORD flags) {
    HINTERNET result = g_open(agent, access, proxy, bypass, flags);
    shim_log("[winhttp] WinHttpOpen agent=%ls access=%lu proxy=%ls flags=0x%lx -> %p err=%lu",
             text(agent), access, text(proxy), flags, result, result ? 0 : GetLastError());
    return result;
}

HINTERNET WINAPI hooked_connect(HINTERNET session, LPCWSTR server, INTERNET_PORT port, DWORD reserved) {
    HINTERNET result = g_connect(session, server, port, reserved);
    shim_log("[winhttp] WinHttpConnect %ls:%u -> %p err=%lu", text(server), port, result, result ? 0 : GetLastError());
    return result;
}

HINTERNET WINAPI hooked_open_request(HINTERNET connection, LPCWSTR verb, LPCWSTR object, LPCWSTR version,
                                     LPCWSTR referrer, LPCWSTR* accept, DWORD flags) {
    HINTERNET result = g_open_request(connection, verb, object, version, referrer, accept, flags);
    shim_log("[winhttp] WinHttpOpenRequest %ls %ls flags=0x%lx -> %p err=%lu", text(verb), text(object), flags,
             result, result ? 0 : GetLastError());
    return result;
}

void CALLBACK status_callback(HINTERNET request, DWORD_PTR context, DWORD status, LPVOID info, DWORD length) {
    if (status == WINHTTP_CALLBACK_STATUS_REQUEST_ERROR && info && length >= sizeof(WINHTTP_ASYNC_RESULT)) {
        const auto* async = static_cast<const WINHTTP_ASYNC_RESULT*>(info);
        shim_log("[winhttp] callback request=%p REQUEST_ERROR function=%lu error=%lu", request,
                 static_cast<unsigned long>(async->dwResult), async->dwError);
    } else {
        shim_log("[winhttp] callback request=%p status=0x%08lx length=%lu", request, status, length);
    }
    if (g_game_callback) g_game_callback(request, context, status, info, length);
}

WINHTTP_STATUS_CALLBACK WINAPI hooked_set_status_callback(HINTERNET handle, WINHTTP_STATUS_CALLBACK callback,
                                                          DWORD flags, DWORD_PTR reserved) {
    shim_log("[winhttp] WinHttpSetStatusCallback handle=%p callback=%p flags=0x%lx", handle,
             reinterpret_cast<void*>(callback), flags);
    if (!callback) return g_set_status_callback(handle, nullptr, flags, reserved);
    g_game_callback = callback;
    return g_set_status_callback(handle, status_callback, flags, reserved);
}

BOOL WINAPI hooked_send_request(HINTERNET request, LPCWSTR headers, DWORD headers_length, LPVOID optional,
                                DWORD optional_length, DWORD total_length, DWORD_PTR context) {
    const BOOL result = g_send_request(request, headers, headers_length, optional, optional_length, total_length, context);
    shim_log("[winhttp] WinHttpSendRequest request=%p headers=%ls -> %d err=%lu", request,
             headers && headers_length ? headers : L"", result, result ? 0 : GetLastError());
    return result;
}

BOOL WINAPI hooked_receive_response(HINTERNET request, LPVOID reserved) {
    const BOOL result = g_receive_response(request, reserved);
    shim_log("[winhttp] WinHttpReceiveResponse request=%p -> %d err=%lu", request, result, result ? 0 : GetLastError());
    return result;
}

BOOL WINAPI hooked_query_data_available(HINTERNET request, LPDWORD available) {
    const BOOL result = g_query_data_available(request, available);
    shim_log("[winhttp] WinHttpQueryDataAvailable request=%p -> %d available=%lu err=%lu", request, result,
             result && available ? *available : 0, result ? 0 : GetLastError());
    return result;
}

BOOL WINAPI hooked_close_handle(HINTERNET handle) {
    shim_log("[winhttp] WinHttpCloseHandle %p", handle);
    return g_close_handle(handle);
}

BOOL WINAPI hooked_get_proxy_for_url(HINTERNET session, LPCWSTR url, WINHTTP_AUTOPROXY_OPTIONS* options,
                                     WINHTTP_PROXY_INFO* info) {
    const BOOL result = g_get_proxy_for_url(session, url, options, info);
    shim_log("[winhttp] WinHttpGetProxyForUrl %ls flags=0x%lx -> %d err=%lu access=%lu proxy=%ls", text(url),
             options ? options->dwFlags : 0, result, result ? 0 : GetLastError(),
             result && info ? info->dwAccessType : 0, result && info ? text(info->lpszProxy) : L"");
    return result;
}

BOOL WINAPI hooked_get_ie_proxy_config(WINHTTP_CURRENT_USER_IE_PROXY_CONFIG* config) {
    const BOOL result = g_get_ie_proxy_config(config);
    shim_log("[winhttp] WinHttpGetIEProxyConfigForCurrentUser -> %d err=%lu autodetect=%d autoconfig=%ls proxy=%ls",
             result, result ? 0 : GetLastError(), result && config ? config->fAutoDetect : 0,
             result && config ? text(config->lpszAutoConfigUrl) : L"", result && config ? text(config->lpszProxy) : L"");
    return result;
}

struct Patch { const char* name; void* hook; void** original; };

}

void install_winhttp_trace(HMODULE process_module) {
    if (!hook_config().trace_winhttp) return;
    const Patch patches[] = {
        {"WinHttpOpen", reinterpret_cast<void*>(&hooked_open), reinterpret_cast<void**>(&g_open)},
        {"WinHttpConnect", reinterpret_cast<void*>(&hooked_connect), reinterpret_cast<void**>(&g_connect)},
        {"WinHttpOpenRequest", reinterpret_cast<void*>(&hooked_open_request), reinterpret_cast<void**>(&g_open_request)},
        {"WinHttpSendRequest", reinterpret_cast<void*>(&hooked_send_request), reinterpret_cast<void**>(&g_send_request)},
        {"WinHttpReceiveResponse", reinterpret_cast<void*>(&hooked_receive_response), reinterpret_cast<void**>(&g_receive_response)},
        {"WinHttpQueryDataAvailable", reinterpret_cast<void*>(&hooked_query_data_available), reinterpret_cast<void**>(&g_query_data_available)},
        {"WinHttpCloseHandle", reinterpret_cast<void*>(&hooked_close_handle), reinterpret_cast<void**>(&g_close_handle)},
        {"WinHttpGetProxyForUrl", reinterpret_cast<void*>(&hooked_get_proxy_for_url), reinterpret_cast<void**>(&g_get_proxy_for_url)},
        {"WinHttpGetIEProxyConfigForCurrentUser", reinterpret_cast<void*>(&hooked_get_ie_proxy_config), reinterpret_cast<void**>(&g_get_ie_proxy_config)},
        {"WinHttpSetStatusCallback", reinterpret_cast<void*>(&hooked_set_status_callback), reinterpret_cast<void**>(&g_set_status_callback)},
    };
    int installed = 0;
    for (const Patch& patch : patches) {
        if (void* original = patch_iat(process_module, "WINHTTP.dll", patch.name, patch.hook)) {
            *patch.original = original;
            ++installed;
        }
    }
    shim_log("[winhttp] trace installed on %d call%s", installed, installed == 1 ? "" : "s");
}

}
