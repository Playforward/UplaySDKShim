#pragma once

#include "core/game_adapter.h"

// Watch_Dogs (2014), Steam build 11241563: Disrupt_b64.dll PE timestamp 0x5cd13864.
// The engine DLL is VMProtect-packed (.vmp0/.vmp1), so its import table only exists at runtime;
// bind Winsock by export detour as Far Cry 4 does.
namespace watchdogs::current {
inline constexpr const char* kVersion = "wd1-disrupt-5cd13864";
inline constexpr const char* kModules[] = {"Disrupt_b64.dll", nullptr};
inline constexpr const char* kHosts[] = {
    "api-ubiservices.ubi.com", "prod-api-ubiservices.ubi.com", "uat-api-ubiservices.ubi.com",
    "ubiservices.ubi.com", "uplay-ext.ubi.com", nullptr
};
inline constexpr NetworkBindingDefinition kNetwork[] = {
    {NetworkApi::AddrInfoLookup, "getaddrinfo", 0, ResolverIat | ResolverGetProc | ResolverExportDetour},
    {NetworkApi::GetHostByName, "gethostbyname", 0, ResolverIat | ResolverGetProc | ResolverExportDetour},
    {NetworkApi::Connect, "connect", 4, ResolverIat | ResolverGetProc},
    {NetworkApi::Bind, "bind", 2, ResolverIat | ResolverGetProc},
    {NetworkApi::SendTo, "sendto", 20, ResolverIat | ResolverGetProc},
    {NetworkApi::Recv, "recv", 16, ResolverIat | ResolverGetProc},
    {NetworkApi::CloseSocket, "closesocket", 3, ResolverIat | ResolverGetProc},
    {NetworkApi::WSARecv, "WSARecv", 0, ResolverIat | ResolverGetProc},
    {NetworkApi::WSASendTo, "WSASendTo", 0, ResolverIat | ResolverGetProc},
    {NetworkApi::WSAGetOverlappedResult, "WSAGetOverlappedResult", 0, ResolverIat | ResolverGetProc},
    {NetworkApi::WSAIoctl, "WSAIoctl", 0, ResolverIat | ResolverGetProc},
};
// No verified TLS verifier yet; the build's backend surface is still being mapped.
inline constexpr TlsHookDefinition kTls{0, TlsHookMethod::None, 0, 0};
}
