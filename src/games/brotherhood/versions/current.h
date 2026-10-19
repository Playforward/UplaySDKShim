#pragma once

#include "core/game_adapter.h"

namespace brotherhood::current {
// ACBMP.exe is the 2011 multiplayer build (PE timestamp 0x4d8b6c22); ACBSP.exe
// is the 2022 single-player rebuild, which launches it. Both import
// binkw32.dll, so the one proxy loads into whichever is running.
inline constexpr const char* kVersion = "acb-pc-2011";
inline constexpr const char* kModules[] = {"ACBMP.exe", "ACBSP.exe", nullptr};
// OSDK 1.2.4's JobPopulateConfig: GET /OnlineConfigService.svc/GetOnlineConfig
// over plain HTTP, from whichever of these the build is pointed at.
inline constexpr const char* kHosts[] = {
    "onlineconfigservice.ubi.com", "cert-onlineconfigservice.ubi.com",
    "uat-onlineconfigservice.ubi.com",
    // Whatever else it looks up at Ubisoft (the real online config still
    // names live RendezVous hosts such as lb-ne1-z02-rdv-ac.ubisoft.com).
    "*.ubi.com", "*.ubisoft.com", nullptr
};
// ACBMP.exe imports the BSD-style calls from WS2_32 by ordinal and only the
// WSA* extensions and getaddrinfo by name (pefile prints names for both, so
// check import_by_ordinal). A name binding misses an ordinal import, and the
// unhooked gethostbyname then resolves Ubisoft's real hosts.
inline constexpr NetworkBindingDefinition kNetwork[] = {
    {NetworkApi::AddrInfoLookup, "getaddrinfo", 0},
    {NetworkApi::GetHostByName, nullptr, 52},
    {NetworkApi::Socket, nullptr, 23},
    {NetworkApi::Bind, nullptr, 2},
    {NetworkApi::Connect, nullptr, 4},
    {NetworkApi::Send, nullptr, 19},
    {NetworkApi::Recv, nullptr, 16},
    {NetworkApi::CloseSocket, nullptr, 3},
    {NetworkApi::SendTo, nullptr, 20},
    {NetworkApi::RecvFrom, nullptr, 17},
    {NetworkApi::WSASendTo, "WSASendTo", 0},
    {NetworkApi::WSARecvFrom, "WSARecvFrom", 0},
    {NetworkApi::WSAGetOverlappedResult, "WSAGetOverlappedResult", 0},
    {NetworkApi::WSAIoctl, "WSAIoctl", 0},
};
inline constexpr TlsHookDefinition kTls{0, TlsHookMethod::None, 0, 0};
// Not yet observed; 0 leaves the launch proof off for this title.
inline constexpr uint16_t kPrudpListenerPort = 0;
inline constexpr uint16_t kLaunchPort = 6576;
inline constexpr const char* kPlayforwardTitle = "assassins-creed-brotherhood";
}
