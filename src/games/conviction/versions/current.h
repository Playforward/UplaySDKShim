#pragma once

#include "core/game_adapter.h"

namespace conviction::current {
// conviction_game.exe is the Steam build (app 33220, game version 1.04, PE
// timestamp 0x4c097be1), wrapped in SteamStub: its .text is encrypted on
// disk, so static analysis needs a runtime dump. Quazal RendezVous back end
// ("BackEndServices") plus Net-Z peer sessions; no uplay_r1 import -- the
// player and the always-online DRM link come from the Ubisoft Game Launcher's
// ubiorbitapi_r2.dll, which this shim serves itself (orbit.cpp).
inline constexpr const char* kVersion = "scc-pc-1.04";
inline constexpr const char* kModules[] = {"conviction_game.exe", nullptr};
// Plain-HTTP OnlineConfig (with &target=client), GameConnect, STUN.
inline constexpr const char* kHosts[] = {
    "onlineconfigservice.ubi.com", "cert-onlineconfigservice.ubi.com",
    "uat-onlineconfigservice.ubi.com", "*.ubi.com", "*.ubisoft.com", nullptr
};
// WS2_32's classic calls by ordinal, the WSA* extensions and getaddrinfo by name.
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
inline constexpr uint16_t kLaunchPort = 6584;
inline constexpr const char* kPlayforwardTitle = "splinter-cell-conviction";
}
