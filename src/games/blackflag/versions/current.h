#pragma once

#include "core/game_adapter.h"

namespace blackflag::current {
// AC4BFMP.exe is the multiplayer build; AC4BFSP.exe (single player) launches
// it with /launchedfromotherexec. Both import bink2w32.dll, so the one proxy
// loads into whichever is running.
inline constexpr const char* kVersion = "ac4bf-pc-steam";
inline constexpr const char* kModules[] = {"AC4BFMP.exe", "AC4BFSP.exe", nullptr};
// UbiServices (https://{env}api-ubiservices.ubi.com) gives it its sandbox,
// then RendezVous. Everything else at Ubisoft goes here too, so a missed
// lookup cannot reach whatever Ubisoft still runs.
inline constexpr const char* kHosts[] = {"*.ubi.com", "*.ubisoft.com", nullptr};
// As Brotherhood: WS2_32's classic calls by ordinal, the WSA* extensions and
// getaddrinfo by name.
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
inline constexpr uint16_t kLaunchPort = 6578;
inline constexpr const char* kPlayforwardTitle = "assassins-creed-iv-black-flag";
}
