#pragma once

#include "core/game_adapter.h"

namespace ac3::current {
// AC3MP.exe is the 2013 multiplayer build (PE timestamp 0x517f6f88, OSDK
// 1.4.6, patch 1.06). Assassin's Creed III Remastered ships no multiplayer;
// this exe and its 2012-era DLLs come from the Animus Network package and
// are dropped into the Remastered folder. It imports binkw32.dll.
inline constexpr const char* kVersion = "ac3-pc-2013";
inline constexpr const char* kModules[] = {"AC3MP.exe", nullptr};
// As Revelations: plain-HTTP OnlineConfig, and every other Ubisoft host,
// though Ubisoft's config service no longer answers this title's id.
inline constexpr const char* kHosts[] = {
    "onlineconfigservice.ubi.com", "cert-onlineconfigservice.ubi.com",
    "uat-onlineconfigservice.ubi.com", "*.ubi.com", "*.ubisoft.com", nullptr
};
// Same WS2_32 import shape as ACRMP: classic calls by ordinal, the WSA*
// extensions and getaddrinfo by name.
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
inline constexpr uint16_t kLaunchPort = 6586;
inline constexpr const char* kPlayforwardTitle = "assassins-creed-3";
}
