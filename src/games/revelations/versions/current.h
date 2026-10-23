#pragma once

#include "core/game_adapter.h"

namespace revelations::current {
// ACRMP.exe is the 2012 multiplayer build (PE timestamp 0x4f3b8231, OSDK
// 1.3.4). Steam stopped shipping it in March 2024; it comes from depot 201871
// manifest 3788743185036498953. ACRSP.exe launches it with
// /launchedfromotherexec. Both import binkw32.dll.
inline constexpr const char* kVersion = "acr-pc-2012";
inline constexpr const char* kModules[] = {"ACRMP.exe", "ACRSP.exe", nullptr};
// As Brotherhood: plain-HTTP OnlineConfig, and everything else at Ubisoft too,
// since Ubisoft's config service still answers this title's id and names live
// RendezVous hosts.
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
inline constexpr uint16_t kLaunchPort = 6580;
inline constexpr const char* kPlayforwardTitle = "assassins-creed-revelations";
}
