#pragma once

#include "core/game_adapter.h"

namespace driver::current {
// Driver.exe is the Steam build (PE timestamp 0x4ec0d92b, OSDK 1.3.6, Hermes).
// It imports binkw32.dll by name; the Bink build is the same as Revelations'
// (77 exports, same ordinals).
inline constexpr const char* kVersion = "dsf-pc-2011";
inline constexpr const char* kModules[] = {"Driver.exe", nullptr};
// Plain-HTTP OnlineConfig (with &target=client), and everything else at
// Ubisoft too: its config service still answers this title's id and names
// RendezVous hosts that still resolve (lb-rdv-as-prod01.ubisoft.com:21231).
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
inline constexpr uint16_t kLaunchPort = 6582;
inline constexpr const char* kPlayforwardTitle = "driver-san-francisco";
}
