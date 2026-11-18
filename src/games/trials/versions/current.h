#pragma once

#include "core/game_adapter.h"

namespace trials::current {
// trialsFMX.exe, Trials Evolution Gold Edition (Steam 220160), PE timestamp
// 0x529d7e1b (Dec 2013): Quazal OSDK 1.4.11 behind a SteamStub wrapper.
inline constexpr const char* kVersion = "trials-evolution-pc-2013";
inline constexpr const char* kModules[] = {"trialsFMX.exe", nullptr};
inline constexpr const char* kHosts[] = {
    "onlineconfigservice.ubi.com", "cert-onlineconfigservice.ubi.com",
    "uat-onlineconfigservice.ubi.com", nullptr
};
// The classic calls come from WSOCK32.dll by ordinal (the same ordinals as
// WS2_32's; redirect.cpp falls back to it); the rest from WS2_32.dll by name.
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
// Seen on the wire (hook.log, 2026-11-12): RendezVous leaves from 3074.
inline constexpr uint16_t kPrudpListenerPort = 3074;
inline constexpr uint16_t kLaunchPort = 6598;
inline constexpr const char* kPlayforwardTitle = "trials-evolution";
// The game's logger entry (cdecl, varargs), called with every debug line;
// the release build drops them all (channels off at 0x429640).
inline constexpr uint32_t kGameLogRva = 0x2a5b0;
// The failsafe tms/ugc.xml (Track Central feeds) the game parses when it
// gets no TMS document (TMSUGC::loadData, 0x69fba7).
inline constexpr uint32_t kFailsafeUgcXmlRva = 0x14d92c8;
inline constexpr uint32_t kFailsafeUgcXmlSize = 0x518;
inline constexpr uint8_t kGameLogPrologue[] = {0x51, 0x8B, 0x44, 0x24, 0x20, 0x8B, 0x4C, 0x24};
}
