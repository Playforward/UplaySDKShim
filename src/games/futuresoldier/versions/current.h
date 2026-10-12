#pragma once

#include "core/game_adapter.h"

namespace futuresoldier::current {
inline constexpr const char* kVersion = "grfs-pc-2013";
inline constexpr const char* kModules[] = {"Future Soldier DX11.exe", "Future Soldier DX9.exe", nullptr};
inline constexpr const char* kHosts[] = {
    "onlineconfigservice.ubi.com", "cert-onlineconfigservice.ubi.com",
    "uat-onlineconfigservice.ubi.com", nullptr
};
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
inline constexpr uint16_t kPrudpListenerPort = 2347;
inline constexpr uint16_t kLaunchPort = 6574;
inline constexpr const char* kPlayforwardTitle = "ghost-recon-future-soldier";
}
