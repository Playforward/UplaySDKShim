#pragma once

#include "core/networking/tls_pin.h"

#include <cstdint>
#include <windows.h>

struct HookConfig {
    char redirect_ip[16] = {};
    uint32_t redirect_ip_be = 0;
    char bind_ip[16] = {};
    uint32_t bind_ip_be = 0;
    bool bypass_tls_verify = false;
    uint64_t rva_tls_verify = 0;
    uint32_t tls_verify_stack_bytes = 0;
    static constexpr size_t kMaxTlsPins = 2;
    tls_pin::Pin tls_pins[kMaxTlsPins] = {};
    size_t tls_pin_count = 0;
    bool redirect_all_dns = false;
    bool capture_tcp = false;
    bool dump_module = false;
    bool log_rdv_full = false;
    bool log_tcp_full = false;
    bool trace_getprocaddr = false;
    bool trace_cng = false;
    bool trace_cng_payload = false;
    bool trace_stack = false;
    bool capture_ssl = false;
    bool capture_uplay = false;
    bool dump_session_blob = false;
    bool trace_uplay = false;
    bool complete_upc_product_list = false;
    bool trace_tls_alert = false;
    bool dump_ssl_jumptable = false;
    bool trace_invite_dostart = false;
    bool trace_game_log = false;
    bool trace_debug_strings = false;
    bool trace_winhttp = false;
    bool trace_net_states = false;
    bool nla_report_online = true;
    bool menu_autopress = false;
    bool online_autologin = true;
    bool build_fixes = true;
    char trace_points[512] = {};
    char login_name[64] = {};
    bool playforward_launch = true;
    bool playforward_presence = true;
    uint16_t launch_port = 0;
    uint16_t prudp_port = 0;
    char launch_pipe[64] = "playforward-game-bridge";
    uint16_t bridge_port = 24771;
    uint16_t redirect_http_port = 0;
};

const HookConfig& hook_config();
void initialize_hook_config(HINSTANCE shim_module);
void set_hook_config(const HookConfig& config);
HookConfig load_hook_config();
void log_hook_config(const HookConfig& config);
