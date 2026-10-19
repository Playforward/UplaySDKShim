#include "games/brotherhood/identity.h"

#include "core/config.h"
#include "core/hooking/iat.h"
#include "core/logging.h"

#include <cstdio>
#include <cstring>
#include <string>

namespace brotherhood {
namespace {

// What ACBSP.exe's launch line carries (format string in ACBSP.exe:
// "%s /launchedfromotherexec /onlineUser:%s /onlinePassword:%s %s"). The
// password is a stand-in: the server never checks it.
constexpr const char* kPassword = "playforward";

std::string g_command_line_a;
std::wstring g_command_line_w;

bool starts_option(const std::string& token, const char* name) {
    const size_t length = std::strlen(name);
    return token.size() > length + 1 && token[0] == '/' &&
           _strnicmp(token.c_str() + 1, name, length) == 0 && token[length + 1] == ':';
}

// Splits on whitespace outside quotes, keeping each token as written.
std::string rewrite(const char* original, const char* name) {
    std::string out;
    bool launched = false;
    const char* p = original ? original : "";
    bool first = true;
    while (*p) {
        while (*p == ' ' || *p == '\t') ++p;
        if (!*p) break;
        const char* start = p;
        bool quoted = false;
        while (*p && (quoted || (*p != ' ' && *p != '\t'))) {
            if (*p == '"') quoted = !quoted;
            ++p;
        }
        std::string token(start, p);
        if (!first && (starts_option(token, "onlineUser") || starts_option(token, "onlinePassword"))) continue;
        if (!first && _stricmp(token.c_str(), "/launchedfromotherexec") == 0) launched = true;
        if (!out.empty()) out += ' ';
        out += token;
        first = false;
    }
    // Without it ACBMP treats the run as not started from ACBSP.
    if (!launched) out += " /launchedfromotherexec";
    out += " /onlineUser:";
    out += name;
    out += " /onlinePassword:";
    out += kPassword;
    return out;
}

LPSTR WINAPI hooked_get_command_line_a() {
    return g_command_line_a.data();
}

LPWSTR WINAPI hooked_get_command_line_w() {
    return g_command_line_w.data();
}

}

void install_identity(HMODULE process_module) {
    const HookConfig& c = hook_config();
    char path[MAX_PATH] = {};
    GetModuleFileNameA(process_module, path, MAX_PATH);
    const char* exe = std::strrchr(path, '\\');
    exe = exe ? exe + 1 : path;
    if (_stricmp(exe, "ACBMP.exe") != 0) return;
    if (!c.login_name[0]) {
        shim_log("[acb] no login_name in hook.config; ACBMP logs in as whatever /onlineUser: ACBSP passed");
        return;
    }
    if (std::strchr(c.login_name, ' ') || std::strchr(c.login_name, '"')) {
        shim_log("[acb] login_name '%s' has a space or quote, which ACBMP's /key:value options cannot carry; not applied",
                 c.login_name);
        return;
    }

    g_command_line_a = rewrite(GetCommandLineA(), c.login_name);
    const int wide = MultiByteToWideChar(CP_UTF8, 0, g_command_line_a.c_str(), -1, nullptr, 0);
    g_command_line_w.assign(wide > 0 ? wide : 1, L'\0');
    if (wide > 0) MultiByteToWideChar(CP_UTF8, 0, g_command_line_a.c_str(), -1, g_command_line_w.data(), wide);

    const bool a = patch_iat(process_module, "KERNEL32.dll", "GetCommandLineA",
                             reinterpret_cast<void*>(&hooked_get_command_line_a)) != nullptr;
    const bool w = patch_iat(process_module, "KERNEL32.dll", "GetCommandLineW",
                             reinterpret_cast<void*>(&hooked_get_command_line_w)) != nullptr;
    shim_log("[acb] ACBMP will log in as %s (GetCommandLineA %s, GetCommandLineW %s): %s",
             c.login_name, a ? "hooked" : "not imported", w ? "hooked" : "not imported", g_command_line_a.c_str());
}

}
