#include "games/conviction/orbit.h"

#include "core/config.h"
#include "core/hooking/iat.h"
#include "core/logging.h"
#include "games/conviction/agora.h"

#include <cstdint>
#include <cstdio>
#include <cstring>
#include <cwchar>
#include <string>
#include <vector>

namespace {

constexpr const char* kLauncherKey = "SOFTWARE\\Ubisoft\\Launcher";
constexpr const char* kOrbitDll = "ubiorbitapi_r2.dll";
constexpr const char* kPassword = "playforward";
const HKEY kFakeLauncherKey = reinterpret_cast<HKEY>(static_cast<uintptr_t>(0x5C0A1));

struct OrbitSession { uint32_t magic = 0x0B17; };
OrbitSession g_session;
LONG g_next_request = 1000;

template <typename... Args>
void callback(void* listener, Args... args) {
    void** vtable = listener ? *static_cast<void***>(listener) : nullptr;
    using Fn = void(__thiscall*)(void*, Args...);
    auto fn = vtable ? reinterpret_cast<Fn>(vtable[0]) : nullptr;
    if (fn) fn(listener, args...);
    else shim_log("[scc-orbit] listener %p has no callback", listener);
}

struct SaveInfo {
    unsigned product = 0, id = 0, size = 0;
    wchar_t name[128] = {};
};

struct SaveReader { std::vector<char> data; };

struct SaveWriter {
    unsigned product = 0, id = 0;
    std::vector<char> data;
    std::wstring name;
};

std::wstring save_dir() {
    wchar_t exe[MAX_PATH] = {};
    GetModuleFileNameW(nullptr, exe, MAX_PATH);
    std::wstring dir(exe);
    dir.resize(dir.find_last_of(L"\\/") + 1);
    dir += L"playforward-orbit";
    CreateDirectoryW(dir.c_str(), nullptr);
    const char* name = hook_config().login_name;
    wchar_t wide[64] = L"player";
    if (name[0]) MultiByteToWideChar(CP_UTF8, 0, name, -1, wide, 63);
    dir += L"\\";
    dir += wide;
    CreateDirectoryW(dir.c_str(), nullptr);
    return dir + L"\\";
}

std::wstring save_path(unsigned product, unsigned id, const wchar_t* ext) {
    wchar_t file[64];
    swprintf(file, 64, L"%u_%u.%ls", product, id, ext);
    return save_dir() + file;
}

bool read_file(const std::wstring& path, std::vector<char>& out) {
    HANDLE f = CreateFileW(path.c_str(), GENERIC_READ, FILE_SHARE_READ, nullptr, OPEN_EXISTING, 0, nullptr);
    if (f == INVALID_HANDLE_VALUE) return false;
    DWORD size = GetFileSize(f, nullptr), got = 0;
    out.resize(size);
    bool ok = size == 0 || (ReadFile(f, out.data(), size, &got, nullptr) && got == size);
    CloseHandle(f);
    return ok;
}

bool write_file(const std::wstring& path, const void* data, size_t size) {
    std::wstring temp = path + L".tmp";
    HANDLE f = CreateFileW(temp.c_str(), GENERIC_WRITE, 0, nullptr, CREATE_ALWAYS, 0, nullptr);
    if (f == INVALID_HANDLE_VALUE) return false;
    DWORD put = 0;
    bool ok = size == 0 || (WriteFile(f, data, static_cast<DWORD>(size), &put, nullptr) && put == size);
    CloseHandle(f);
    return ok && MoveFileExW(temp.c_str(), path.c_str(), MOVEFILE_REPLACE_EXISTING);
}

std::vector<SaveInfo*> g_infos; 

void write_frame(HANDLE pipe, uint8_t type, const uint8_t* payload, uint16_t size) {
    uint8_t frame[5 + 16] = {static_cast<uint8_t>(size >> 8), static_cast<uint8_t>(size), 0, 0, type};
    memcpy(frame + 5, payload, size);
    DWORD put = 0;
    WriteFile(pipe, frame, 5u + size, &put, nullptr);
}

DWORD WINAPI serve_orbit_pipe(LPVOID handle) {
    HANDLE pipe = static_cast<HANDLE>(handle);
    std::vector<uint8_t> pending;
    uint8_t buffer[4096];
    unsigned long long total = 0, reports = 0;
    for (;;) {
        DWORD got = 0;
        if (!ReadFile(pipe, buffer, sizeof buffer, &got, nullptr)) {
            shim_log("[scc-orbit] DRM link closed after %llu bytes, %llu reports acknowledged (error %lu)", total, reports, GetLastError());
            break;
        }
        total += got;
        pending.insert(pending.end(), buffer, buffer + got);
        while (pending.size() >= 5) {
            size_t size = (static_cast<size_t>(pending[0]) << 8) | pending[1];
            if (pending.size() < 5 + size) break;
            uint8_t type = pending[4];
            const uint8_t* payload = pending.data() + 5;
            if (type == 1 && size >= 12) {
                write_frame(pipe, 5, payload + 8, 4);
                if (reports++ < 3) shim_log("[scc-orbit] DRM link: acknowledged progress report %u (later ones silently)",
                                           (payload[8] << 24) | (payload[9] << 16) | (payload[10] << 8) | payload[11]);
            } else {
                char hex[3 * 16 + 1] = {};
                for (size_t i = 0; i < size && i < 16; ++i) snprintf(hex + 3 * i, 4, "%02x ", payload[i]);
                shim_log("[scc-orbit] DRM link: type %u, %u bytes: %s", type, static_cast<unsigned>(size), hex);
            }
            pending.erase(pending.begin(), pending.begin() + 5 + size);
        }
    }
    CloseHandle(pipe);
    return 0;
}

HANDLE open_drm_link() {
    char name[96];
    static LONG serial = 0;
    snprintf(name, sizeof name, "\\\\.\\pipe\\playforward-scc-orbit-%lu-%ld", GetCurrentProcessId(), InterlockedIncrement(&serial));
    HANDLE server = CreateNamedPipeA(name, PIPE_ACCESS_DUPLEX | FILE_FLAG_OVERLAPPED,
                                     PIPE_TYPE_BYTE | PIPE_READMODE_BYTE | PIPE_WAIT, 1, 65536, 65536, 0, nullptr);
    if (server == INVALID_HANDLE_VALUE) {
        shim_log("[scc-orbit] cannot create DRM link pipe: %lu", GetLastError());
        return INVALID_HANDLE_VALUE;
    }
    HANDLE client = CreateFileA(name, GENERIC_READ | GENERIC_WRITE, 0, nullptr, OPEN_EXISTING, 0, nullptr);
    if (client == INVALID_HANDLE_VALUE) {
        shim_log("[scc-orbit] cannot open DRM link pipe: %lu", GetLastError());
        CloseHandle(server);
        return INVALID_HANDLE_VALUE;
    }
    if (HANDLE t = CreateThread(nullptr, 0, serve_orbit_pipe, client, 0, nullptr)) CloseHandle(t);
    return server;
}

using RegOpenKeyExA_t = LONG(WINAPI*)(HKEY, LPCSTR, DWORD, REGSAM, PHKEY);
using RegQueryValueExA_t = LONG(WINAPI*)(HKEY, LPCSTR, LPDWORD, LPDWORD, LPBYTE, LPDWORD);
using RegCloseKey_t = LONG(WINAPI*)(HKEY);
using LoadLibraryA_t = HMODULE(WINAPI*)(LPCSTR);
RegOpenKeyExA_t g_reg_open = nullptr;
RegQueryValueExA_t g_reg_query = nullptr;
RegCloseKey_t g_reg_close = nullptr;
LoadLibraryA_t g_load_library = nullptr;

HMODULE this_module() {
    HMODULE module = nullptr;
    GetModuleHandleExA(GET_MODULE_HANDLE_EX_FLAG_FROM_ADDRESS | GET_MODULE_HANDLE_EX_FLAG_UNCHANGED_REFCOUNT,
                       reinterpret_cast<LPCSTR>(&this_module), &module);
    return module;
}

LONG WINAPI hooked_reg_open(HKEY key, LPCSTR sub_key, DWORD options, REGSAM sam, PHKEY result) {
    if (key == HKEY_LOCAL_MACHINE && sub_key && _stricmp(sub_key, kLauncherKey) == 0 && result) {
        *result = kFakeLauncherKey;
        return ERROR_SUCCESS;
    }
    return g_reg_open(key, sub_key, options, sam, result);
}

LONG WINAPI hooked_reg_query(HKEY key, LPCSTR value, LPDWORD reserved, LPDWORD type, LPBYTE data, LPDWORD size) {
    if (key != kFakeLauncherKey) return g_reg_query(key, value, reserved, type, data, size);
    if (!value || _stricmp(value, "InstallDir") != 0) return ERROR_FILE_NOT_FOUND;
    char dir[MAX_PATH] = {};
    GetModuleFileNameA(nullptr, dir, MAX_PATH);
    if (char* slash = strrchr(dir, '\\')) *slash = 0;
    DWORD needed = static_cast<DWORD>(strlen(dir) + 1);
    if (type) *type = REG_SZ;
    if (!size) return data ? ERROR_INVALID_PARAMETER : ERROR_SUCCESS;
    if (data && *size < needed) { *size = needed; return ERROR_MORE_DATA; }
    if (data) memcpy(data, dir, needed);
    *size = needed;
    return ERROR_SUCCESS;
}

LONG WINAPI hooked_reg_close(HKEY key) {
    return key == kFakeLauncherKey ? ERROR_SUCCESS : g_reg_close(key);
}

HMODULE WINAPI hooked_load_library(LPCSTR path) {
    size_t length = path ? strlen(path) : 0, suffix = strlen(kOrbitDll);
    if (length >= suffix && _stricmp(path + length - suffix, kOrbitDll) == 0) {
        shim_log("[scc-orbit] LoadLibraryA(%s) -> served by the shim", path);
        conviction::install_agora_root_key(GetModuleHandleA(nullptr));
        return this_module();
    }
    return g_load_library(path);
}

}

namespace conviction {
void install_orbit(HMODULE process_module) {
    g_reg_open = reinterpret_cast<RegOpenKeyExA_t>(patch_iat(process_module, "ADVAPI32.dll", "RegOpenKeyExA", reinterpret_cast<void*>(&hooked_reg_open)));
    g_reg_query = reinterpret_cast<RegQueryValueExA_t>(patch_iat(process_module, "ADVAPI32.dll", "RegQueryValueExA", reinterpret_cast<void*>(&hooked_reg_query)));
    g_reg_close = reinterpret_cast<RegCloseKey_t>(patch_iat(process_module, "ADVAPI32.dll", "RegCloseKey", reinterpret_cast<void*>(&hooked_reg_close)));
    g_load_library = reinterpret_cast<LoadLibraryA_t>(patch_iat(process_module, "KERNEL32.dll", "LoadLibraryA", reinterpret_cast<void*>(&hooked_load_library)));
    if (!g_reg_open || !g_reg_query || !g_reg_close || !g_load_library) {
        shim_log("[scc-orbit] could not hook the launcher lookup; the game will report a launcher error");
        return;
    }
    const char* name = hook_config().login_name;
    shim_log("[scc-orbit] serving ubiorbitapi_r2.dll; will log in as %s", name[0] ? name : "(no login_name: player)");
}
}

extern "C" {

void* MgOrbitdllGetSession() { shim_log("[scc-orbit] GetSession"); return &g_session; }
void* MgOrbitdllGetFakeSession() { return &g_session; }
void MgOrbitdllUpdate(void*) {}
unsigned MgOrbitdllGetRequestUniqueId(void*) { return static_cast<unsigned>(InterlockedIncrement(&g_next_request)); }

bool MgOrbitdllStartLauncher(void*, unsigned a, unsigned b, const char* language, const char* arguments) {
    shim_log("[scc-orbit] StartLauncher(%u, %u, %s, %s) -> false", a, b, language ? language : "", arguments ? arguments : "");
    return false;
}

void MgOrbitdllGetLoginDetails(void*, unsigned request, void* listener) {
    const char* name = hook_config().login_name;
    if (!name[0]) name = "player";
    wchar_t wide[64] = {};
    MultiByteToWideChar(CP_UTF8, 0, name, -1, wide, 63);
    shim_log("[scc-orbit] GetLoginDetails req=%u -> %s", request, name);
    callback<unsigned, const char*, const wchar_t*, const char*>(listener, request, name, wide, kPassword);
}

void MgOrbitdllGetOrbitServer(void*, unsigned request, void* listener, unsigned a, unsigned b) {
    HANDLE link = open_drm_link();
    shim_log("[scc-orbit] GetOrbitServer req=%u (%u, %#x) -> local DRM link %p", request, a, b, link);
    callback<unsigned, HANDLE>(listener, request, link);
}

void MgOrbitdllGetNetworkTraffic(void*, unsigned request, void*) {
    shim_log("[scc-orbit] GetNetworkTraffic req=%u (not answered)", request);
}

const wchar_t* MgOrbitdllGetLocText(void*, const wchar_t* key, const char* context) {
    shim_log("[scc-orbit] GetLocText(%ls, %s)", key ? key : L"", context ? context : "");
    return key ? key : L"";
}

void MgOrbitdllGetSavegameList(void*, unsigned request, void* listener, unsigned product) {
    std::vector<SaveInfo*> list;
    wchar_t pattern[32];
    swprintf(pattern, 32, L"%u_*.sav", product);
    WIN32_FIND_DATAW found;
    HANDLE search = FindFirstFileW((save_dir() + pattern).c_str(), &found);
    if (search != INVALID_HANDLE_VALUE) {
        do {
            auto* info = new SaveInfo;
            info->product = product;
            if (swscanf(found.cFileName, L"%u_%u.sav", &info->product, &info->id) != 2) { delete info; continue; }
            info->size = found.nFileSizeLow;
            std::vector<char> name;
            if (read_file(save_path(product, info->id, L"name"), name))
                memcpy(info->name, name.data(), std::min(name.size(), sizeof info->name - sizeof(wchar_t)));
            g_infos.push_back(info);
            list.push_back(info);
        } while (FindNextFileW(search, &found));
        FindClose(search);
    }
    shim_log("[scc-orbit] GetSavegameList req=%u product=%u -> %u saves", request, product, static_cast<unsigned>(list.size()));
    static std::vector<SaveInfo*> handed;   // the game copies the handles out during the callback
    handed = list;
    callback<unsigned, SaveInfo**, unsigned>(listener, request, handed.empty() ? nullptr : handed.data(), static_cast<unsigned>(handed.size()));
}

void MgOrbitdllGetSavegameReader(void*, unsigned request, void* listener, unsigned product, unsigned id) {
    auto* reader = new SaveReader;
    bool found = read_file(save_path(product, id, L"sav"), reader->data);
    shim_log("[scc-orbit] GetSavegameReader req=%u %u/%u -> %s (%u bytes)", request, product, id, found ? "found" : "missing",
             static_cast<unsigned>(reader->data.size()));
    if (!found) { delete reader; reader = nullptr; }
    callback<unsigned, int, SaveReader*>(listener, request, found ? 0 : 1, reader);
}

void MgOrbitdllSaveGameReaderRead(SaveReader* reader, unsigned request, void* listener, unsigned offset, void* buffer, unsigned count) {
    unsigned got = 0;
    if (reader && offset < reader->data.size()) {
        got = std::min<unsigned>(count, static_cast<unsigned>(reader->data.size()) - offset);
        memcpy(buffer, reader->data.data() + offset, got);
    }
    callback<unsigned, unsigned>(listener, request, got);
}

void MgOrbitdllSaveGameReaderClose(SaveReader* reader) { delete reader; }

void MgOrbitdllGetSavegameWriter(void*, unsigned request, void* listener, unsigned product, unsigned id, bool open) {
    auto* writer = new SaveWriter;
    writer->product = product;
    writer->id = id;
    shim_log("[scc-orbit] GetSavegameWriter req=%u %u/%u open=%d", request, product, id, static_cast<int>(open));
    callback<unsigned, int, SaveWriter*>(listener, request, 0, writer);
}

bool MgOrbitdllSaveGameWriterSetName(SaveWriter* writer, const wchar_t* name) {
    if (writer && name) writer->name = name;
    return true;
}

void MgOrbitdllSaveGameWriterWrite(SaveWriter* writer, unsigned request, void* listener, const void* buffer, unsigned count) {
    if (writer && buffer) writer->data.insert(writer->data.end(), static_cast<const char*>(buffer), static_cast<const char*>(buffer) + count);
    callback<unsigned, unsigned>(listener, request, writer ? count : 0);
}

void MgOrbitdllSaveGameWriterClose(SaveWriter* writer, bool commit) {
    if (!writer) return;
    if (commit) {
        bool ok = write_file(save_path(writer->product, writer->id, L"sav"), writer->data.data(), writer->data.size());
        if (!writer->name.empty())
            write_file(save_path(writer->product, writer->id, L"name"), writer->name.c_str(), (writer->name.size() + 1) * sizeof(wchar_t));
        shim_log("[scc-orbit] saved %u/%u (%u bytes)%s", writer->product, writer->id, static_cast<unsigned>(writer->data.size()), ok ? "" : " FAILED");
    }
    delete writer;
}

void MgOrbitdllRemoveSavegame(void*, unsigned request, void* listener, unsigned product, unsigned id) {
    bool removed = DeleteFileW(save_path(product, id, L"sav").c_str()) != 0;
    DeleteFileW(save_path(product, id, L"name").c_str());
    shim_log("[scc-orbit] RemoveSavegame req=%u %u/%u -> %d", request, product, id, static_cast<int>(removed));
    callback<unsigned, bool>(listener, request, removed);
}

const wchar_t* MgOrbitdllSaveGameInfoGetName(SaveInfo* info) { return info ? info->name : L""; }
unsigned MgOrbitdllSaveGameInfoGetProductId(SaveInfo* info) { return info ? info->product : 0; }
unsigned MgOrbitdllSaveGameInfoGetSavegameId(SaveInfo* info) { return info ? info->id : 0; }
unsigned MgOrbitdllSaveGameInfoGetSize(SaveInfo* info) { return info ? info->size : 0; }

}
