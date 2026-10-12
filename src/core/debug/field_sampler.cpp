#include "core/debug/field_sampler.h"

#include "core/logging.h"

#include <cstring>

namespace {

struct Sample {
    uintptr_t address = 0;
    unsigned long last = 0;
    bool valid = false;
    char label[64] = {};
};

constexpr int kMaxSamples = 4;
constexpr DWORD kIntervalMs = 250;
Sample g_samples[kMaxSamples];
volatile LONG g_count = 0;
HANDLE g_thread = nullptr;

DWORD WINAPI sampler(LPVOID) {
    for (;;) {
        const LONG count = g_count;
        for (LONG i = 0; i < count && i < kMaxSamples; ++i) {
            Sample& sample = g_samples[i];
            if (sample.address == 0) continue;
            if (IsBadReadPtr(reinterpret_cast<void*>(sample.address), 4)) {
                if (sample.valid) {
                    shim_log("[sample] %s at 0x%08llx became unreadable", sample.label,
                             static_cast<unsigned long long>(sample.address));
                    sample.valid = false;
                }
                continue;
            }
            const unsigned long value =
                *reinterpret_cast<const unsigned long*>(sample.address);
            if (!sample.valid || value != sample.last) {
                shim_log("[sample] %s at 0x%08llx = 0x%08lx%s", sample.label,
                         static_cast<unsigned long long>(sample.address), value,
                         sample.valid ? " (changed)" : " (initial)");
                sample.last = value;
                sample.valid = true;
            }
        }
        Sleep(kIntervalMs);
    }
}

}

bool field_sampler_start(uintptr_t address, const char* label) {
    const LONG index = InterlockedIncrement(&g_count) - 1;
    if (index >= kMaxSamples) {
        InterlockedDecrement(&g_count);
        shim_log("[sample] no free slot for %s", label ? label : "field");
        return false;
    }
    Sample& sample = g_samples[index];
    strncpy_s(sample.label, label ? label : "field", _TRUNCATE);
    sample.valid = false;
    sample.address = address;

    if (!g_thread) {
        g_thread = CreateThread(nullptr, 0, sampler, nullptr, 0, nullptr);
        if (!g_thread) {
            shim_log("[sample] CreateThread failed: %lu", GetLastError());
            return false;
        }
    }
    shim_log("[sample] %s watching 0x%08llx every %lums", sample.label,
             static_cast<unsigned long long>(address), static_cast<unsigned long>(kIntervalMs));
    return true;
}
