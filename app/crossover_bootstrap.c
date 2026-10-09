/* SPDX-License-Identifier: GPL-2.0-or-later
 * Windows 1.6 runtime adapter: support expanded TLS slots without changing
 * guest registers, flags, stack, or red zone. All main-image RVAs are guarded
 * by the patcher's SHA256 check. This DLL has no CRT dependencies.
 */
#include <windows.h>
#include <stdint.h>

#define GUEST_TLS_SLOT_RVA 0x00c052d8
#define RUNTIME_LOW_MAP_RVA 0x0000cbb0
typedef struct { uint64_t address, size, flags; } Segment;
typedef void *(*LowMap)(size_t size, int protection);

static volatile LONG cursor_watcher_started = 0;

static void hide_cursor(int *show_cursor_calls) {
    do {
        ++*show_cursor_calls;
    } while (ShowCursor(FALSE) >= 0);
}

static DWORD WINAPI watch_game_cursor(LPVOID unused) {
    (void)unused;
    const DWORD game_pid = GetCurrentProcessId();
    BOOL game_has_focus = FALSE;
    int show_cursor_calls = 0;
    for (;;) {
        HWND foreground = GetForegroundWindow();
        DWORD foreground_pid = 0;
        if (foreground) GetWindowThreadProcessId(foreground, &foreground_pid);
        const BOOL focused = foreground_pid == game_pid;
        if (focused && !game_has_focus) {
            hide_cursor(&show_cursor_calls);
        } else if (!focused && game_has_focus) {
            while (show_cursor_calls > 0) {
                ShowCursor(TRUE);
                --show_cursor_calls;
            }
        } else if (focused) {
            CURSORINFO cursor = {sizeof(cursor)};
            if (GetCursorInfo(&cursor) && (cursor.flags & CURSOR_SHOWING)) {
                hide_cursor(&show_cursor_calls);
            }
        }
        game_has_focus = focused;
        Sleep(75);
    }
}

static void start_cursor_watcher(void) {
    if (InterlockedCompareExchange(&cursor_watcher_started, 1, 0) != 0) return;
    HANDLE thread = CreateThread(NULL, 0, watch_game_cursor, NULL, 0, NULL);
    if (thread) CloseHandle(thread);
    else InterlockedExchange(&cursor_watcher_started, 0);
}

static int is_tcb_load(const unsigned char *at) {
    return *(const uint64_t *)at == UINT64_C(0x25048b4865) && !at[8];
}

static void stop(void) {
    static const char message[] = "STOP: CrossOver TLS adapter could not allocate a nearby trampoline\r\n";
    DWORD written;
    WriteFile(GetStdHandle(STD_ERROR_HANDLE), message, sizeof(message) - 1, &written, NULL);
    ExitProcess(21);
}

static void relative_jump(unsigned char *at, const unsigned char *target) {
    intptr_t delta = (intptr_t)((uintptr_t)target - ((uintptr_t)at + 5));
    if (delta < INT32_MIN || delta > INT32_MAX) stop();
    at[0] = 0xe9;
    *(int32_t *)(at + 1) = (int32_t)delta;
}

__declspec(dllexport) uint64_t bb_crossover_patch_tcb(
        const Segment *segments, uint64_t count, unsigned char *image) {
    start_cursor_watcher();
    unsigned char *main_image = (unsigned char *)GetModuleHandleW(NULL);
    DWORD slot = *(DWORD *)(main_image + GUEST_TLS_SLOT_RVA);
    if (slot == TLS_OUT_OF_INDEXES) stop();
    uint64_t matches = 0;
    for (uint64_t s = 0; s < count; ++s) {
        if (!(segments[s].flags & 1) || segments[s].size < 9) continue;
        unsigned char *at = image + segments[s].address;
        unsigned char *end = at + segments[s].size - 9;
        for (; at <= end; ++at) if (is_tcb_load(at)) { ++matches; at += 8; }
    }
    unsigned char *stubs = NULL;
    if (matches && slot >= 64) {
        LowMap allocate = (LowMap)(main_image + RUNTIME_LOW_MAP_RVA);
        stubs = allocate((size_t)matches * 32, 7); /* PROT_READ|WRITE|EXEC */
        if (!stubs) stop();
    }
    uint64_t patched = 0;
    for (uint64_t s = 0; s < count; ++s) {
        if (!(segments[s].flags & 1) || segments[s].size < 9) continue;
        unsigned char *at = image + segments[s].address;
        unsigned char *end = at + segments[s].size - 9;
        for (; at <= end; ++at) {
            if (!is_tcb_load(at)) continue;
            if (slot < 64) {
                *(uint32_t *)(at + 5) = 0x1480 + slot * 8;
            } else {
                unsigned char *stub = stubs + patched * 32;
                /* mov rax,gs:[TlsExpansionSlots]; mov rax,[rax+(slot-64)*8] */
                *(uint64_t *)stub = UINT64_C(0x178025048b4865);
                stub[8] = 0;
                stub[9] = 0x48; stub[10] = 0x8b; stub[11] = 0x80;
                *(uint32_t *)(stub + 12) = (slot - 64) * 8;
                relative_jump(stub + 16, at + 9);
                relative_jump(at, stub);
                for (unsigned i = 5; i < 9; ++i) at[i] = 0x90;
            }
            ++patched;
            at += 8;
        }
    }
    if (stubs) FlushInstructionCache(GetCurrentProcess(), stubs, (SIZE_T)matches * 32);
    return patched;
}

BOOL WINAPI DllMain(HINSTANCE instance, DWORD reason, LPVOID reserved) {
    (void)instance;
    (void)reserved;
    (void)reason;
    return TRUE;
}
