#include "pg_hook_monitor.h"
#include <TlHelp32.h>
#include <Psapi.h>
#include <string.h>

#pragma comment(lib, "psapi.lib")

static HANDLE g_hook_thread;
static HANDLE g_hook_stop;
static PG_HOOK_CALLBACK g_hook_callback;
static DWORD g_hook_interval = 5000;

static BOOL IsRedirect(const BYTE* p) {
    if (p[0] == 0xE9 || p[0] == 0xE8 || p[0] == 0xEB) return TRUE;
    if (p[0] == 0xFF && (p[1] == 0x25 || p[1] == 0x15)) return TRUE;
    if (p[0] == 0x48 && p[1] == 0xB8 && p[10] == 0xFF && p[11] == 0xE0) return TRUE;
    if (p[0] == 0x49 && p[1] == 0xBB && p[10] == 0x41 && p[11] == 0xFF && p[12] == 0xE3) return TRUE;
    return FALSE;
}

static void ScanProcess(DWORD pid) {
    HANDLE hp = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, FALSE, pid);
    if (!hp) return;
    HMODULE mods[1024];
    DWORD needed = 0;
    if (EnumProcessModules(hp, mods, sizeof(mods), &needed)) {
        DWORD count = needed / sizeof(HMODULE);
        for (DWORD m = 0; m < count; ++m) {
            char path[MAX_PATH] = { 0 };
            if (!GetModuleFileNameExA(hp, mods[m], path, MAX_PATH)) continue;
            const char* base = strrchr(path, '\\');
            base = base ? base + 1 : path;
            HMODULE local = GetModuleHandleA(base);
            if (!local) local = LoadLibraryExA(path, NULL, DONT_RESOLVE_DLL_REFERENCES);
            if (!local) continue;
            BYTE* dos = (BYTE*)local;
            if (*(WORD*)dos != IMAGE_DOS_SIGNATURE) continue;
            IMAGE_NT_HEADERS* nt = (IMAGE_NT_HEADERS*)(dos + *(LONG*)(dos + 0x3C));
            if (nt->Signature != IMAGE_NT_SIGNATURE) continue;
            DWORD exportRva = nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress;
            if (!exportRva) continue;
            IMAGE_EXPORT_DIRECTORY* exp = (IMAGE_EXPORT_DIRECTORY*)(dos + exportRva);
            DWORD* names = (DWORD*)(dos + exp->AddressOfNames);
            WORD* ords = (WORD*)(dos + exp->AddressOfNameOrdinals);
            DWORD* funcs = (DWORD*)(dos + exp->AddressOfFunctions);
            for (DWORD i = 0; i < exp->NumberOfNames; ++i) {
                const char* fn = (const char*)(dos + names[i]);
                DWORD rva = funcs[ords[i]];
                if (rva >= nt->OptionalHeader.SizeOfImage) continue;
                BYTE* target = dos + rva;
                if (!IsRedirect(target)) continue;
                PG_HOOK_EVENT e = { 0 };
                e.pid = pid;
                strncpy_s(e.module, sizeof(e.module), base, _TRUNCATE);
                strncpy_s(e.function, sizeof(e.function), fn, _TRUNCATE);
                e.opcode_size = 16;
                memcpy(e.opcode, target, 16);
                if (g_hook_callback) g_hook_callback(&e);
            }
        }
    }
    CloseHandle(hp);
}

static DWORD WINAPI HookThread(LPVOID param) {
    UNREFERENCED_PARAMETER(param);
    while (WaitForSingleObject(g_hook_stop, g_hook_interval) == WAIT_TIMEOUT) {
        HANDLE snap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
        if (snap == INVALID_HANDLE_VALUE) continue;
        PROCESSENTRY32W pe = { 0 };
        pe.dwSize = sizeof(pe);
        if (Process32FirstW(snap, &pe)) {
            do {
                ScanProcess(pe.th32ProcessID);
            } while (Process32NextW(snap, &pe));
        }
        CloseHandle(snap);
    }
    return 0;
}

BOOL PGHookStart(PG_HOOK_CALLBACK callback, DWORD interval_ms) {
    if (g_hook_thread) return FALSE;
    g_hook_callback = callback;
    g_hook_interval = interval_ms ? interval_ms : 5000;
    g_hook_stop = CreateEventW(NULL, TRUE, FALSE, NULL);
    if (!g_hook_stop) return FALSE;
    g_hook_thread = CreateThread(NULL, 0, HookThread, NULL, 0, NULL);
    if (!g_hook_thread) {
        CloseHandle(g_hook_stop);
        g_hook_stop = NULL;
        return FALSE;
    }
    return TRUE;
}

void PGHookStop(void) {
    if (!g_hook_thread) return;
    SetEvent(g_hook_stop);
    WaitForSingleObject(g_hook_thread, 3000);
    CloseHandle(g_hook_thread);
    CloseHandle(g_hook_stop);
    g_hook_thread = NULL;
    g_hook_stop = NULL;
    g_hook_callback = NULL;
}
