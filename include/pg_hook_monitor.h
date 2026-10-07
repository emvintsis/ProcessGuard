#ifndef PG_HOOK_MONITOR_H
#define PG_HOOK_MONITOR_H

#include <Windows.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef struct {
    DWORD pid;
    char module[MAX_PATH];
    char function[128];
    BYTE opcode[16];
    DWORD opcode_size;
} PG_HOOK_EVENT;

typedef void (*PG_HOOK_CALLBACK)(const PG_HOOK_EVENT* event);

BOOL PGHookStart(PG_HOOK_CALLBACK callback, DWORD interval_ms);
void PGHookStop(void);

#ifdef __cplusplus
}
#endif

#endif
