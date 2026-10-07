#ifndef PG_NET_MONITOR_H
#define PG_NET_MONITOR_H

#include <Windows.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef struct {
    DWORD pid;
    DWORD protocol;
    DWORD local_address;
    USHORT local_port;
    DWORD remote_address;
    USHORT remote_port;
    DWORD state;
} PG_NET_EVENT;

typedef void (*PG_NET_CALLBACK)(const PG_NET_EVENT* event);

BOOL PGNetStart(PG_NET_CALLBACK callback, DWORD interval_ms);
void PGNetStop(void);

#ifdef __cplusplus
}
#endif

#endif
