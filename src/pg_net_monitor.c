#include "pg_net_monitor.h"
#include <iphlpapi.h>
#include <stdlib.h>

#pragma comment(lib, "iphlpapi.lib")

static HANDLE g_net_thread;
static HANDLE g_net_stop;
static PG_NET_CALLBACK g_net_callback;
static DWORD g_net_interval = 2000;

static void Emit(DWORD pid, DWORD protocol, DWORD la, USHORT lp, DWORD ra, USHORT rp, DWORD state) {
    if (!g_net_callback) return;
    PG_NET_EVENT e = { 0 };
    e.pid = pid;
    e.protocol = protocol;
    e.local_address = la;
    e.local_port = lp;
    e.remote_address = ra;
    e.remote_port = rp;
    e.state = state;
    g_net_callback(&e);
}

static void ScanTcp(void) {
    ULONG size = 0;
    if (GetExtendedTcpTable(NULL, &size, FALSE, AF_INET, TCP_TABLE_OWNER_PID_ALL, 0) != ERROR_INSUFFICIENT_BUFFER) return;
    PMIB_TCPTABLE_OWNER_PID table = (PMIB_TCPTABLE_OWNER_PID)malloc(size);
    if (!table) return;
    if (GetExtendedTcpTable(table, &size, FALSE, AF_INET, TCP_TABLE_OWNER_PID_ALL, 0) == NO_ERROR) {
        for (DWORD i = 0; i < table->dwNumEntries; ++i) {
            MIB_TCPROW_OWNER_PID* r = &table->table[i];
            Emit(r->dwOwningPid, IPPROTO_TCP, r->dwLocalAddr, ntohs((u_short)r->dwLocalPort), r->dwRemoteAddr, ntohs((u_short)r->dwRemotePort), r->dwState);
        }
    }
    free(table);
}

static void ScanUdp(void) {
    ULONG size = 0;
    if (GetExtendedUdpTable(NULL, &size, FALSE, AF_INET, UDP_TABLE_OWNER_PID, 0) != ERROR_INSUFFICIENT_BUFFER) return;
    PMIB_UDPTABLE_OWNER_PID table = (PMIB_UDPTABLE_OWNER_PID)malloc(size);
    if (!table) return;
    if (GetExtendedUdpTable(table, &size, FALSE, AF_INET, UDP_TABLE_OWNER_PID, 0) == NO_ERROR) {
        for (DWORD i = 0; i < table->dwNumEntries; ++i) {
            MIB_UDPROW_OWNER_PID* r = &table->table[i];
            Emit(r->dwOwningPid, IPPROTO_UDP, r->dwLocalAddr, ntohs((u_short)r->dwLocalPort), 0, 0, 0);
        }
    }
    free(table);
}

static DWORD WINAPI NetThread(LPVOID param) {
    UNREFERENCED_PARAMETER(param);
    while (WaitForSingleObject(g_net_stop, g_net_interval) == WAIT_TIMEOUT) {
        ScanTcp();
        ScanUdp();
    }
    return 0;
}

BOOL PGNetStart(PG_NET_CALLBACK callback, DWORD interval_ms) {
    if (g_net_thread) return FALSE;
    g_net_callback = callback;
    g_net_interval = interval_ms ? interval_ms : 2000;
    g_net_stop = CreateEventW(NULL, TRUE, FALSE, NULL);
    if (!g_net_stop) return FALSE;
    g_net_thread = CreateThread(NULL, 0, NetThread, NULL, 0, NULL);
    if (!g_net_thread) {
        CloseHandle(g_net_stop);
        g_net_stop = NULL;
        return FALSE;
    }
    return TRUE;
}

void PGNetStop(void) {
    if (!g_net_thread) return;
    SetEvent(g_net_stop);
    WaitForSingleObject(g_net_thread, 3000);
    CloseHandle(g_net_thread);
    CloseHandle(g_net_stop);
    g_net_thread = NULL;
    g_net_stop = NULL;
    g_net_callback = NULL;
}
