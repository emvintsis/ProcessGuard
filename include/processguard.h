#ifndef PROCESSGUARD_H
#define PROCESSGUARD_H

#include <Windows.h>
#include <evntrace.h>
#include <evntcons.h>
#include <tdh.h>
#include <stdio.h>

#define PG_VERSION L"0.1.0"
#define SESSION_NAME L"PGSession"

// Microsoft-Windows-Kernel-Process
static const GUID ProcessProviderGuid = { 0x22fb2cd6, 0x0e7b, 0x422b, {0xa0, 0xc7, 0x2f, 0xad, 0x1f, 0xd0, 0xe7, 0x16} };

typedef struct {
	DWORD pid;
	DWORD ppid;
	char processName[MAX_PATH];
	char fullPath[MAX_PATH];
	char cmdLine[4096];
}ProcessInfo;


int StartETWSession(CONTROLTRACE_ID* traceId);
DWORD WINAPI ConsumeEvents(LPVOID lpParam);
char* ExtractProperty(PEVENT_RECORD pEvent, const char* propertyName);
ProcessInfo GetProcessInfo(DWORD pid);
int StopETWSession();

#endif