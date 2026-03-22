#ifndef PROCESSGUARD_H
#define PROCESSGUARD_H

#include <Windows.h>
#include <evntrace.h>
#include <evntcons.h>
#include <tdh.h>
#include <stdio.h>
#include <winhttp.h>
#include "cJSON.h"

#define PG_VERSION L"0.1.0"
#define SESSION_NAME L"PGSession"
#define BUFFER_SIZE 100

// Microsoft-Windows-Kernel-Process
static const GUID ProcessProviderGuid = { 0x22fb2cd6, 0x0e7b, 0x422b, {0xa0, 0xc7, 0x2f, 0xad, 0x1f, 0xd0, 0xe7, 0x16} };

typedef struct {
	DWORD pid;
	DWORD ppid;
	char processName[MAX_PATH];
	char fullPath[MAX_PATH];
	char cmdLine[8192];
}ProcessInfo;

typedef enum {  PROCESS_START, PROCESS_STOP, THREAD_CREATE, IMAGE_LOAD, DRIVER_PROCESS_BLOCKED } EVENT_TYPE;
typedef enum { SOURCE_ETW, SOURCE_DRIVER, SOURCE_SCANNER } SOURCE_TYPE;

typedef struct {
	EVENT_TYPE event;
	SOURCE_TYPE source; 
	DWORD pid;
	DWORD ppid;
	WCHAR image_name[MAX_PATH];
	WCHAR command_line[1024];
	FILETIME timestamp;
	DWORD flags; // Metadata flags
} TELEMETRY_EVENT;

extern TELEMETRY_EVENT rBuffer[BUFFER_SIZE]; // buffer for the rotating buffer
extern int head;
extern int tail;
extern CRITICAL_SECTION bufferLock;


int StartETWSession(CONTROLTRACE_ID* traceId);
DWORD WINAPI ConsumeEvents(LPVOID lpParam);
char* ExtractProperty(PEVENT_RECORD pEvent, const char* propertyName);
ProcessInfo GetProcessInfo(DWORD pid);
DWORD WINAPI FlushToController(LPVOID lpParam);
int StopETWSession();

#endif