#include "processguard.h"

TELEMETRY_EVENT rBuffer[BUFFER_SIZE]; // buffer for the rotating buff
int head = 0;
int tail = 0;
CRITICAL_SECTION bufferLock;

int StartETWSession(CONTROLTRACE_ID	*traceId) {
	InitializeCriticalSection(&bufferLock); // With this function, two functions cant write and read on the same buffer on the same time
	PEVENT_TRACE_PROPERTIES properties = calloc(1, sizeof(EVENT_TRACE_PROPERTIES) + 1024); // allocate clean memory
	properties->Wnode.BufferSize = sizeof(EVENT_TRACE_PROPERTIES) + 1024; //  size of strcuture + 1024 for the buffersize 
	properties->Wnode.Flags = WNODE_FLAG_TRACED_GUID; // This flag indicates to windows the structure will be used fort etw
	properties->LogFileMode = EVENT_TRACE_REAL_TIME_MODE; // I choose real time mode instead of file
	properties->LoggerNameOffset = sizeof(EVENT_TRACE_PROPERTIES); // I give the name addr (just after the structure)

	ULONG result = StartTraceW(traceId, SESSION_NAME, properties);
	if (result != ERROR_SUCCESS) {
		printf("[-] ERROR with StartTraceW : %lu\n", result);
		free(properties);
		return -1;
	}
	printf("[+] Session PGSession started successfully\n");
	
	result = EnableTraceEx2(
		*traceId,
		&ProcessProviderGuid, // Microsoft-Windows-Kernel-Process GUI
		EVENT_CONTROL_CODE_ENABLE_PROVIDER,
		TRACE_LEVEL_VERBOSE, // VERBOSE = ALL
		0, // no match any keyword
		0, // no match all keyword
		0, // no timeout
		NULL);
	if (result != ERROR_SUCCESS) {
		printf("[-] ERROR with EnableTraceEx2 : %lu\n", result);
		free(properties);
		return -1;
	}
	printf("[*] Provider enabled successfully\n");
	
	free(properties);
	return 0;
}

int StopETWSession(CONTROLTRACE_ID tid) {
	PEVENT_TRACE_PROPERTIES properties = calloc(1, sizeof(EVENT_TRACE_PROPERTIES) + 1024);
	properties->LoggerNameOffset = sizeof(EVENT_TRACE_PROPERTIES);
	properties->Wnode.BufferSize = sizeof(EVENT_TRACE_PROPERTIES) + 1024;
	ULONG result = ControlTraceW(tid, NULL, properties, EVENT_TRACE_CONTROL_STOP);
	if (result != ERROR_SUCCESS) {
		printf("[-] ERROR with ControlTraceW : %lu\n", result);
		free(properties);
		return -1;
	}

	free(properties);
	return 0;
}
