#include "processguard.h"

void WINAPI EventRecordCallback(PEVENT_RECORD pEvent) {
	printf("\t[*] Event received\n");
}

DWORD WINAPI ConsumeEvents(LPVOID lpParam) { // a conventional WINAPI fuction who returns DWORD takes  LPVOID parameter
	CONTROLTRACE_ID* pTraceId = (CONTROLTRACE_ID*)lpParam;
	EVENT_TRACE_LOGFILE trace = { 0 }; // initalize all members at 0
	trace.LoggerName = SESSION_NAME;
	// real time and modern mode with eventrecordcallback
	trace.ProcessTraceMode = PROCESS_TRACE_MODE_REAL_TIME | PROCESS_TRACE_MODE_EVENT_RECORD;
	trace.EventRecordCallback = EventRecordCallback;

	TRACEHANDLE hTrace = OpenTraceW(&trace);
	if (hTrace == INVALID_PROCESSTRACE_HANDLE) {
		printf("[-] ERROR with OpenTraceW : INVALID_PROCESSTRACE_HANDLE\n");
		return -1;
	}

	ULONG result = ProcessTrace(
		&hTrace, // my handle array
		1, // handle count
		NULL, // Start now
		NULL // Never end
	);
	if (result != ERROR_SUCCESS) {
		printf("[-] ERROR with ProcessTrace : %lu\n", result);
		CloseTrace(hTrace);
		return -1;
	}

	CloseTrace(hTrace);
	return 0;
}
