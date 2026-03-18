#include "processguard.h"

void WINAPI EventRecordCallback(PEVENT_RECORD pEvent) {
	ProcessInfo pi = { 0 };
	pi.pid = *(DWORD*)pEvent->UserData;
	LARGE_INTEGER timestamp = pEvent->EventHeader.TimeStamp;
	FILETIME fileTime;
	fileTime.dwLowDateTime = timestamp.LowPart;
	fileTime.dwHighDateTime = timestamp.HighPart;
	SYSTEMTIME systemTime;
	if (!FileTimeToSystemTime(&fileTime, &systemTime)) {
		printf("[-] ERROR with FileTimeToSystemTime : %lu\n", GetLastError());
		return;
	}
	SYSTEMTIME fullTime;
	if (!SystemTimeToTzSpecificLocalTime(NULL, &systemTime, &fullTime)) {
		printf("[-] ERROR with SystemTimeToTzSpecificLocalTime : %lu\n", GetLastError());
		return;
	}

	if (pEvent->EventHeader.EventDescriptor.Opcode == 1 && pEvent->EventHeader.EventDescriptor.Version == 4) {
		pi = GetProcessInfo(pi.pid);
		printf("\t[%02d:%02d:%02d] Process %s created with PID %d (PPID:%d)\n",
			fullTime.wHour,
			fullTime.wMinute,
			fullTime.wSecond,
			pi.processName,
			pi.pid,
			pi.ppid);
	}
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
