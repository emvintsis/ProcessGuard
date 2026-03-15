#include "processguard.h"

int StartETWSession(CONTROLTRACE_ID	*traceId) {
	PEVENT_TRACE_PROPERTIES properties = calloc(1, sizeof(EVENT_TRACE_PROPERTIES) + 1024); // allocate clean memory
	properties->Wnode.BufferSize = sizeof(EVENT_TRACE_PROPERTIES) + 1024; //  size of strcuture + 1024 for the buffersize 
	properties->Wnode.Flags = WNODE_FLAG_TRACED_GUID; // This flag indicates to windows the structure will be used fort etw
	properties->LogFileMode = EVENT_TRACE_REAL_TIME_MODE; // I choose real time mode instead of file
	properties->LoggerNameOffset = sizeof(EVENT_TRACE_PROPERTIES); // I give the name addr (jsut after the structure)

	ULONG result = StartTraceW(traceId, SESSION_NAME, properties);
	if (result != ERROR_SUCCESS) {
		printf("[-] ERROR with StartTraceW : %lu\n", result);
		free(properties);
		return -1;
	}
	printf("[+] Session %s started successfully\n", SESSION_NAME);
	free(properties);
	return 0;
}