#include "processguard.h"

int main() {
	CONTROLTRACE_ID tid;
	if (StartETWSession(&tid) != 0) return -1;
	HANDLE hThreadETW = CreateThread(
		NULL, // No security attribute
		0,
		ConsumeEvents, // function
		&tid, // parameter
		0,
		NULL // 
	);
	HANDLE hThreadTransport = CreateThread(
		NULL, // No security attribute
		0,
		FlushToController, // function
		NULL,
		0,
		NULL // 
	);

	if (hThreadETW == NULL || hThreadTransport == NULL) {
		printf("[-] ERROR : Invalid Handle Value for CreateThread\n");
		return -1;
	}

	printf("Press Enter to stop...\n");
	getchar();
	WaitForSingleObject(hThreadETW, 2000);
	WaitForSingleObject(hThreadTransport, 2000);
	CloseHandle(hThreadETW);
	CloseHandle(hThreadTransport);
	if (StopETWSession(tid) != 0) return -1;

	return 0;
}