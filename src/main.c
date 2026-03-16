#include "processguard.h"

int main() {
	CONTROLTRACE_ID tid;
	if (StartETWSession(&tid) != 0) return -1;
	HANDLE hThread = CreateThread(
		NULL, // No security attribute
		0,
		ConsumeEvents, // function
		&tid, // parameter
		0,
		NULL // 
	);

	if (hThread == NULL) {
		printf("[-] ERROR : Invalid Handle Value for CreateThread\n");
		return -1;
	}

	printf("Press Enter to stop...\n");
	getchar();
	WaitForSingleObject(hThread, 5000);
	CloseHandle(hThread);
	if (StopETWSession(tid) != 0) return -1;

	return 0;
}