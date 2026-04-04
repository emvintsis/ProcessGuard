#include "processguard.h"

int main() {
	setvbuf(stdout, NULL, _IONBF, 0); // disable buffering


	if (!GetHostInfo()) return -1;
	if (!RegisterAgent()) return -1;
	HINTERNET hWebSocket = ConnectWebSocket();
	if (hWebSocket == NULL) return -1;

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
	HANDLE hThreadFlush = CreateThread(
		NULL, // No security attribute
		0,
		FlushToController, // function
		NULL,
		0,
		NULL // 
	);
	HANDLE hThreadWebSocket = CreateThread(
		NULL, // No security attribute
		0,
		ListenWebSocket, // function
		hWebSocket,
		0,
		NULL // 
	);

	if (hThreadETW == NULL || hThreadFlush == NULL || hThreadWebSocket == NULL) {
		printf("[-] ERROR : Invalid Handle Value for CreateThread\n");
		return -1;
	}

	printf("Press Enter to stop...\n");
	getchar();
	WaitForSingleObject(hThreadETW, 2000);
	WaitForSingleObject(hThreadFlush, 2000);
	WaitForSingleObject(hThreadWebSocket, 2000);
	CloseHandle(hThreadETW);
	CloseHandle(hThreadFlush);
	CloseHandle(hThreadWebSocket);
	if (StopETWSession(tid) != 0) return -1;

	return 0;
}