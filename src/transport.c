#include "processguard.h"

DWORD WINAPI FlushToController(LPVOID lpParam) {
	while (TRUE) {
		Sleep(5000); // the callback send the data every 5 seconds
		EnterCriticalSection(&bufferLock);
		while (tail != head) {
			wprintf(L"%s\n", rBuffer[tail].image_name);
			tail = (tail + 1) % BUFFER_SIZE; // increase tail 
		}
		LeaveCriticalSection(&bufferLock);
	}
}