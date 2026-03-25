#include "processguard.h"

HostInfo hostInfo;

BOOL GetHostInfo() {

	PIP_ADAPTER_INFO adapterInfo;
	ULONG bufferSize = 0;

	DWORD size = MAX_COMPUTERNAME_LENGTH + 1;
	if (!GetComputerNameA(hostInfo.hostname, &size)) {
		printf("[-] ERROR with GetComputerNameA : %lu\n", GetLastError());
		return FALSE;
	}
	size = UNLEN + 1;

	if (!GetUserNameA(hostInfo.username, &size)) {
		printf("[-] ERROR with GetUserNameA : %lu\n", GetLastError());
		return FALSE;
	}

	ULONG status = GetAdaptersInfo(adapterInfo, &bufferSize);

	if (status != ERROR_BUFFER_OVERFLOW) {
		printf("[-] ERROR with GetAdaptersInfo (1) : %lu\n", GetLastError());
		return FALSE;
	}
	adapterInfo = malloc(bufferSize);

	status = GetAdaptersInfo(adapterInfo, &bufferSize);
	if (status != ERROR_SUCCESS) {
		printf("[-] ERROR with GetAdaptersInfo (2) : %lu\n", GetLastError());
		free(adapterInfo);
		adapterInfo = NULL;
		return FALSE;
	}

	free(adapterInfo);
	adapterInfo = NULL;
	return TRUE;
}