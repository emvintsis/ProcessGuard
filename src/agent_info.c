#include "processguard.h"

HostInfo hi;

BOOL GetHostInfo() {

	PIP_ADAPTER_INFO adapterInfo = NULL;
	ULONG bufferSize = 0;

	DWORD size = MAX_COMPUTERNAME_LENGTH + 1;
	if (!GetComputerNameA(hi.hostname, &size)) {
		printf("[-] ERROR with GetComputerNameA : %lu\n", GetLastError());
		return FALSE;
	}
	size = UNLEN + 1;

	if (!GetUserNameA(hi.username, &size)) {
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

	PIP_ADAPTER_INFO current = adapterInfo;

	while (current != NULL) {
		if (strcmp(current->IpAddressList.IpAddress.String, "0.0.0.0") != 0 &&
			strcmp(current->IpAddressList.IpAddress.String, "127.0.0.1") != 0) {
			strcpy_s(hi.ip, 16, current->IpAddressList.IpAddress.String);
			
			for (int i = 0; i < current->AddressLength; i += 1) {

				// last bit without :
				if (i == current->AddressLength - 1) sprintf_s(hi.mac + (i * 3), 3, "%02X", current->Address[i]);
				else sprintf_s(hi.mac + (i * 3), 4, "%02X:", current->Address[i]);
			}
		}
		if (hi.mac[0] != '\0' && hi.ip[0] != '\0') break;

		current = current->Next;
	}

	free(adapterInfo);
	adapterInfo = NULL;
	return TRUE;
}