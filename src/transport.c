#include "processguard.h"

DWORD WINAPI FlushToController(LPVOID lpParam) {
	char imagename[1024];
	char commandLine[8192];
	WCHAR* serverIp = L"192.168.122.1";
	INTERNET_PORT serverPort = 8001;
	HINTERNET hSession = WinHttpOpen(NULL, WINHTTP_ACCESS_TYPE_NO_PROXY, NULL, NULL, NULL); // open session
	if (hSession == NULL) {
		printf("[-] ERROR with WinHttpOpen: %lu\n", GetLastError());
		return;
	}
	HINTERNET hConnect = WinHttpConnect(hSession, serverIp, serverPort, 0); // Etablish connection to server
	if (hConnect == NULL) {
		printf("[-] ERROR with WinHttpConnect : %lu\n", GetLastError());
		return;
	}
	while (TRUE) {
		cJSON* cObject = cJSON_CreateObject(); // like an handle for create a new json object
		cJSON* cArray = cJSON_CreateArray();
		cJSON_AddItemToObject(cObject, "events", cArray);
		int eventsCount = 0;
		Sleep(5000); // the callback send the data every 5 seconds
		EnterCriticalSection(&bufferLock);
		while (tail != head) {
			WideCharToMultiByte(CP_UTF8, 0, rBuffer[tail].command_line, -1, commandLine, 8192, NULL, NULL);
			WideCharToMultiByte(CP_UTF8, 0, rBuffer[tail].image_name, -1, imagename, 1024, NULL, NULL);
			// convert to 64 bits
			ULONGLONG unix_timestamp = (rBuffer[tail].timestamp.dwHighDateTime << 32) | rBuffer[tail].timestamp.dwLowDateTime;
			// convert to unix timestamp (1970 instead of 1601)
			unix_timestamp = ((unix_timestamp - 116444736000000000) / 10000000);

			cJSON* cEventObject = cJSON_CreateObject();
			cJSON_AddNumberToObject(cEventObject, "timestamp", unix_timestamp);
			cJSON_AddNumberToObject(cEventObject, "event", rBuffer[tail].event);
			cJSON_AddNumberToObject(cEventObject, "source", rBuffer[tail].source);
			cJSON_AddNumberToObject(cEventObject, "pid", rBuffer[tail].pid);
			cJSON_AddNumberToObject(cEventObject, "ppid", rBuffer[tail].ppid);
			cJSON_AddStringToObject(cEventObject, "image_name", imagename);
			cJSON_AddStringToObject(cEventObject, "command_line", commandLine);
			cJSON_AddNumberToObject(cEventObject, "flags", rBuffer[tail].flags);
			cJSON_AddItemToArray(cArray, cEventObject);

			tail = (tail + 1) % BUFFER_SIZE; // increase tail 
			eventsCount += 1;
		}
		if (eventsCount != 0) {
			char* content = cJSON_PrintUnformatted(cObject);
			printf("%s\n", content);
			HINTERNET hRequest = WinHttpOpenRequest(hConnect, L"POST", L"/api/v1/telemetry/batch",
				NULL, WINHTTP_NO_REFERER, WINHTTP_DEFAULT_ACCEPT_TYPES, 0);
			if (hRequest == NULL) {
				printf("[-] ERROR with WinHttpOpenRequest: %lu\n", GetLastError());
				goto cleanup;
			}
			WCHAR headers[64];
			swprintf(headers, 64, L"Content-Length: %d", strlen(content));
			if (!WinHttpAddRequestHeaders(hRequest, L"Content-Type: application/json", -1, WINHTTP_ADDREQ_FLAG_ADD)) {
				printf("[-] ERROR with WinHttpAddRequestHeaders (content-type) : %lu\n", GetLastError());
				goto cleanup;
			}
			if (!WinHttpAddRequestHeaders(hRequest,headers, -1, WINHTTP_ADDREQ_FLAG_ADD)) {
				printf("[-] ERROR with WinHttpAddRequestHeaders (content-length) : %lu\n", GetLastError());
				goto cleanup;
			}
			if (!WinHttpSendRequest(hRequest, NULL, 0, content, strlen(content), strlen(content), 0)) {
				printf("[-] ERROR with WinHttpSendRequest : %lu\n", GetLastError());
				goto cleanup;
			}
			if (!WinHttpReceiveResponse(hRequest, NULL)) {
				printf("[-] ERROR with WinHttpReceiveResponse : %lu\n", GetLastError());
				
			}
			cleanup:
				if (content) cJSON_free(content);
				if (hRequest) WinHttpCloseHandle(hRequest);
		}
		LeaveCriticalSection(&bufferLock);
		cJSON_Delete(cObject);
	}
}