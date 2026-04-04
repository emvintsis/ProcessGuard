#include "processguard.h"

DWORD WINAPI FlushToController(LPVOID lpParam) {
	char imagename[1024];
	char commandLine[8192];
	WCHAR* serverIp = L"192.168.122.1";
	INTERNET_PORT serverPort = 8001;
	HINTERNET hSession = WinHttpOpen(NULL, WINHTTP_ACCESS_TYPE_NO_PROXY, NULL, NULL, 0); // open session
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
		cJSON* cUuidObject = cJSON_CreateObject(); // like an handle for create a new json object
		cJSON* cArray = cJSON_CreateArray();
		cJSON_AddItemToObject(cUuidObject, "events", cArray);
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
			cJSON_AddStringToObject(cEventObject, "agent_id", hi.agent_id);
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
			char* content = cJSON_PrintUnformatted(cUuidObject);
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
		cJSON_Delete(cUuidObject);
	}
}

BOOL RegisterAgent() {
	BOOL success = FALSE;
	char* response = NULL;
	cJSON* root = NULL;
	WCHAR* serverIp = L"192.168.122.1";
	INTERNET_PORT serverPort = 8001;
	HINTERNET hSession = WinHttpOpen(NULL, WINHTTP_ACCESS_TYPE_NO_PROXY, NULL, NULL, 0); // open session
	if (hSession == NULL) {
		printf("[-] ERROR with WinHttpOpen (Register): %lu\n", GetLastError());
		return FALSE;
	}
	HINTERNET hConnect = WinHttpConnect(hSession, serverIp, serverPort, 0); // Etablish connection to server
	if (hConnect == NULL) {
		printf("[-] ERROR with WinHttpConnect (Register): %lu\n", GetLastError());
		return FALSE;
	}
	cJSON* cUuidObject = cJSON_CreateObject(); // like an handle for create a new json object

	cJSON_AddStringToObject(cUuidObject, "hostname", hi.hostname);
	cJSON_AddStringToObject(cUuidObject, "ip", hi.ip);
	cJSON_AddStringToObject(cUuidObject, "mac", hi.mac);
	cJSON_AddStringToObject(cUuidObject, "username", hi.username);


	char* content = cJSON_PrintUnformatted(cUuidObject);
	printf("%s\n", content);

	HINTERNET hRequest = WinHttpOpenRequest(hConnect, L"POST", L"/api/v1/agents/register",
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
	if (!WinHttpAddRequestHeaders(hRequest, headers, -1, WINHTTP_ADDREQ_FLAG_ADD)) {
		printf("[-] ERROR with WinHttpAddRequestHeaders (content-length) : %lu\n", GetLastError());
		goto cleanup;
	}
	if (!WinHttpSendRequest(hRequest, NULL, 0, content, strlen(content), strlen(content), 0)) {
		printf("[-] ERROR with WinHttpSendRequest : %lu\n", GetLastError());
		goto cleanup;
	}
	if (!WinHttpReceiveResponse(hRequest, NULL)) {
		printf("[-] ERROR with WinHttpReceiveResponse : %lu\n", GetLastError());
		goto cleanup;
	}
	DWORD bufSize = 0;
	if (!WinHttpQueryDataAvailable(hRequest, &bufSize)) {
		printf("[-] ERROR with HttpQueryDataAvailable : %lu\n", GetLastError());
		goto cleanup;
	}
	response = malloc(bufSize + 1);

	if (!WinHttpReadData(hRequest, response, bufSize, NULL)) {
		printf("[-] ERROR with WinHttpReadData : %lu\n", GetLastError());
		goto cleanup;
	}
	response[bufSize] = '\0';
	root = cJSON_Parse(response);

	cJSON* objectValue = cJSON_GetObjectItem(root, "agent_id");
	strcpy_s(hi.agent_id, sizeof(hi.agent_id), objectValue->valuestring);
	printf(hi.agent_id);
	success = TRUE;

	cleanup:
		if (content) cJSON_free(content);
		if (hRequest) WinHttpCloseHandle(hRequest);
		if (response) free(response);
		if (cUuidObject) cJSON_Delete(cUuidObject);
		if (root) cJSON_Delete(root);
	return success;
}

HINTERNET ConnectWebSocket() {
	WCHAR* serverIp = L"192.168.122.1";
	INTERNET_PORT serverPort = 8001;
	WCHAR endpointPath[64];
	// un wchar occupe 2 octets donc endpointpath fait 128 octets , en divisant j'obtiens le bon nombre de caracteres
	swprintf_s(endpointPath, sizeof(endpointPath) / sizeof(WCHAR),L"/ws/agent/%S", hi.agent_id);
	HINTERNET hSession = WinHttpOpen(L"Websocket", WINHTTP_ACCESS_TYPE_NO_PROXY, NULL, NULL, 0); // open session
	if (hSession == NULL) {
		printf("[-] ERROR with WinHttpOpen: %lu\n", GetLastError());
		return NULL;
	}
	HINTERNET hConnect = WinHttpConnect(hSession, serverIp, serverPort, 0); // Etablish connection to server
	if (hConnect == NULL) {
		printf("[-] ERROR with WinHttpConnect : %lu\n", GetLastError());
		return NULL;
	}
	// Le protocole Websocket demarre toujours par un GET
	HINTERNET hRequestHandle = WinHttpOpenRequest(hConnect, L"GET", endpointPath, NULL, NULL, NULL, 0);
	if (!WinHttpSetOption(hRequestHandle, WINHTTP_OPTION_UPGRADE_TO_WEB_SOCKET, NULL, 0)) {
		printf("[-] ERROR with WinHttpOpenRequest : %lu\n", GetLastError());
		return NULL;
	}

	// je fais seulement un handshake
	if (!WinHttpSendRequest(hRequestHandle, NULL, 0, NULL, 0, 0, NULL)) {
		printf("[-] ERROR with WinHttpSendRequest : %lu\n", GetLastError());
		return NULL;
	}
	if (!WinHttpReceiveResponse(hRequestHandle, NULL)) {
		printf("[-] ERROR with WinHttpReceiveResponse : %lu\n", GetLastError());
		return NULL;
	}
	HINTERNET hWebSocketHandle = WinHttpWebSocketCompleteUpgrade(hRequestHandle, NULL);
	if (hWebSocketHandle == NULL) {
		printf("[-] ERROR with WinHttpWebSocketCompleteUpgrade : %lu\n", GetLastError());
		return NULL;
	}
	return hWebSocketHandle;
}