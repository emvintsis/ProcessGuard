#include "processguard.h"
#include <stdlib.h>
#include <string.h>

static const GUID NetworkProviderGuid = { 0x7dd42a49, 0x5329, 0x4832, {0x8d, 0xf4, 0x3d, 0x97, 0x91, 0x53, 0xa8, 0x88} };

static void PushTelemetry(TELEMETRY_EVENT* event) {
	EnterCriticalSection(&bufferLock);
	rBuffer[head] = *event;
	head = (head + 1) % BUFFER_SIZE;
	if (head == tail) tail = (tail + 1) % BUFFER_SIZE;
	LeaveCriticalSection(&bufferLock);
}

static BOOL GetEventInfo(PEVENT_RECORD pEvent, PTRACE_EVENT_INFO* info, ULONG* size) {
	ULONG bufferSize = 0;
	ULONG status = TdhGetEventInformation(pEvent, 0, NULL, NULL, &bufferSize);
	if (status != ERROR_INSUFFICIENT_BUFFER) return FALSE;
	PTRACE_EVENT_INFO eventInfo = (PTRACE_EVENT_INFO)malloc(bufferSize);
	if (!eventInfo) return FALSE;
	status = TdhGetEventInformation(pEvent, 0, NULL, eventInfo, &bufferSize);
	if (status != ERROR_SUCCESS) {
		free(eventInfo);
		return FALSE;
	}
	*info = eventInfo;
	*size = bufferSize;
	return TRUE;
}

static BOOL FindProperty(PEVENT_RECORD pEvent, const char* propertyName, PROPERTY_DATA_DESCRIPTOR* descriptor, PTRACE_EVENT_INFO info) {
	for (ULONG i = 0; i < info->TopLevelPropertyCount; ++i) {
		LPCWSTR name = (LPCWSTR)((BYTE*)info + info->EventPropertyInfoArray[i].NameOffset);
		char current[256] = { 0 };
		if (!WideCharToMultiByte(CP_UTF8, 0, name, -1, current, sizeof(current), NULL, NULL)) continue;
		if (_stricmp(current, propertyName) == 0) {
			descriptor->PropertyName = (ULONGLONG)name;
			descriptor->ArrayIndex = (ULONG)-1;
			return TRUE;
		}
	}
	return FALSE;
}

BOOL ExtractUInt64Property(PEVENT_RECORD pEvent, const char* propertyName, ULONGLONG* value) {
	if (!value) return FALSE;
	PTRACE_EVENT_INFO info = NULL;
	ULONG size = 0;
	if (!GetEventInfo(pEvent, &info, &size)) return FALSE;
	PROPERTY_DATA_DESCRIPTOR descriptor = { 0 };
	BOOL found = FindProperty(pEvent, propertyName, &descriptor, info);
	if (!found) {
		free(info);
		return FALSE;
	}
	ULONG bufferSize = 0;
	ULONG status = TdhGetPropertySize(pEvent, 0, NULL, 1, &descriptor, &bufferSize);
	if (status != ERROR_SUCCESS || bufferSize == 0 || bufferSize > 16) {
		free(info);
		return FALSE;
	}
	BYTE buffer[16] = { 0 };
	status = TdhGetProperty(pEvent, 0, NULL, 1, &descriptor, bufferSize, buffer);
	if (status != ERROR_SUCCESS) {
		free(info);
		return FALSE;
	}
	if (bufferSize >= sizeof(ULONGLONG)) memcpy(value, buffer, sizeof(ULONGLONG));
	else if (bufferSize >= sizeof(DWORD)) {
		DWORD v = 0;
		memcpy(&v, buffer, sizeof(v));
		*value = v;
	} else if (bufferSize >= sizeof(USHORT)) {
		USHORT v = 0;
		memcpy(&v, buffer, sizeof(v));
		*value = v;
	} else {
		*value = buffer[0];
	}
	free(info);
	return TRUE;
}

BOOL ExtractAddressProperty(PEVENT_RECORD pEvent, const char* propertyName, char* output, size_t outputSize) {
	if (!output || outputSize == 0) return FALSE;
	output[0] = '\0';
	PTRACE_EVENT_INFO info = NULL;
	ULONG size = 0;
	if (!GetEventInfo(pEvent, &info, &size)) return FALSE;
	PROPERTY_DATA_DESCRIPTOR descriptor = { 0 };
	if (!FindProperty(pEvent, propertyName, &descriptor, info)) {
		free(info);
		return FALSE;
	}
	ULONG bufferSize = 0;
	ULONG status = TdhGetPropertySize(pEvent, 0, NULL, 1, &descriptor, &bufferSize);
	if (status != ERROR_SUCCESS || bufferSize == 0 || bufferSize > 256) {
		free(info);
		return FALSE;
	}
	BYTE buffer[256] = { 0 };
	status = TdhGetProperty(pEvent, 0, NULL, 1, &descriptor, bufferSize, buffer);
	if (status != ERROR_SUCCESS) {
		free(info);
		return FALSE;
	}
	ULONG propIndex = 0;
	USHORT inType = TDH_INTYPE_BINARY;
	for (ULONG i = 0; i < info->TopLevelPropertyCount; ++i) {
		LPCWSTR name = (LPCWSTR)((BYTE*)info + info->EventPropertyInfoArray[i].NameOffset);
		char current[256] = { 0 };
		if (WideCharToMultiByte(CP_UTF8, 0, name, -1, current, sizeof(current), NULL, NULL) && _stricmp(current, propertyName) == 0) {
			inType = info->EventPropertyInfoArray[i].nonStructType.InType;
			propIndex = i;
			break;
		}
	}
	if (inType == TDH_INTYPE_UNICODESTRING) {
		WideCharToMultiByte(CP_UTF8, 0, (LPCWCH)buffer, -1, output, (int)outputSize, NULL, NULL);
	} else if (inType == TDH_INTYPE_ANSISTRING) {
		strcpy_s(output, outputSize, (char*)buffer);
	} else if (bufferSize == 4) {
		DWORD v = 0;
		memcpy(&v, buffer, sizeof(v));
		IN_ADDR addr;
		addr.S_un.S_addr = v;
		inet_ntop(AF_INET, &addr, output, (DWORD)outputSize);
	} else if (bufferSize == 16) {
		IN6_ADDR addr6;
		memcpy(&addr6, buffer, sizeof(addr6));
		inet_ntop(AF_INET6, &addr6, output, (DWORD)outputSize);
	} else {
		size_t n = bufferSize < outputSize - 1 ? bufferSize : outputSize - 1;
		for (size_t i = 0; i < n; ++i) sprintf_s(output + i * 2, outputSize - i * 2, "%02X", buffer[i]);
	}
	free(info);
	return output[0] != '\0';
}

static void HandleProcessEvent(PEVENT_RECORD pEvent) {
	if (pEvent->EventHeader.EventDescriptor.Id != 1 && pEvent->EventHeader.EventDescriptor.Id != 5) return;
	DWORD pid = 0;
	if (pEvent->UserDataLength >= sizeof(DWORD)) memcpy(&pid, pEvent->UserData, sizeof(DWORD));
	if (!pid) {
		ULONGLONG value = 0;
		if (ExtractUInt64Property(pEvent, "ProcessID", &value)) pid = (DWORD)value;
		if (!pid && ExtractUInt64Property(pEvent, "PID", &value)) pid = (DWORD)value;
	}
	if (!pid) return;
	TELEMETRY_EVENT tEvent = { 0 };
	tEvent.pid = pid;
	tEvent.source = SOURCE_ETW;
	tEvent.timestamp.dwLowDateTime = pEvent->EventHeader.TimeStamp.LowPart;
	tEvent.timestamp.dwHighDateTime = pEvent->EventHeader.TimeStamp.HighPart;
	if (pEvent->EventHeader.EventDescriptor.Id == 1) {
		ProcessInfo pi = GetProcessInfo(pid);
		tEvent.event = PROCESS_START;
		tEvent.ppid = pi.ppid;
		MultiByteToWideChar(CP_UTF8, 0, pi.cmdLine, -1, tEvent.command_line, 1024);
		MultiByteToWideChar(CP_UTF8, 0, pi.processName, -1, tEvent.image_name, MAX_PATH);
	} else {
		char imagePath[MAX_PATH] = { 0 };
		if (!ExtractAddressProperty(pEvent, "ImageName", imagePath, sizeof(imagePath))) return;
		tEvent.event = IMAGE_LOAD;
		MultiByteToWideChar(CP_UTF8, 0, imagePath, -1, tEvent.image_name, MAX_PATH);
	}
	PushTelemetry(&tEvent);
}

static void HandleNetworkEvent(PEVENT_RECORD pEvent) {
	USHORT id = pEvent->EventHeader.EventDescriptor.Id;
	if (id != 12 && id != 15 && id != 28 && id != 31) return;
	ULONGLONG pidValue = 0;
	if (!ExtractUInt64Property(pEvent, "PID", &pidValue) && !ExtractUInt64Property(pEvent, "ProcessID", &pidValue)) return;
	TELEMETRY_EVENT tEvent = { 0 };
	tEvent.event = (id == 15 || id == 31) ? NETWORK_ACCEPT : NETWORK_CONNECT;
	tEvent.source = SOURCE_ETW;
	tEvent.pid = (DWORD)pidValue;
	tEvent.timestamp.dwLowDateTime = pEvent->EventHeader.TimeStamp.LowPart;
	tEvent.timestamp.dwHighDateTime = pEvent->EventHeader.TimeStamp.HighPart;
	ExtractAddressProperty(pEvent, "saddr", tEvent.source_address, sizeof(tEvent.source_address));
	ExtractAddressProperty(pEvent, "daddr", tEvent.destination_address, sizeof(tEvent.destination_address));
	ULONGLONG port = 0;
	if (ExtractUInt64Property(pEvent, "sport", &port)) tEvent.source_port = (USHORT)port;
	if (ExtractUInt64Property(pEvent, "dport", &port)) tEvent.destination_port = (USHORT)port;
	PushTelemetry(&tEvent);
}

void WINAPI EventRecordCallback(PEVENT_RECORD pEvent) {
	if (IsEqualGUID(&pEvent->EventHeader.ProviderId, &NetworkProviderGuid)) {
		HandleNetworkEvent(pEvent);
		return;
	}
	if (IsEqualGUID(&pEvent->EventHeader.ProviderId, &ProcessProviderGuid)) {
		HandleProcessEvent(pEvent);
	}
}

DWORD WINAPI ConsumeEvents(LPVOID lpParam) {
	CONTROLTRACE_ID* pTraceId = (CONTROLTRACE_ID*)lpParam;
	EVENT_TRACE_LOGFILE trace = { 0 };
	trace.LoggerName = SESSION_NAME;
	trace.ProcessTraceMode = PROCESS_TRACE_MODE_REAL_TIME | PROCESS_TRACE_MODE_EVENT_RECORD;
	trace.EventRecordCallback = EventRecordCallback;
	HANDLE hTrace = OpenTraceW(&trace);
	if (hTrace == INVALID_PROCESSTRACE_HANDLE) {
		printf("[-] ERROR with OpenTraceW : INVALID_PROCESSTRACE_HANDLE\n");
		return 1;
	}
	ULONG result = ProcessTrace(&hTrace, 1, NULL, NULL);
	if (result != ERROR_SUCCESS && InterlockedCompareExchange(&pgRunning, 0, 0)) printf("[-] ERROR with ProcessTrace : %lu\n", result);
	CloseTrace(hTrace);
	return 0;
}
