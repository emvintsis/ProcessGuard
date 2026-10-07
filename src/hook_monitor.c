#include "processguard.h"
#include <tlhelp32.h>
#include <psapi.h>

volatile LONG pgRunning = 1;

static const char* CriticalFunctions[] = {
	"NtOpenProcess",
	"NtCreateFile",
	"NtProtectVirtualMemory",
	"CreateProcessW",
	"WinHttpSendRequest"
};

static BOOL IsSuspiciousPrologue(const BYTE* code, SIZE_T size) {
	if (!code || size < 6) return FALSE;
	if (code[0] == 0xE9 || code[0] == 0xE8) return TRUE;
	if (code[0] == 0xFF && (code[1] == 0x25 || code[1] == 0x15)) return TRUE;
	if (code[0] == 0x48 && code[1] == 0xB8 && code[10] == 0xFF && code[11] == 0xE0) return TRUE;
	return FALSE;
}

static BOOL ReportHook(DWORD pid, const char* module, const char* functionName) {
	TELEMETRY_EVENT event = { 0 };
	event.event = HOOK_DETECTED;
	event.source = SOURCE_SCANNER;
	event.pid = pid;
	strncpy_s(event.hook_module, sizeof(event.hook_module), module, _TRUNCATE);
	strncpy_s(event.hook_function, sizeof(event.hook_function), functionName, _TRUNCATE);
	GetSystemTimeAsFileTime(&event.timestamp);
	EnterCriticalSection(&bufferLock);
	rBuffer[head] = event;
	head = (head + 1) % BUFFER_SIZE;
	if (head == tail) tail = (tail + 1) % BUFFER_SIZE;
	LeaveCriticalSection(&bufferLock);
	return TRUE;
}

static void ScanProcess(DWORD pid) {
	HANDLE process = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, FALSE, pid);
	if (!process) return;
	HMODULE modules[1024];
	DWORD needed = 0;
	if (!EnumProcessModules(process, modules, sizeof(modules), &needed)) {
		CloseHandle(process);
		return;
	}
	DWORD count = needed / sizeof(HMODULE);
	HMODULE localNtdll = GetModuleHandleW(L"ntdll.dll");
	HMODULE localKernel32 = GetModuleHandleW(L"kernel32.dll");
	HMODULE localWinhttp = LoadLibraryW(L"winhttp.dll");
	for (DWORD i = 0; i < count; ++i) {
		char moduleName[MAX_PATH] = { 0 };
		if (!GetModuleBaseNameA(process, modules[i], moduleName, sizeof(moduleName))) continue;
		HMODULE localModule = NULL;
		if (_stricmp(moduleName, "ntdll.dll") == 0) localModule = localNtdll;
		else if (_stricmp(moduleName, "kernel32.dll") == 0) localModule = localKernel32;
		else if (_stricmp(moduleName, "winhttp.dll") == 0) localModule = localWinhttp;
		if (!localModule) continue;
		for (size_t f = 0; f < sizeof(CriticalFunctions) / sizeof(CriticalFunctions[0]); ++f) {
			FARPROC localAddress = GetProcAddress(localModule, CriticalFunctions[f]);
			if (!localAddress) continue;
			SIZE_T offset = (BYTE*)localAddress - (BYTE*)localModule;
			BYTE* remoteAddress = (BYTE*)modules[i] + offset;
			BYTE remoteCode[16] = { 0 };
			SIZE_T read = 0;
			if (!ReadProcessMemory(process, remoteAddress, remoteCode, sizeof(remoteCode), &read)) continue;
			if (IsSuspiciousPrologue(remoteCode, read) && memcmp(remoteCode, (const void*)localAddress, 12) != 0) {
				ReportHook(pid, moduleName, CriticalFunctions[f]);
			}
		}
	}
	if (localWinhttp) FreeLibrary(localWinhttp);
	CloseHandle(process);
}

DWORD WINAPI MonitorHooks(LPVOID lpParam) {
	UNREFERENCED_PARAMETER(lpParam);
	while (InterlockedCompareExchange(&pgRunning, 0, 0)) {
		HANDLE snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
		if (snapshot != INVALID_HANDLE_VALUE) {
			PROCESSENTRY32W entry = { 0 };
			entry.dwSize = sizeof(entry);
			if (Process32FirstW(snapshot, &entry)) {
				do {
					if (entry.th32ProcessID > 4) ScanProcess(entry.th32ProcessID);
				} while (Process32NextW(snapshot, &entry) && InterlockedCompareExchange(&pgRunning, 0, 0));
			}
			CloseHandle(snapshot);
		}
		for (int i = 0; i < 10 && InterlockedCompareExchange(&pgRunning, 0, 0); ++i) Sleep(500);
	}
	return 0;
}
