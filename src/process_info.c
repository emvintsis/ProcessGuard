#include "processguard.h"

//char* ExtractProperty(PEVENT_RECORD pEvent, const char* propertyName) {
//    WCHAR wPropertyName[256];
//    MultiByteToWideChar( // Convert peropertyname to wchar for compare
//        CP_UTF8, // to utf8
//        0, // flag
//        propertyName, // source string (ascii)
//        -1, // source string lenght
//        wPropertyName, // destination buffer
//        256); // size of buffer
//
//    ULONG bufferSize = 0;
//
//    ULONG status = TdhGetEventInformation(pEvent, 0, NULL, 0, &bufferSize); // i dont put any buffer because i want the size first
//
//    if (status == ERROR_INSUFFICIENT_BUFFER) {
//        PTRACE_EVENT_INFO pInfo = malloc(bufferSize);
//
//        status = TdhGetEventInformation(pEvent, 0, NULL, pInfo, &bufferSize);
//
//        if (status == ERROR_SUCCESS) {
//            for (int i = 0; i < pInfo->PropertyCount; i += 1) {
//                LPWSTR currentPropertyName = (LPWSTR)((BYTE*)pInfo + pInfo->EventPropertyInfoArray[i].NameOffset); // property addr
//                wprintf(L"Propriété %d: %s\n", i, currentPropertyName);
//                if (wcscmp(currentPropertyName, wPropertyName) == 0) {
//                    WCHAR formattedValue[1024]; // will receive the propertyname value (ex : notepad)
//                    ULONG fValuebuffersize = sizeof(formattedValue);
//
//                    ULONG formatStatus = TdhFormatProperty(
//                        pInfo, // Which provider, which type of data
//                        NULL, // for enum
//                        sizeof(PVOID), // PVOID for 32 and 64 bytes architecture
//                        pInfo->EventPropertyInfoArray[i].nonStructType.InType, // which type of data in
//                        pInfo->EventPropertyInfoArray[i].nonStructType.OutType,// which type of data formatted 
//                        pInfo->EventPropertyInfoArray[i].length, // direct size of property
//                        pEvent->UserDataLength, // total size of all event data
//                        pEvent->UserData, // source of data to extract
//                        &fValuebuffersize, 
//                        formattedValue,
//                        NULL
//                    );
//                    if (formatStatus == ERROR_SUCCESS) {
//                        char* result = malloc(1024);
//
//                        WideCharToMultiByte(CP_UTF8, 0, formattedValue, -1, result, 1024, NULL, NULL); // convert unicode to ascii
//
//                        free(pInfo);
//                        return result;
//                    }
//                } 
//            }
//            free(pInfo);
//        }
//        else {
//            free(pInfo);
//            return NULL;
//        }
//    }
//    else {
//        return NULL;
//    }
//
//    return NULL;
//}

typedef struct _UNICODE_STRING {
	USHORT Length;
	USHORT MaximumLength;
	PWSTR  Buffer;
} UNICODE_STRING, * PUNICODE_STRING;


typedef struct _RTL_USER_PROCESS_PARAMETERS {
	BYTE Reserved1[16];
	PVOID Reserved2[10];
	UNICODE_STRING ImagePathName;
	UNICODE_STRING CommandLine;
} RTL_USER_PROCESS_PARAMETERS, * PRTL_USER_PROCESS_PARAMETERS;


typedef struct _PEB {
	BYTE Reserved1[2];
	BYTE BeingDebugged;
	BYTE Reserved2[1];
	PVOID Reserved3[2];
	PVOID Ldr;
	PRTL_USER_PROCESS_PARAMETERS ProcessParameters;
} PEB, * PPEB;

typedef LONG NTSTATUS;
typedef struct _PROCESS_BASIC_INFORMATION {
	PVOID Reserved1;
	PVOID PebBaseAddress; // i replaced ppeb by pvoid because i dont use winternl.h
	PVOID Reserved2[2];
	ULONG_PTR UniqueProcessId;
	ULONG_PTR InheritedFromUniqueProcessId;  // PPID
} PROCESS_BASIC_INFORMATION;

typedef NTSTATUS(WINAPI* NtQueryInformationProcessFunc)(
	HANDLE ProcessHandle,
	UINT ProcessInformationClass,
	PVOID ProcessInformation,
	ULONG ProcessInformationLength,
	PULONG ReturnLength
	);

ProcessInfo GetProcessInfo(DWORD pid) {
	PROCESS_BASIC_INFORMATION pbi;
	ProcessInfo info;
	info.pid = pid;
	PEB peb;
	RTL_USER_PROCESS_PARAMETERS upp;

	// PROCESS_VM_READ for Readprocessmemory and PROCESS_QUERY_LIMITED_INFORMATION for ntqueryinformationprocess
	HANDLE hProcess = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION | PROCESS_VM_READ, FALSE, pid);
	strcpy_s(info.fullPath, sizeof(info.fullPath), "Unknown"); // Default path
	strcpy_s(info.processName, sizeof(info.processName), "Unknown");// default name 
	strcpy_s(info.cmdLine, sizeof(info.cmdLine), "Unknown");
	info.ppid = 0; // default value for ppid
	if (hProcess) {

		char path[MAX_PATH];
		DWORD size = MAX_PATH;
		if (QueryFullProcessImageNameA(hProcess, 0, path, &size)) {
			char* name = strrchr(path, '\\');
			strcpy_s(info.processName, sizeof(info.processName), (name ? name + 1 : path));
			strcpy_s(info.fullPath, sizeof(info.fullPath), path);

			HMODULE ntdll = GetModuleHandleA("ntdll.dll");
			NtQueryInformationProcessFunc NtQueryInfoProcess =
				(NtQueryInformationProcessFunc)GetProcAddress(ntdll, "NtQueryInformationProcess"); // Native function call

			NTSTATUS status = NtQueryInfoProcess(hProcess, 0, &pbi, sizeof(pbi), NULL);

			if (status != 0x00000000) { // STATUS_SUCCESS
				printf("[-] ERROR with NTQueryInformationprocess : %lu\n", status);
			}
			else {
				info.ppid = pbi.InheritedFromUniqueProcessId;
				if (!ReadProcessMemory(hProcess, pbi.PebBaseAddress, &peb, sizeof(PEB), NULL)) { // i give to peb struct the content of the peb
					printf("[-] ERROR with ReadProcessMemory (PEB) : %lu\n", GetLastError());
				}
				else {
					if (!ReadProcessMemory(hProcess, peb.ProcessParameters, &upp, sizeof(RTL_USER_PROCESS_PARAMETERS), NULL)) {
						printf("[-] ERROR with ReadProcessMemory (UPP) : %lu\n", GetLastError());
					}
					else {
						WCHAR* unicodeCmdLine = malloc(upp.CommandLine.Length);
						if (!ReadProcessMemory(hProcess, upp.CommandLine.Buffer, unicodeCmdLine, upp.CommandLine.Length, NULL)) {
							printf("[-] ERROR with ReadProcessMemory (unicodeCmdLine): %lu\n", GetLastError());
							free(unicodeCmdLine);
							unicodeCmdLine = NULL;
						}
						else {
							int written = WideCharToMultiByte(CP_UTF8, 0, unicodeCmdLine,
								min(upp.CommandLine.Length / 2, 8191), // protection against buffer overflow
								info.cmdLine, 8191, NULL, NULL);
							info.cmdLine[written] = '\0';
							free(unicodeCmdLine);
							unicodeCmdLine = NULL;
						}
					}
				}
			}
		}

		CloseHandle(hProcess);

	}
	return info;
}