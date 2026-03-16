#include "processguard.h"

char* ExtractProperty(PEVENT_RECORD pEvent, const char* propertyName) {
    WCHAR wPropertyName[256];
    MultiByteToWideChar( // Convert peropertyname to wchar for compare
        CP_UTF8, // to utf8
        0, // flag
        propertyName, // source string (ascii)
        -1, // source string lenght
        wPropertyName, // destination buffer
        256); // size of buffer

    ULONG bufferSize = 0;

    ULONG status = TdhGetEventInformation(pEvent, 0, NULL, 0, &bufferSize); // i dont put any buffer because i want the size first

    if (status == ERROR_INSUFFICIENT_BUFFER) {
        PTRACE_EVENT_INFO pInfo = malloc(bufferSize);

        status = TdhGetEventInformation(pEvent, 0, NULL, pInfo, &bufferSize);

        if (status == ERROR_SUCCESS) {
            for (int i = 0; i < pInfo->PropertyCount; i += 1) {
                LPWSTR currentPropertyName = (LPWSTR)((BYTE*)pInfo + pInfo->EventPropertyInfoArray[i].NameOffset); // property addr
                wprintf(L"Propriété %d: %s\n", i, currentPropertyName);
                if (wcscmp(currentPropertyName, wPropertyName) == 0) {
                    WCHAR formattedValue[1024]; // will receive the propertyname value (ex : notepad)
                    ULONG fValuebuffersize = sizeof(formattedValue);

                    ULONG formatStatus = TdhFormatProperty(
                        pInfo, // Which provider, which type of data
                        NULL, // for enum
                        sizeof(PVOID), // PVOID for 32 and 64 bytes architecture
                        pInfo->EventPropertyInfoArray[i].nonStructType.InType, // which type of data in
                        pInfo->EventPropertyInfoArray[i].nonStructType.OutType,// which type of data formatted 
                        pInfo->EventPropertyInfoArray[i].length, // direct size of property
                        pEvent->UserDataLength, // total size of all event data
                        pEvent->UserData, // source of data to extract
                        &fValuebuffersize, 
                        formattedValue,
                        NULL
                    );
                    if (formatStatus == ERROR_SUCCESS) {
                        char* result = malloc(1024);

                        WideCharToMultiByte(CP_UTF8, 0, formattedValue, -1, result, 1024, NULL, NULL); // convert unicode to ascii

                        free(pInfo);
                        return result;
                    }
                } 
            }
            free(pInfo);
        }
        else {
            free(pInfo);
            return NULL;
        }
    }
    else {
        return NULL;
    }

    return NULL;
}

char* GetProcessName(DWORD pid) {
    HANDLE hProcess = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, pid);
    if (hProcess) {
        char path[MAX_PATH];
        DWORD size = MAX_PATH;
        if (QueryFullProcessImageNameA(hProcess, 0, path, &size)) {
            CloseHandle(hProcess);
            char* name = strrchr(path, '\\');
            return _strdup(name ? name + 1 : path);
        }
        CloseHandle(hProcess);
    }
    return _strdup("Unknown");
}