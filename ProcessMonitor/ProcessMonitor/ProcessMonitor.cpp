#include <windows.h>
#include <wintrust.h>
#include <softpub.h>
#include <shlobj.h>
#include <string>
#include <map>
#include <vector>
#include <sstream>
#include <iomanip>

#pragma comment(lib, "wintrust.lib")
#pragma comment(lib, "shell32.lib")

#define IOCTL_RECEIVE CTL_CODE(FILE_DEVICE_UNKNOWN, 0x800, METHOD_BUFFERED, FILE_READ_DATA)
#define printf

typedef enum {
    RegNtPreCreateKey = 10,
    RegNtPreSetValueKey = 1,
    RegNtPreDeleteKey = 0,
    RegNtPreDeleteValueKey = 2
} REG_NOTIFY_CLASS;

typedef enum __EVENT_TYPE {
    EVENT_IMAGE_LOAD,
    EVENT_REGISTRY,
    EVENT_PROCESS_CREATE,
    EVENT_FILE_CREATE,
    EVENT_FILE_WRITE
} __EVENT_TYPE;

typedef struct _PROC_MON_EVENT_DATA {
    LIST_ENTRY ListEntry;
    __EVENT_TYPE Type;
    LARGE_INTEGER Timestamp;
    union {
        struct {
            HANDLE ProcessId;
            WCHAR ImagePath[260];
        } ImageLoad;
        struct {
            HANDLE ProcessId;
            WCHAR KeyPath[260];
            ULONG Operation;
        } Registry;
        struct {
            HANDLE ProcessId;
            HANDLE ParentId;
            WCHAR ImageName[260];
        } ProcessCreate;
    } Data;
} PROC_MON_EVENT_DATA, * PPROC_MON_EVENT_DATA;

typedef struct _FILE_FILTER_EVENT_DATA {
    LIST_ENTRY ListEntry;
    __EVENT_TYPE Type;
    LARGE_INTEGER Timestamp;
    struct {
        HANDLE ProcessId;
        WCHAR FilePath[260];
        ACCESS_MASK DesiredAccess;
    } FileCreate;
} FILE_FILTER_EVENT_DATA, * PFILE_FILTER_EVENT_DATA;

// Class to manage process activity
class ProcessActivity {
public:
    HANDLE ProcessId;
    HANDLE ProcessHandle; // For termination detection
    std::wstring ImageName;
    struct DllInfo {
        std::wstring Path;
        bool IsUnsigned;
        bool IsNonStandardPath;
    };
    std::vector<DllInfo> SuspiciousDlls;
    struct RegistryOp {
        std::wstring KeyPath;
        std::string Operation;
        LARGE_INTEGER Timestamp;
    };
    std::vector<RegistryOp> SensitiveRegistryOps;
    struct FileOp {
        std::wstring FilePath;
        std::string Access;
        LARGE_INTEGER Timestamp;
        bool IsWrite;
    };
    std::vector<FileOp> SensitiveFileOps;
    LARGE_INTEGER LastEventTime;

    ProcessActivity(HANDLE pid, HANDLE handle, const std::wstring& imageName)
        : ProcessId(pid), ProcessHandle(handle), ImageName(imageName), LastEventTime({ 0 }) {}

    ~ProcessActivity() {
        if (ProcessHandle) CloseHandle(ProcessHandle);
    }

    // Generate summary for console output
    std::wstring GetSummary() const {
        if (SuspiciousDlls.empty()) {
            return L""; // Nothing to report
        }
        std::wstringstream ss;
        ss << L"Process: " << ImageName << L" (PID: " << ProcessId << L")\n\n";

        if (!SuspiciousDlls.empty()) {
            ss << L"Suspicious DLLs Loaded (Potential Hijacking):\n";
            for (const auto& dll : SuspiciousDlls) {
                ss << L"- " << dll.Path << L" (Unsigned: " << (dll.IsUnsigned ? L"Yes" : L"No")
                    << L", Non-standard: " << (dll.IsNonStandardPath ? L"Yes" : L"No") << L")\n";
            }
        }
        else {
            ss << L"No suspicious DLLs loaded.\n";
        }

        if (!SensitiveRegistryOps.empty()) {
            ss << L"\nSensitive Registry Operations:\n";
            for (const auto& reg : SensitiveRegistryOps) {
                FILETIME ft = { reg.Timestamp.LowPart, (DWORD)reg.Timestamp.HighPart };
                SYSTEMTIME st;
                FileTimeToSystemTime(&ft, &st);
                ss << L"- " << std::wstring(reg.Operation.begin(), reg.Operation.end()).c_str() << L" on " << reg.KeyPath
                    << L" at " << std::setfill(L'0') << std::setw(2) << st.wHour << L":"
                    << std::setw(2) << st.wMinute << L":" << std::setw(2) << st.wSecond
                    << L"." << std::setw(3) << st.wMilliseconds << L"\n";
            }
        }
        else {
            ss << L"\nNo sensitive registry operations.\n";
        }

        if (!SensitiveFileOps.empty()) {
            ss << L"\nSensitive File Operations:\n";
            for (const auto& file : SensitiveFileOps) {
                FILETIME ft = { file.Timestamp.LowPart, (DWORD)file.Timestamp.HighPart };
                SYSTEMTIME st;
                FileTimeToSystemTime(&ft, &st);
                ss << L"- " << (file.IsWrite ? L"Write" : L"Create") << L" on " << file.FilePath
                    << L" (Access: " << std::wstring(file.Access.begin(), file.Access.end()).c_str() << L") at "
                    << std::setfill(L'0') << std::setw(2) << st.wHour << L":"
                    << std::setw(2) << st.wMinute << L":" << std::setw(2) << st.wSecond
                    << L"." << std::setw(3) << st.wMilliseconds << L"\n";
            }
        }
        else {
            ss << L"\nNo sensitive file operations.\n";
        }

        return ss.str();
    }
};

// Global variables
std::map<HANDLE, ProcessActivity> gProcessActivities;
CRITICAL_SECTION gProcessActivityLock;
volatile BOOL gTerminate = FALSE;

// Get Desktop and Startup folder paths
std::wstring GetDesktopPath() {
    WCHAR path[MAX_PATH];
    if (SUCCEEDED(SHGetFolderPathW(NULL, CSIDL_DESKTOP, NULL, 0, path))) {
        return std::wstring(path);
    }
    return L"";
}

std::wstring GetStartupPath() {
    WCHAR path[MAX_PATH];
    if (SUCCEEDED(SHGetFolderPathW(NULL, CSIDL_STARTUP, NULL, 0, path))) {
        return std::wstring(path);
    }
    return L"";
}

const char* RegOpToString(ULONG op) {
    switch (op) {
    case RegNtPreCreateKey: return "CreateKey";
    case RegNtPreSetValueKey: return "SetValueKey";
    case RegNtPreDeleteKey: return "DeleteKey";
    case RegNtPreDeleteValueKey: return "DeleteValueKey";
    default: return "Unknown";
    }
}

const char* AccessMaskToString(ACCESS_MASK access) {
    static char buffer[256];
    buffer[0] = '\0';
    if (access & FILE_READ_DATA) strcat_s(buffer, sizeof(buffer), "Read ");
    if (access & FILE_WRITE_DATA) strcat_s(buffer, sizeof(buffer), "Write ");
    if (access & FILE_APPEND_DATA) strcat_s(buffer, sizeof(buffer), "Append ");
    if (access & FILE_EXECUTE) strcat_s(buffer, sizeof(buffer), "Execute ");
    if (buffer[0] == '\0') strcpy_s(buffer, sizeof(buffer), "Unknown");
    return buffer;
}

void PrintTimestamp(LARGE_INTEGER ts) {
    FILETIME ft;
    ft.dwLowDateTime = ts.LowPart;
    ft.dwHighDateTime = ts.HighPart;
    SYSTEMTIME st;
    FileTimeToSystemTime(&ft, &st);
    printf("[%04d-%02d-%02d %02d:%02d:%02d.%03d] ",
        st.wYear, st.wMonth, st.wDay, st.wHour, st.wMinute, st.wSecond, st.wMilliseconds);
}

// Check if path is a system directory
BOOL IsSystemPath(const WCHAR* path) {
    WCHAR systemDir[MAX_PATH];
    GetSystemDirectoryW(systemDir, MAX_PATH);
    return _wcsnicmp(path, systemDir, wcslen(systemDir)) == 0 ||
        _wcsnicmp(path, L"C:\\Windows\\", 10) == 0;
}

// Check if file is a DLL
BOOL IsDllFile(const WCHAR* path) {
    const WCHAR* ext = wcsrchr(path, L'.');
    return ext && _wcsicmp(ext, L".dll") == 0;
}

std::wstring ConvertDevicePathToUserPath(const WCHAR* devicePath) {
    if (!devicePath || !devicePath[0]) {
        printf("ConvertDevicePathToUserPath: Invalid or empty path\n");
        return L"";
    }

    // Already a Win32 path
    if (devicePath[1] == L':' && devicePath[2] == L'\\') {
        //printf("Already a Win32 path: %ws\n", devicePath);
        return std::wstring(devicePath);
    }

    // Handle \SystemRoot\ paths
    if (_wcsnicmp(devicePath, L"\\SystemRoot\\", 12) == 0) {
        WCHAR systemDir[MAX_PATH];
        GetWindowsDirectoryW(systemDir, MAX_PATH);
        std::wstring userPath = std::wstring(systemDir) + (devicePath + 11);
        //printf("Resolved \\SystemRoot to %ws\n", userPath.c_str());
        return userPath;
    }

    // Try mapping device path to drive letter using QueryDosDeviceW
    WCHAR drives[1024] = { 0 };
    DWORD driveLen = GetLogicalDriveStringsW(1024, drives);
    if (driveLen == 0) {
        printf("GetLogicalDriveStringsW failed: %ld\n", GetLastError());
        return L"";
    }

    WCHAR* drive = drives;
    while (*drive) {
        WCHAR deviceName[MAX_PATH] = { 0 };
        if (QueryDosDeviceW(drive, deviceName, MAX_PATH)) {
            size_t devLen = wcslen(deviceName);
            if (_wcsnicmp(devicePath, deviceName, devLen) == 0) {
                std::wstring userPath = std::wstring(drive) + (devicePath + devLen);
                //printf("Mapped %ws to %ws via %ws\n", devicePath, userPath.c_str(), deviceName);
                return userPath;
            }
        }
        drive += wcslen(drive) + 1;
    }

    // Try CreateFileW and GetFinalPathNameByHandleW if above fails
    HANDLE hFile = CreateFileW(devicePath, GENERIC_READ, FILE_SHARE_READ | FILE_SHARE_WRITE,
        NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
    if (hFile != INVALID_HANDLE_VALUE) {
        WCHAR finalPath[MAX_PATH * 2] = { 0 };
        DWORD len = GetFinalPathNameByHandleW(hFile, finalPath, MAX_PATH * 2, FILE_NAME_NORMALIZED);
        CloseHandle(hFile);
        if (len > 0 && len < MAX_PATH * 2) {
            WCHAR* resultPath = finalPath;
            if (wcsncmp(finalPath, L"\\\\?\\", 4) == 0)
                resultPath += 4;

            //printf("Resolved final path: %ws\n", resultPath);
            return std::wstring(resultPath);
        }
        else {
            printf("GetFinalPathNameByHandleW failed: %ld\n", GetLastError());
        }
    }

    // Fallback to volume GUID resolution (usually unnecessary if above worked)
    WCHAR volumeName[MAX_PATH] = { 0 };
    HANDLE hVol = FindFirstVolumeW(volumeName, MAX_PATH);
    while (hVol != INVALID_HANDLE_VALUE) {
        WCHAR pathNames[MAX_PATH] = { 0 };
        DWORD returnLen = 0;
        if (GetVolumePathNamesForVolumeNameW(volumeName, pathNames, MAX_PATH, &returnLen)) {
            WCHAR deviceName[MAX_PATH] = { 0 };
            WCHAR volumeRoot[MAX_PATH] = { 0 };
            wcscpy_s(volumeRoot, pathNames);
            if (volumeRoot[wcslen(volumeRoot) - 1] == L'\\')
                volumeRoot[wcslen(volumeRoot) - 1] = L'\0';

            if (QueryDosDeviceW(volumeRoot, deviceName, MAX_PATH)) {
                size_t devLen = wcslen(deviceName);
                if (_wcsnicmp(devicePath, deviceName, devLen) == 0) {
                    std::wstring userPath = std::wstring(volumeRoot) + (devicePath + devLen);
                    /*printf("Volume fallback mapping: %ws → %ws via %ws\n",
                        devicePath, userPath.c_str(), deviceName);*/
                    FindClose(hVol);
                    return userPath;
                }
            }
        }
        if (!FindNextVolumeW(hVol, volumeName, MAX_PATH))
            break;
    }
    if (hVol != INVALID_HANDLE_VALUE)
        FindClose(hVol);

    printf("Failed to convert device path: %ws\n", devicePath);
    return L"";
}

BOOL IsDllSigned(const WCHAR* dllPath) {
    if (!dllPath || !dllPath[0]) {
        return FALSE;
    }

    DWORD fileAttr = GetFileAttributesW(dllPath);
    if (fileAttr == INVALID_FILE_ATTRIBUTES) {
        return FALSE;
    }

    WINTRUST_FILE_INFO fileInfo = { sizeof(WINTRUST_FILE_INFO) };
    fileInfo.pcwszFilePath = dllPath;

    WINTRUST_DATA winTrustData = { sizeof(WINTRUST_DATA) };
    winTrustData.dwUIChoice = WTD_UI_NONE;
    winTrustData.fdwRevocationChecks = WTD_REVOKE_NONE;
    winTrustData.dwUnionChoice = WTD_CHOICE_FILE;
    winTrustData.pFile = &fileInfo;
    winTrustData.dwStateAction = WTD_STATEACTION_VERIFY;
    winTrustData.dwProvFlags = WTD_SAFER_FLAG;

    GUID policyGUID = WINTRUST_ACTION_GENERIC_VERIFY_V2;
    LONG status = WinVerifyTrust(NULL, &policyGUID, &winTrustData);

    if (status == ERROR_SUCCESS) {
        return TRUE;
    }
    return FALSE;    
}
// Check if registry operation is sensitive
BOOL IsSensitiveRegistryOp(const WCHAR* keyPath, ULONG operation) {
    static const WCHAR* sensitivePaths[] = {
        L"\\REGISTRY\\MACHINE\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run",
        /*L"\\REGISTRY\\MACHINE\\SYSTEM\\CurrentControlSet\\Services",*/
        L"\\REGISTRY\\USER\\Software\\Classes" // HKCU\Software\Classes
    };
    for (size_t i = 0; i < ARRAYSIZE(sensitivePaths); i++) {
        if (_wcsnicmp(keyPath, sensitivePaths[i], wcslen(sensitivePaths[i])) == 0) {
            return TRUE;
        }
    }
    return operation == RegNtPreSetValueKey || operation == RegNtPreCreateKey;
}

// Check if file operation is sensitive
BOOL IsSensitiveFileOp(const WCHAR* filePath, ACCESS_MASK access) {
    static std::wstring desktopPath = GetDesktopPath();
    static std::wstring startupPath = GetStartupPath();
    //static const WCHAR* sensitivePaths[] = {
    //    L"C:\\Windows\\",
    //    L"C:\\Program Files\\",
    //    L"C:\\Program Files (x86)\\"
    //};

    //// Check static sensitive paths
    //for (size_t i = 0; i < ARRAYSIZE(sensitivePaths); i++) {
    //    if (_wcsnicmp(filePath, sensitivePaths[i], wcslen(sensitivePaths[i])) == 0) {
    //        return TRUE;
    //    }
    //}

    // Check dynamic paths (Desktop and Startup)
    if (!desktopPath.empty() && _wcsnicmp(filePath, desktopPath.c_str(), desktopPath.length()) == 0) {
        return TRUE;
    }
    if (!startupPath.empty() && _wcsnicmp(filePath, startupPath.c_str(), startupPath.length()) == 0) {
        return TRUE;
    }

    // Check for write/append operations
    return (access & (FILE_WRITE_DATA | FILE_APPEND_DATA)) != 0;
}

// Thread to check for terminated processes
DWORD WINAPI ProcessTerminationChecker(LPVOID) {
    while (!gTerminate) {
        EnterCriticalSection(&gProcessActivityLock);
        for (auto it = gProcessActivities.begin(); it != gProcessActivities.end();) {
            HANDLE hProcess = it->second.ProcessHandle;
            if (hProcess && WaitForSingleObject(hProcess, 0) == WAIT_OBJECT_0) {
                // Process terminated, print summary to console
                std::wstring summary = it->second.GetSummary();
                wprintf(L"Process Terminated - Activity Summary:\n%ws\n", summary.c_str());
                it = gProcessActivities.erase(it);
            }
            else {
                ++it;
            }
        }
        LeaveCriticalSection(&gProcessActivityLock);
    }
    return 0;
}

void ProcessProcMonEvent(PPROC_MON_EVENT_DATA Event) {
    //PrintTimestamp(Event->Timestamp);
    EnterCriticalSection(&gProcessActivityLock);
    switch (Event->Type) {
    case EVENT_IMAGE_LOAD: {
        /*printf("Image Load: PID=%p, Path=%ws\n",
            Event->Data.ImageLoad.ProcessId, Event->Data.ImageLoad.ImagePath);*/
        std::wstring userPath = ConvertDevicePathToUserPath(Event->Data.ImageLoad.ImagePath);
        if (userPath.empty()) {
            printf("ProcessProcMonEvent: Failed to convert image path %ws\n", Event->Data.ImageLoad.ImagePath);
        }
        else if (IsDllFile(Event->Data.ImageLoad.ImagePath)) {
            bool isUnsigned = !IsDllSigned(userPath.c_str());
            bool isNonStandard = !IsSystemPath(userPath.c_str());
            // Flag as suspicious only if both unsigned AND non-standard
            if (isUnsigned && isNonStandard) {
                auto it = gProcessActivities.find(Event->Data.ImageLoad.ProcessId);
                if (it != gProcessActivities.end()) {
                    it->second.SuspiciousDlls.push_back({
                        userPath.c_str(),
                        isUnsigned,
                        isNonStandard
                        });
                    it->second.LastEventTime = Event->Timestamp;
                }
            }
        }
    }
        break;
    case EVENT_REGISTRY:
        if (IsSensitiveRegistryOp(Event->Data.Registry.KeyPath, Event->Data.Registry.Operation)) {
            /*auto it = gProcessActivities.find(Event->Data.Registry.ProcessId);
            it->second.SensitiveRegistryOps.push_back({
                Event->Data.Registry.KeyPath,
                RegOpToString(Event->Data.Registry.Operation),
                Event->Timestamp
                });
            it->second.LastEventTime = Event->Timestamp;*/
            
        }
        break;
    case EVENT_PROCESS_CREATE:
        /*printf("Process Create: PID=%p, Parent=%p, Image=%ws\n",
            Event->Data.ProcessCreate.ProcessId, Event->Data.ProcessCreate.ParentId,
            Event->Data.ProcessCreate.ImageName);*/
        {
            HANDLE hProcess = OpenProcess(SYNCHRONIZE | PROCESS_QUERY_INFORMATION,
                FALSE, (DWORD)(ULONG_PTR)Event->Data.ProcessCreate.ProcessId);
            gProcessActivities.emplace(Event->Data.ProcessCreate.ProcessId,
                ProcessActivity(Event->Data.ProcessCreate.ProcessId, hProcess,
                    Event->Data.ProcessCreate.ImageName));
        }
        break;
    default:
        /*printf("Unknown ProcMon event type: %d\n", Event->Type);*/
        break;
    }
    LeaveCriticalSection(&gProcessActivityLock);
}

void ProcessFileFilterEvent(PFILE_FILTER_EVENT_DATA Event) {
    //PrintTimestamp(Event->Timestamp);
    EnterCriticalSection(&gProcessActivityLock);
    printf("File Create: PID=%p, Path=%ws, Access=%s\n",
        Event->FileCreate.ProcessId, Event->FileCreate.FilePath,
        AccessMaskToString(Event->FileCreate.DesiredAccess));
    std::wstring userPath = ConvertDevicePathToUserPath(Event->FileCreate.FilePath);
    if (userPath.empty()) {
        printf("ProcessProcMonEvent: Failed to convert image path %ws\n", Event->FileCreate.FilePath);
    }
    else {
        switch (Event->Type) {
        case EVENT_FILE_CREATE: {
            printf("File Create: PID=%p, Path=%ws, Access=%s\n",
                Event->FileCreate.ProcessId, userPath.c_str(),
                AccessMaskToString(Event->FileCreate.DesiredAccess));
                auto it = gProcessActivities.find(Event->FileCreate.ProcessId);
                if (it != gProcessActivities.end()) {
                   /* it->second.SensitiveFileOps.push_back({
                        Event->FileCreate.FilePath,
                        AccessMaskToString(Event->FileCreate.DesiredAccess),
                        Event->Timestamp,
                        false
                        });
                    it->second.LastEventTime = Event->Timestamp;*/
                }          
        }
            break;
        case EVENT_FILE_WRITE: {
            /*printf("File Write: PID=%p, Path=%ws, Length=%lu bytes\n",
                Event->FileCreate.ProcessId, userPath.c_str(),
                (ULONG)Event->FileCreate.DesiredAccess);
                auto it = gProcessActivities.find(Event->FileCreate.ProcessId);
                if (it != gProcessActivities.end()) {
                    it->second.SensitiveFileOps.push_back({
                        Event->FileCreate.FilePath,
                        AccessMaskToString(Event->FileCreate.DesiredAccess),
                        Event->Timestamp,
                        true
                        });
                    it->second.LastEventTime = Event->Timestamp;
                }*/
        }
            break;
        default:
            /*printf("Unsupported FileFilter event type: %d\n", Event->Type);*/
            break;
        }
    }
    LeaveCriticalSection(&gProcessActivityLock);
}

DWORD WINAPI ProcMonReceiverThread(LPVOID) {
    HANDLE hDevice = CreateFileW(L"\\\\.\\MonitorDriver", GENERIC_READ | GENERIC_WRITE, 0, NULL, OPEN_EXISTING, FILE_FLAG_OVERLAPPED, NULL);
    if (hDevice == INVALID_HANDLE_VALUE) {
        printf("Failed to open ProcMon device: %d\n", GetLastError());
        return 1;
    }

    PROC_MON_EVENT_DATA event;
    DWORD bytesReturned;
    OVERLAPPED overlapped = { 0 };
    overlapped.hEvent = CreateEventW(NULL, TRUE, FALSE, NULL);
    if (!overlapped.hEvent) {
        printf("Failed to create ProcMon event: %d\n", GetLastError());
        CloseHandle(hDevice);
        return 1;
    }

    while (!gTerminate) {
        if (DeviceIoControl(hDevice, IOCTL_RECEIVE, NULL, 0, &event, sizeof(event), &bytesReturned, &overlapped)) {
            if (bytesReturned == sizeof(PROC_MON_EVENT_DATA))
                ProcessProcMonEvent(&event);
        }
        else {
            DWORD error = GetLastError();
            if (error == ERROR_IO_PENDING) {
                WaitForSingleObject(overlapped.hEvent, INFINITE);
                if (GetOverlappedResult(hDevice, &overlapped, &bytesReturned, FALSE) &&
                    bytesReturned == sizeof(PROC_MON_EVENT_DATA)) {
                    ProcessProcMonEvent(&event);
                }
            }
            else if (error != ERROR_NO_MORE_ITEMS) {
                printf("ProcMon DeviceIoControl failed: %ld\n", error);
                break;
            }
        }
        ResetEvent(overlapped.hEvent);
    }

    CloseHandle(overlapped.hEvent);
    CloseHandle(hDevice);
    return 0;
}

DWORD WINAPI FileFilterReceiverThread(LPVOID) {
    HANDLE hDevice = CreateFileW(L"\\\\.\\FileFilterDriver", GENERIC_READ | GENERIC_WRITE, 0, NULL, OPEN_EXISTING, FILE_FLAG_OVERLAPPED, NULL);
    if (hDevice == INVALID_HANDLE_VALUE) {
        printf("Failed to open FileFilter device: %d\n", GetLastError());
        return 1;
    }

    FILE_FILTER_EVENT_DATA event;
    DWORD bytesReturned;
    OVERLAPPED overlapped = { 0 };
    overlapped.hEvent = CreateEventW(NULL, TRUE, FALSE, NULL);
    if (!overlapped.hEvent) {
        printf("Failed to create FileFilter event: %d\n", GetLastError());
        CloseHandle(hDevice);
        return 1;
    }

    while (!gTerminate) {
        if (DeviceIoControl(hDevice, IOCTL_RECEIVE, NULL, 0, &event, sizeof(event), &bytesReturned, &overlapped)) {
            if (bytesReturned == sizeof(FILE_FILTER_EVENT_DATA))
                ProcessFileFilterEvent(&event);
        }
        else {
            DWORD error = GetLastError();
            if (error == ERROR_IO_PENDING) {
                WaitForSingleObject(overlapped.hEvent, INFINITE);
                if (GetOverlappedResult(hDevice, &overlapped, &bytesReturned, FALSE) &&
                    bytesReturned == sizeof(FILE_FILTER_EVENT_DATA)) {
                    ProcessFileFilterEvent(&event);
                }
            }
            else if (error != ERROR_NO_MORE_ITEMS) {
                printf("FileFilter DeviceIoControl failed: %ld\n", error);
                break;
            }
        }
        ResetEvent(overlapped.hEvent);
    }

    CloseHandle(overlapped.hEvent);
    CloseHandle(hDevice);
    return 0;
}

int main() {
    InitializeCriticalSection(&gProcessActivityLock);

    // Start process termination checker thread
    HANDLE terminationThread = CreateThread(NULL, 0, ProcessTerminationChecker, NULL, 0, NULL);
    if (!terminationThread) {
        printf("Failed to create termination checker thread: %d\n", GetLastError());
        DeleteCriticalSection(&gProcessActivityLock);
        return 1;
    }

    HANDLE procMonThread = CreateThread(NULL, 0, ProcMonReceiverThread, NULL, 0, NULL);
    if (!procMonThread) {
        printf("Failed to create ProcMon thread: %d\n", GetLastError());
        gTerminate = TRUE;
        WaitForSingleObject(terminationThread, INFINITE);
        CloseHandle(terminationThread);
        DeleteCriticalSection(&gProcessActivityLock);
        return 1;
    }

    HANDLE fileFilterThread = CreateThread(NULL, 0, FileFilterReceiverThread, NULL, 0, NULL);
    if (!fileFilterThread) {
        printf("Failed to create FileFilter thread: %d\n", GetLastError());
        gTerminate = TRUE;
        WaitForSingleObject(procMonThread, INFINITE);
        WaitForSingleObject(terminationThread, INFINITE);
        CloseHandle(procMonThread);
        CloseHandle(terminationThread);
        DeleteCriticalSection(&gProcessActivityLock);
        return 1;
    }

    printf("Monitoring started. Press Enter to exit...\n");
    getchar();
    gTerminate = TRUE;

    // Wait for threads to finish
    WaitForSingleObject(procMonThread, INFINITE);
    WaitForSingleObject(fileFilterThread, INFINITE);
    WaitForSingleObject(terminationThread, INFINITE);

    // Print summary for all remaining processes
    EnterCriticalSection(&gProcessActivityLock);
    Sleep(1000);
    std::wstring allSummaries;
    for (auto it = gProcessActivities.begin(); it != gProcessActivities.end(); ++it) {
        allSummaries += it->second.GetSummary();
    }
    if (!allSummaries.empty()) {
        MessageBoxW(nullptr, allSummaries.c_str(), L"All Summaries", MB_OK | MB_ICONINFORMATION);

    }
    gProcessActivities.clear();
    LeaveCriticalSection(&gProcessActivityLock);

    CloseHandle(procMonThread);
    CloseHandle(fileFilterThread);
    CloseHandle(terminationThread);
    DeleteCriticalSection(&gProcessActivityLock);
    return 0;
}