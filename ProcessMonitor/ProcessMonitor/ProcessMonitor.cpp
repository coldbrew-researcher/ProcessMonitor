#include <windows.h>
#include <wintrust.h>
#include <softpub.h>
#include <shlobj.h>
#include <map>
#include <vector>
#include <sstream>
#include <iomanip>
#include <winhttp.h>
#include <string>
#include <sstream>
#include <algorithm>
#include <winhttp.h>
#include <string>
#include <sstream>
#include <algorithm>
#include <codecvt>
#include <locale>

#pragma comment(lib, "winhttp.lib")


#pragma comment(lib, "wintrust.lib")
#pragma comment(lib, "shell32.lib")

#define IOCTL_RECEIVE CTL_CODE(FILE_DEVICE_UNKNOWN, 0x800, METHOD_BUFFERED, FILE_READ_DATA)


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

    std::wstring GetSummary() const {
        if (SuspiciousDlls.empty()) {
            return L""; 
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

        if (!SensitiveRegistryOps.empty()) {
            ss << L"\nSensitive Registry Operations:\n";
            for (const auto& reg : SensitiveRegistryOps) {
                FILETIME ft = { reg.Timestamp.LowPart, (DWORD)reg.Timestamp.HighPart };
                SYSTEMTIME st;
                FileTimeToSystemTime(&ft, &st);
                ss << L"- " << std::wstring(reg.Operation.begin(), reg.Operation.end()).c_str() << L" on " << reg.KeyPath<< L"\n";
            }
        }

        if (!SensitiveFileOps.empty()) {
            ss << L"\nSensitive File Operations:\n";
            for (const auto& file : SensitiveFileOps) {
                FILETIME ft = { file.Timestamp.LowPart, (DWORD)file.Timestamp.HighPart };
                SYSTEMTIME st;
                FileTimeToSystemTime(&ft, &st);
                ss << L"- " << (file.IsWrite ? L"Write" : L"Create") << L" on " << file.FilePath << L"\n";
            }
        }

        return ss.str();
    }
};

std::string json_escape(const std::string& input) {
    std::string output;
    output.reserve(input.size() * 2); 
    for (char c : input) {
        switch (c) {
        case '\\': output += "\\\\"; break;
        case '"':  output += "\\\""; break;
        case '\n': output += "\\n";  break;
        case '\r': output += "\\r";  break;
        case '\t': output += "\\t";  break;
        default:   output += c;      break;
        }
    }
    return output;
}

std::string askLMStudio(const std::string& question) {
    HINTERNET hSession = WinHttpOpen(L"LMStudioClient", WINHTTP_ACCESS_TYPE_DEFAULT_PROXY, WINHTTP_NO_PROXY_NAME, WINHTTP_NO_PROXY_BYPASS, 0);
    if (!hSession) {
        return "";
    }

    HINTERNET hConnect = WinHttpConnect(hSession, L"192.168.106.1", 1234, 0);
    if (!hConnect) {
        WinHttpCloseHandle(hSession);
        return "";
    }

    HINTERNET hRequest = WinHttpOpenRequest(hConnect, L"POST", L"/v1/chat/completions", NULL, WINHTTP_NO_REFERER, WINHTTP_DEFAULT_ACCEPT_TYPES, 0);
    if (!hRequest) {
        WinHttpCloseHandle(hConnect);
        WinHttpCloseHandle(hSession);
        return "";
    }

    std::wstring headers = L"Content-Type: application/json\r\n";
    if (!WinHttpAddRequestHeaders(hRequest, headers.c_str(), (DWORD)headers.length(), WINHTTP_ADDREQ_FLAG_ADD)) {
        WinHttpCloseHandle(hRequest);
        WinHttpCloseHandle(hConnect);
        WinHttpCloseHandle(hSession);
        return "";
    }

    std::stringstream json;
    json << "{\"model\": \"phi-3.1-mini-128k-instruct\", \"messages\": ["
        << "{\"role\": \"system\", \"content\": \"You are a cybersecurity analyst. Analyze the list of file paths and registry keys and summarize all findings in about 20 words. Do not use backslashes, quotes, or line breaks in the output.\"},"
        << "{\"role\": \"user\", \"content\": \"" << json_escape(question) << "\"}"
        << "], \"temperature\": 0.7, \"max_tokens\": -1, \"stream\": false}";

    std::string payload = json.str();

    // Send request
    if (!WinHttpSendRequest(hRequest, WINHTTP_NO_ADDITIONAL_HEADERS, 0, (LPVOID)payload.c_str(), (DWORD)payload.length(), (DWORD)payload.length(), 0)) {
        WinHttpCloseHandle(hRequest);
        WinHttpCloseHandle(hConnect);
        WinHttpCloseHandle(hSession);
        return "";
    }

    if (!WinHttpReceiveResponse(hRequest, NULL)) {
        WinHttpCloseHandle(hRequest);
        WinHttpCloseHandle(hConnect);
        WinHttpCloseHandle(hSession);
        return "";
    }

    DWORD statusCode = 0;
    DWORD statusCodeSize = sizeof(statusCode);
    if (!WinHttpQueryHeaders(hRequest, WINHTTP_QUERY_STATUS_CODE | WINHTTP_QUERY_FLAG_NUMBER, NULL, &statusCode, &statusCodeSize, NULL)) {
        WinHttpCloseHandle(hRequest);
        WinHttpCloseHandle(hConnect);
        WinHttpCloseHandle(hSession);
        return "";
    }
    if (statusCode != 200) {
        return "";
    }

    std::string response;
    DWORD bytesAvailable, bytesRead;
    char buffer[4096];
    while (WinHttpQueryDataAvailable(hRequest, &bytesAvailable) && bytesAvailable > 0) {
        DWORD toRead = min(bytesAvailable, sizeof(buffer) - 1);
        if (!WinHttpReadData(hRequest, buffer, toRead, &bytesRead) || bytesRead == 0) {
            break;
        }
        buffer[bytesRead] = '\0';
        response.append(buffer, bytesRead);
    }

    // Cleanup
    WinHttpCloseHandle(hRequest);
    WinHttpCloseHandle(hConnect);
    WinHttpCloseHandle(hSession);
    return response;
}

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
        return L"";
    }

    if (devicePath[1] == L':' && devicePath[2] == L'\\') {
        return std::wstring(devicePath);
    }

    if (_wcsnicmp(devicePath, L"\\SystemRoot\\", 12) == 0) {
        WCHAR systemDir[MAX_PATH];
        GetWindowsDirectoryW(systemDir, MAX_PATH);
        std::wstring userPath = std::wstring(systemDir) + (devicePath + 11);
        return userPath;
    }

    WCHAR drives[1024] = { 0 };
    DWORD driveLen = GetLogicalDriveStringsW(1024, drives);
    if (driveLen == 0) {
        return L"";
    }

    WCHAR* drive = drives;
    while (*drive) {
        WCHAR deviceName[MAX_PATH] = { 0 };
        if (QueryDosDeviceW(drive, deviceName, MAX_PATH)) {
            size_t devLen = wcslen(deviceName);
            if (_wcsnicmp(devicePath, deviceName, devLen) == 0) {
                std::wstring userPath = std::wstring(drive) + (devicePath + devLen);
                return userPath;
            }
        }
        drive += wcslen(drive) + 1;
    }

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
            return std::wstring(resultPath);
        }
    }

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
        L"\\REGISTRY\\USER\\Software\\Classes",
        L"\\REGISTRY\\USER\\Software\\Environment"
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
    EnterCriticalSection(&gProcessActivityLock);
    switch (Event->Type) {
    case EVENT_IMAGE_LOAD: {
        std::wstring userPath = ConvertDevicePathToUserPath(Event->Data.ImageLoad.ImagePath);
        if (userPath.empty()) {
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
                std::string responsed = askLMStudio(it->second.GetSummary());
                MessageBoxW(nullptr, responsed, L"Virus detect", MB_OK | MB_ICONINFORMATION);
            }
        }
    }
        break;
    case EVENT_REGISTRY:
        if (IsSensitiveRegistryOp(Event->Data.Registry.KeyPath, Event->Data.Registry.Operation)) {
            auto it = gProcessActivities.find(Event->Data.Registry.ProcessId);
            it->second.SensitiveRegistryOps.push_back({
                Event->Data.Registry.KeyPath,
                RegOpToString(Event->Data.Registry.Operation),
                Event->Timestamp
                });
            it->second.LastEventTime = Event->Timestamp;
            
        }
        break;
    case EVENT_PROCESS_CREATE:
        {
            HANDLE hProcess = OpenProcess(SYNCHRONIZE | PROCESS_QUERY_INFORMATION,
                FALSE, (DWORD)(ULONG_PTR)Event->Data.ProcessCreate.ProcessId);
            gProcessActivities.emplace(Event->Data.ProcessCreate.ProcessId,
                ProcessActivity(Event->Data.ProcessCreate.ProcessId, hProcess,
                    Event->Data.ProcessCreate.ImageName));
        }
        break;
    default:
        break;
    }
    LeaveCriticalSection(&gProcessActivityLock);
}

void ProcessFileFilterEvent(PFILE_FILTER_EVENT_DATA Event) {
    EnterCriticalSection(&gProcessActivityLock);
    std::wstring userPath = ConvertDevicePathToUserPath(Event->FileCreate.FilePath);
    if (userPath.empty()) {
    }
    else {
        switch (Event->Type) {
        case EVENT_FILE_CREATE: {
                auto it = gProcessActivities.find(Event->FileCreate.ProcessId);
                if (it != gProcessActivities.end()) {
                    it->second.SensitiveFileOps.push_back({
                        Event->FileCreate.FilePath,
                        AccessMaskToString(Event->FileCreate.DesiredAccess),
                        Event->Timestamp,
                        false
                        });
                    it->second.LastEventTime = Event->Timestamp;
                }          
        }
            break;
        case EVENT_FILE_WRITE: {
                auto it = gProcessActivities.find(Event->FileCreate.ProcessId);
                if (it != gProcessActivities.end()) {
                    it->second.SensitiveFileOps.push_back({
                        Event->FileCreate.FilePath,
                        AccessMaskToString(Event->FileCreate.DesiredAccess),
                        Event->Timestamp,
                        true
                        });
                    it->second.LastEventTime = Event->Timestamp;
                }
        }
            break;
        default:
            break;
        }
    }
    LeaveCriticalSection(&gProcessActivityLock);
}

DWORD WINAPI ProcMonReceiverThread(LPVOID) {
    HANDLE hDevice = CreateFileW(L"\\\\.\\MonitorDriver", GENERIC_READ | GENERIC_WRITE, 0, NULL, OPEN_EXISTING, FILE_FLAG_OVERLAPPED, NULL);
    if (hDevice == INVALID_HANDLE_VALUE) {
        return 1;
    }

    PROC_MON_EVENT_DATA event;
    DWORD bytesReturned;
    OVERLAPPED overlapped = { 0 };
    overlapped.hEvent = CreateEventW(NULL, TRUE, FALSE, NULL);
    if (!overlapped.hEvent) {
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
        return 1;
    }

    FILE_FILTER_EVENT_DATA event;
    DWORD bytesReturned;
    OVERLAPPED overlapped = { 0 };
    overlapped.hEvent = CreateEventW(NULL, TRUE, FALSE, NULL);
    if (!overlapped.hEvent) {
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
                break;
            }
        }
        ResetEvent(overlapped.hEvent);
    }

    CloseHandle(overlapped.hEvent);
    CloseHandle(hDevice);
    return 0;
}

SC_HANDLE hSCManager = nullptr;

bool hlp_StartService(LPCSTR ServiceName) {
    SC_HANDLE hService = nullptr;
    bool success = false;

    if (hSCManager == nullptr) {
        hSCManager = OpenSCManager(nullptr, nullptr, SC_MANAGER_CONNECT);
        if (!hSCManager) {
            return false;
        }
    }

    hService = OpenServiceA(hSCManager, ServiceName, SERVICE_START | SERVICE_QUERY_STATUS);
    if (!hService) {
        CloseServiceHandle(hSCManager);
        return false;
    }

    if (StartServiceA(hService, 0, nullptr)) {
        SERVICE_STATUS_PROCESS status;
        DWORD bytesNeeded;
        if (QueryServiceStatusEx(hService, SC_STATUS_PROCESS_INFO,
            (LPBYTE)&status, sizeof(status), &bytesNeeded)) {
            success = (status.dwCurrentState == SERVICE_RUNNING);
        }
    }

    CloseServiceHandle(hService);
    return success;
}

bool hlp_StopService(LPCSTR ServiceName) {
    SC_HANDLE hService = nullptr;
    bool success = false;

    if (hSCManager == nullptr) {
        hSCManager = OpenSCManager(nullptr, nullptr, SC_MANAGER_CONNECT);
        if (!hSCManager) {
            return false;
        }
    }

    hService = OpenServiceA(hSCManager, ServiceName, SERVICE_STOP | SERVICE_QUERY_STATUS);
    if (!hService) {
        CloseServiceHandle(hSCManager);
        return false;
    }

    SERVICE_STATUS status;
    if (ControlService(hService, SERVICE_CONTROL_STOP, &status)) {
        SERVICE_STATUS_PROCESS statusProcess;
        DWORD bytesNeeded;
        while (QueryServiceStatusEx(hService, SC_STATUS_PROCESS_INFO,
            (LPBYTE)&statusProcess, sizeof(statusProcess), &bytesNeeded)) {
            if (statusProcess.dwCurrentState == SERVICE_STOPPED) {
                success = true;
                break;
            }
            if (statusProcess.dwCurrentState != SERVICE_STOP_PENDING) {
                break;
            }
            Sleep(100);
        }
    }

    CloseServiceHandle(hService);
    return success;
}

int main() {
    if (!hlp_StartService("ProcessMonitor")) {
        if (hSCManager != nullptr) {
            CloseServiceHandle(hSCManager);
        }
        return 1;
    }
    else {
        printf("[*] ProcessMonitor started.\n");
    }

    if (!hlp_StartService("FileMonitor")) {
        hlp_StopService("ProcessMonitor");
        if (hSCManager != nullptr) {
            CloseServiceHandle(hSCManager);
        }
        return 1;
    }
    else {
        printf("[*] FileMonitor started.\n");
    }

    InitializeCriticalSection(&gProcessActivityLock);

    HANDLE terminationThread = CreateThread(NULL, 0, ProcessTerminationChecker, NULL, 0, NULL);
    if (!terminationThread) {
        DeleteCriticalSection(&gProcessActivityLock);
        return 1;
    }

    HANDLE procMonThread = CreateThread(NULL, 0, ProcMonReceiverThread, NULL, 0, NULL);
    if (!procMonThread) {
        gTerminate = TRUE;
        WaitForSingleObject(terminationThread, INFINITE);
        CloseHandle(terminationThread);
        DeleteCriticalSection(&gProcessActivityLock);
        return 1;
    }

    HANDLE fileFilterThread = CreateThread(NULL, 0, FileFilterReceiverThread, NULL, 0, NULL);
    if (!fileFilterThread) {
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

    WaitForSingleObject(procMonThread, INFINITE);
    WaitForSingleObject(fileFilterThread, INFINITE);
    WaitForSingleObject(terminationThread, INFINITE);

    EnterCriticalSection(&gProcessActivityLock);
    Sleep(1000);

    gProcessActivities.clear();
    LeaveCriticalSection(&gProcessActivityLock);

    hlp_StopService("ProcessMonitor");
    hlp_StopService("FileMonitor");
    CloseServiceHandle(hSCManager);

    CloseHandle(procMonThread);
    CloseHandle(fileFilterThread);
    CloseHandle(terminationThread);
    DeleteCriticalSection(&gProcessActivityLock);
    return 0;
}