#include <windows.h>
#include <detours.h>
#include <psapi.h>
#include <stdio.h>
#include <intrin.h>

// Named pipe handle (optional)
static HANDLE hPipe = INVALID_HANDLE_VALUE;

DWORD pid = 0;

typedef struct _CLIENT_ID {
    HANDLE UniqueProcess;
    HANDLE UniqueThread;
} CLIENT_ID, * PCLIENT_ID;

// Function pointers to original APIs
static LPVOID(WINAPI* OriginalVirtualAlloc)(LPVOID, SIZE_T, DWORD, DWORD) = VirtualAlloc;
static BOOL(WINAPI* OriginalVirtualProtect)(LPVOID, SIZE_T, DWORD, PDWORD) = VirtualProtect;
static LPVOID(WINAPI* OriginalVirtualAllocEx)(HANDLE, LPVOID, SIZE_T, DWORD, DWORD) = VirtualAllocEx;
static BOOL(WINAPI* OriginalVirtualProtectEx)(HANDLE, LPVOID, SIZE_T, DWORD, PDWORD) = VirtualProtectEx;
static BOOL(WINAPI* OriginalWriteProcessMemory)(HANDLE, LPVOID, LPCVOID, SIZE_T, SIZE_T*) = WriteProcessMemory;
static BOOL(WINAPI* OriginalReadProcessMemory)(HANDLE, LPCVOID, LPVOID, SIZE_T, SIZE_T*) = ReadProcessMemory;
static HANDLE(WINAPI* OriginalCreateRemoteThread)(HANDLE, LPSECURITY_ATTRIBUTES, SIZE_T, LPTHREAD_START_ROUTINE, LPVOID, DWORD, LPDWORD) = CreateRemoteThread;
static NTSTATUS(NTAPI* OriginalNtCreateThreadEx)(PHANDLE, ACCESS_MASK, PVOID, HANDLE, PVOID, PVOID, ULONG, ULONG, ULONG, ULONG, PVOID) = nullptr;
static DWORD(WINAPI* OriginalQueueUserAPC)(PAPCFUNC, HANDLE, ULONG_PTR) = QueueUserAPC;
static BOOL(WINAPI* OriginalSetThreadContext)(HANDLE, const CONTEXT*) = SetThreadContext;
static DWORD(WINAPI* OriginalSuspendThread)(HANDLE) = SuspendThread;
static DWORD(WINAPI* OriginalResumeThread)(HANDLE) = ResumeThread;
static HANDLE(WINAPI* OriginalCreateThread)(LPSECURITY_ATTRIBUTES, SIZE_T, LPTHREAD_START_ROUTINE, LPVOID, DWORD, LPDWORD) = CreateThread;
static HMODULE(WINAPI* OriginalLoadLibraryA)(LPCSTR) = LoadLibraryA;
static HMODULE(WINAPI* OriginalLoadLibraryW)(LPCWSTR) = LoadLibraryW;
static HMODULE(WINAPI* OriginalLoadLibraryExW)(LPCWSTR, HANDLE, DWORD) = LoadLibraryExW;
static FARPROC(WINAPI* OriginalGetProcAddress)(HMODULE, LPCSTR) = GetProcAddress;
static BOOL(WINAPI* OriginalEnumProcesses)(DWORD*, DWORD, DWORD*) = EnumProcesses;
static BOOL(WINAPI* OriginalEnumProcessModules)(HANDLE, HMODULE*, DWORD, LPDWORD) = EnumProcessModules;
static BOOL(WINAPI* OriginalEnumProcessModulesEx)(HANDLE, HMODULE*, DWORD, LPDWORD, DWORD) = EnumProcessModulesEx;
static HANDLE(WINAPI* OriginalOpenProcess)(DWORD, BOOL, DWORD) = OpenProcess;
static HANDLE(WINAPI* OriginalCreateFileMappingW)(HANDLE, LPSECURITY_ATTRIBUTES, DWORD, DWORD, DWORD, LPCWSTR) = CreateFileMappingW;
static LPVOID(WINAPI* OriginalMapViewOfFile)(HANDLE, DWORD, DWORD, DWORD, SIZE_T) = MapViewOfFile;
static NTSTATUS(NTAPI* OriginalNtUnmapViewOfSection)(HANDLE, PVOID) = nullptr;
static NTSTATUS(NTAPI* OriginalRtlCreateUserThread)(HANDLE, PSECURITY_DESCRIPTOR, BOOLEAN, ULONG, SIZE_T, SIZE_T, PVOID, PVOID, PHANDLE, PCLIENT_ID) = nullptr;
static HINSTANCE(WINAPI* OriginalShellExecuteW)(HWND, LPCWSTR, LPCWSTR, LPCWSTR, LPCWSTR, INT) = ShellExecuteW;
static UINT(WINAPI* OriginalWinExec)(LPCSTR, UINT) = WinExec;
static BOOL(WINAPI* OriginalCreateProcessW)(LPCWSTR, LPWSTR, LPSECURITY_ATTRIBUTES, LPSECURITY_ATTRIBUTES, BOOL, DWORD, LPVOID, LPCWSTR, LPSTARTUPINFOW, LPPROCESS_INFORMATION) = CreateProcessW;
static BOOL(WINAPI* OriginalCreateProcessWithTokenW)(HANDLE, DWORD, LPCWSTR, LPWSTR, DWORD, LPVOID, LPCWSTR, LPSTARTUPINFOW, LPPROCESS_INFORMATION) = CreateProcessWithTokenW;
static HHOOK(WINAPI* OriginalSetWindowsHookExW)(int, HOOKPROC, HINSTANCE, DWORD) = SetWindowsHookExW;
static ATOM(WINAPI* OriginalGlobalAddAtomW)(LPCWSTR) = GlobalAddAtomW;
static UINT(WINAPI* OriginalGlobalGetAtomNameW)(ATOM, LPWSTR, int) = GlobalGetAtomNameW;

enum ApiCall : DWORD {
    __VirtualAlloc = 1,
    __VirtualProtect = 2,
    __VirtualAllocEx = 3,
    __VirtualProtectEx = 4,
    __WriteProcessMemory = 5,
    __ReadProcessMemory = 6,
    __CreateRemoteThread = 7,
    __NtCreateThreadEx = 8,
    __QueueUserAPC = 9,
    __SetThreadContext = 10,
    __SuspendThread = 11,
    __ResumeThread = 12,
    __CreateThread = 13,
    __LoadLibraryA = 14,
    __LoadLibraryW = 15,
    __LoadLibraryExW = 16,
    __GetProcAddress = 17,
    __EnumProcesses = 18,
    __EnumProcessModules = 19,
    __EnumProcessModulesEx = 20,
    __OpenProcess = 21,
    __CreateFileMappingW = 22,
    __MapViewOfFile = 23,
    __NtUnmapViewOfSection = 24,
    __RtlCreateUserThread = 25,
    __ShellExecuteW = 26,
    __WinExec = 27,
    __CreateProcessW = 28,
    __CreateProcessWithTokenW = 29,
    __SetWindowsHookExW = 30,
    __GlobalAddAtomW = 31,
    __GlobalGetAtomNameW = 32

};

// Named pipe initialization (optional)
void InitNamedPipe()
{
    hPipe = CreateFileW(L"\\\\.\\pipe\\_IMonitor_", GENERIC_WRITE, 0, NULL, OPEN_EXISTING | CREATE_NEW, 0, NULL);
    if (hPipe == INVALID_HANDLE_VALUE) {
        char buffer[256];
        snprintf(buffer, sizeof(buffer), "[ERROR] Failed to connect to named pipe: %lu\n", GetLastError());
        OutputDebugStringA(buffer);
    }
}

// Send message to named pipe (optional)
void SendToPipe(const char* message)
{
    if (hPipe != INVALID_HANDLE_VALUE) {
        DWORD bytesWritten;
        WriteFile(hPipe, message, strlen(message), &bytesWritten, NULL);
    }
}

// Detour functions (existing ones unchanged for brevity)
LPVOID WINAPI DetourVirtualAlloc(LPVOID lpAddress, SIZE_T dwSize, DWORD flAllocationType, DWORD flProtect)
{
    char buffer[8];
    snprintf(buffer, sizeof(buffer), "%u%u", pid, ApiCall::__VirtualAlloc);
    OutputDebugStringA(buffer);
    SendToPipe(buffer);
    return OriginalVirtualAlloc(lpAddress, dwSize, flAllocationType, flProtect);
}

BOOL WINAPI DetourVirtualProtect(LPVOID lpAddress, SIZE_T dwSize, DWORD flNewProtect, PDWORD lpflOldProtect)
{
    MEMORY_BASIC_INFORMATION mbi = {};
    VirtualQuery(lpAddress, &mbi, sizeof(mbi));

    bool isExecutable = (flNewProtect == 0x10) || (flNewProtect == 0x20);
    //bool isSuspiciousSize = dwSize >= 0x1000 && dwSize <= 0x100000;
    bool isPrivateRW = (mbi.Type == MEM_PRIVATE) &&
        (mbi.Protect == PAGE_READWRITE || mbi.Protect == PAGE_WRITECOPY);

    void* returnAddr = _ReturnAddress();
    HMODULE hCaller = NULL;
    GetModuleHandleEx(GET_MODULE_HANDLE_EX_FLAG_FROM_ADDRESS, (LPCTSTR)returnAddr, &hCaller);

    char modulePath[MAX_PATH] = { 0 };
    GetModuleFileNameA(hCaller, modulePath, MAX_PATH);
    bool isSuspiciousCaller = strstr(modulePath, "System32") == NULL;

    if (isExecutable /*&& isSuspiciousSize*/ && isPrivateRW && isSuspiciousCaller)
    {
        char buffer[8];
        snprintf(buffer, sizeof(buffer), "%u%u", pid, ApiCall::__VirtualProtect);
        OutputDebugStringA(buffer);
        SendToPipe(buffer);
    }

    return OriginalVirtualProtect(lpAddress, dwSize, flNewProtect, lpflOldProtect);
}

LPVOID WINAPI DetourVirtualAllocEx(HANDLE hProcess, LPVOID lpAddress, SIZE_T dwSize, DWORD flAllocationType, DWORD flProtect)
{
    if (PAGE_EXECUTE == (flProtect & 0xF0)) {
        char buffer[8];
        snprintf(buffer, sizeof(buffer), "%u%u", pid, ApiCall::__VirtualAllocEx);
        OutputDebugStringA(buffer);
        SendToPipe(buffer);
    }
    return OriginalVirtualAllocEx(hProcess, lpAddress, dwSize, flAllocationType, flProtect);
}

BOOL WINAPI DetourVirtualProtectEx(HANDLE hProcess, LPVOID lpAddress, SIZE_T dwSize, DWORD flNewProtect, PDWORD lpflOldProtect)
{
    char buffer[8];
    snprintf(buffer, sizeof(buffer), "%u%u", pid, ApiCall::__VirtualProtectEx);
    OutputDebugStringA(buffer);
    SendToPipe(buffer);
    return OriginalVirtualProtectEx(hProcess, lpAddress, dwSize, flNewProtect, lpflOldProtect);
}

BOOL WINAPI DetourWriteProcessMemory(HANDLE hProcess, LPVOID lpBaseAddress, LPCVOID lpBuffer, SIZE_T nSize, SIZE_T* lpNumberOfBytesWritten)
{
    char buffer[8];
    snprintf(buffer, sizeof(buffer), "%u%u", pid, ApiCall::__WriteProcessMemory);
    OutputDebugStringA(buffer);
    SendToPipe(buffer);
    return OriginalWriteProcessMemory(hProcess, lpBaseAddress, lpBuffer, nSize, lpNumberOfBytesWritten);
}

BOOL WINAPI DetourReadProcessMemory(HANDLE hProcess, LPCVOID lpBaseAddress, LPVOID lpBuffer, SIZE_T nSize, SIZE_T* lpNumberOfBytesRead)
{
    char buffer[8];
    snprintf(buffer, sizeof(buffer), "%u%u", pid, ApiCall::__ReadProcessMemory);
    OutputDebugStringA(buffer);
    SendToPipe(buffer);
    return OriginalReadProcessMemory(hProcess, lpBaseAddress, lpBuffer, nSize, lpNumberOfBytesRead);
}

HANDLE WINAPI DetourCreateRemoteThread(HANDLE hProcess, LPSECURITY_ATTRIBUTES lpThreadAttributes, SIZE_T dwStackSize, LPTHREAD_START_ROUTINE lpStartAddress, LPVOID lpParameter, DWORD dwCreationFlags, LPDWORD lpThreadId)
{
    char buffer[8];
    snprintf(buffer, sizeof(buffer), "%u%u", pid, ApiCall::__CreateRemoteThread);
    OutputDebugStringA(buffer);
    SendToPipe(buffer);
    return OriginalCreateRemoteThread(hProcess, lpThreadAttributes, dwStackSize, lpStartAddress, lpParameter, dwCreationFlags, lpThreadId);
}

NTSTATUS NTAPI DetourNtCreateThreadEx(PHANDLE ThreadHandle, ACCESS_MASK DesiredAccess, PVOID ObjectAttributes, HANDLE ProcessHandle, PVOID StartRoutine, PVOID Argument, ULONG CreateFlags, ULONG ZeroBits, ULONG StackSize, ULONG MaximumStackSize, PVOID AttributeList)
{
    char buffer[8];
    snprintf(buffer, sizeof(buffer), "%u%u", pid, ApiCall::__NtCreateThreadEx);
    OutputDebugStringA(buffer);
    SendToPipe(buffer);
    return OriginalNtCreateThreadEx(ThreadHandle, DesiredAccess, ObjectAttributes, ProcessHandle, StartRoutine, Argument, CreateFlags, ZeroBits, StackSize, MaximumStackSize, AttributeList);
}

BOOL WINAPI DetourQueueUserAPC(PAPCFUNC pfnAPC, HANDLE hThread, ULONG_PTR dwData)
{
    char buffer[8];
    snprintf(buffer, sizeof(buffer), "%u%u", pid, ApiCall::__QueueUserAPC);
    OutputDebugStringA(buffer);
    SendToPipe(buffer);
    return OriginalQueueUserAPC(pfnAPC, hThread, dwData);
}

BOOL WINAPI DetourSetThreadContext(HANDLE hThread, const CONTEXT* lpContext)
{
    char buffer[8];
    snprintf(buffer, sizeof(buffer), "%u%u", pid, ApiCall::__SetThreadContext);
    OutputDebugStringA(buffer);
    SendToPipe(buffer);
    Sleep(10000);
    return OriginalSetThreadContext(hThread, lpContext);
}

DWORD WINAPI DetourSuspendThread(HANDLE hThread)
{
    char buffer[8];
    snprintf(buffer, sizeof(buffer), "%u%u", pid, ApiCall::__SuspendThread);
    OutputDebugStringA(buffer);
    SendToPipe(buffer);
    return OriginalSuspendThread(hThread);
}

DWORD WINAPI DetourResumeThread(HANDLE hThread)
{
    char buffer[8];
    snprintf(buffer, sizeof(buffer), "%u%u", pid, ApiCall::__ResumeThread);
    OutputDebugStringA(buffer);
    SendToPipe(buffer);
    return OriginalResumeThread(hThread);
}

HANDLE WINAPI DetourCreateThread(LPSECURITY_ATTRIBUTES lpThreadAttributes, SIZE_T dwStackSize, LPTHREAD_START_ROUTINE lpStartAddress, LPVOID lpParameter, DWORD dwCreationFlags, LPDWORD lpThreadId)
{
    char buffer[8];
    snprintf(buffer, sizeof(buffer), "%u%u", pid, ApiCall::__CreateThread);
    OutputDebugStringA(buffer);
    SendToPipe(buffer);
    return OriginalCreateThread(lpThreadAttributes, dwStackSize, lpStartAddress, lpParameter, dwCreationFlags, lpThreadId);
}

HMODULE WINAPI DetourLoadLibraryA(LPCSTR lpLibFileName)
{
    char buffer[8];
    snprintf(buffer, sizeof(buffer), "%u%u", pid, ApiCall::__LoadLibraryA);
    OutputDebugStringA(buffer);
    SendToPipe(buffer);
    return OriginalLoadLibraryA(lpLibFileName);
}

HMODULE WINAPI DetourLoadLibraryW(LPCWSTR lpLibFileName)
{
    char buffer[8];
    snprintf(buffer, sizeof(buffer), "%u%u", pid, ApiCall::__LoadLibraryW);
    OutputDebugStringA(buffer);
    SendToPipe(buffer);
    return OriginalLoadLibraryW(lpLibFileName);
}

HMODULE WINAPI DetourLoadLibraryExW(LPCWSTR lpLibFileName, HANDLE hFile, DWORD dwFlags)
{
    char buffer[8];
    snprintf(buffer, sizeof(buffer), "%u%u", pid, ApiCall::__LoadLibraryExW);
    OutputDebugStringA(buffer);
    SendToPipe(buffer);
    return OriginalLoadLibraryExW(lpLibFileName, hFile, dwFlags);
}

FARPROC WINAPI DetourGetProcAddress(HMODULE hModule, LPCSTR lpProcName)
{
    char buffer[8];
    snprintf(buffer, sizeof(buffer), "%u%u", pid, ApiCall::__GetProcAddress);
    OutputDebugStringA(buffer);
    SendToPipe(buffer);
    return OriginalGetProcAddress(hModule, lpProcName);
}

BOOL WINAPI DetourEnumProcesses(DWORD* pProcessIds, DWORD cb, DWORD* pBytesReturned)
{
    char buffer[8];
    snprintf(buffer, sizeof(buffer), "%u%u", pid, ApiCall::__EnumProcesses);
    OutputDebugStringA(buffer);
    SendToPipe(buffer);
    return OriginalEnumProcesses(pProcessIds, cb, pBytesReturned);
}

BOOL WINAPI DetourEnumProcessModules(HANDLE hProcess, HMODULE* lphModule, DWORD cb, LPDWORD lpcbNeeded)
{
    char buffer[8];
    snprintf(buffer, sizeof(buffer), "%u%u", pid, ApiCall::__EnumProcessModules);
    OutputDebugStringA(buffer);
    SendToPipe(buffer);
    return OriginalEnumProcessModules(hProcess, lphModule, cb, lpcbNeeded);
}

BOOL WINAPI DetourEnumProcessModulesEx(HANDLE hProcess, HMODULE* lphModule, DWORD cb, LPDWORD lpcbNeeded, DWORD dwFilterFlag)
{
    char buffer[8];
    snprintf(buffer, sizeof(buffer), "%u%u", pid, ApiCall::__EnumProcessModulesEx);
    OutputDebugStringA(buffer);
    SendToPipe(buffer);
    return OriginalEnumProcessModulesEx(hProcess, lphModule, cb, lpcbNeeded, dwFilterFlag);
}

HANDLE WINAPI DetourOpenProcess(DWORD dwDesiredAccess, BOOL bInheritHandle, DWORD dwProcessId)
{
    char buffer[8];
    snprintf(buffer, sizeof(buffer), "%u%u", pid, ApiCall::__OpenProcess);
    OutputDebugStringA(buffer);
    SendToPipe(buffer);
    return OriginalOpenProcess(dwDesiredAccess, bInheritHandle, dwProcessId);
}

HANDLE WINAPI DetourCreateFileMappingW(HANDLE hFile, LPSECURITY_ATTRIBUTES lpAttributes, DWORD flProtect, DWORD dwMaximumSizeHigh, DWORD dwMaximumSizeLow, LPCWSTR lpName)
{
    char buffer[8];
    snprintf(buffer, sizeof(buffer), "%u%u", pid, ApiCall::__CreateFileMappingW);
    OutputDebugStringA(buffer);
    SendToPipe(buffer);
    return OriginalCreateFileMappingW(hFile, lpAttributes, flProtect, dwMaximumSizeHigh, dwMaximumSizeLow, lpName);
}

LPVOID WINAPI DetourMapViewOfFile(HANDLE hFileMappingObject, DWORD dwDesiredAccess, DWORD dwFileOffsetHigh, DWORD dwFileOffsetLow, SIZE_T dwNumberOfBytesToMap)
{
    char buffer[8];
    snprintf(buffer, sizeof(buffer), "%u%u", pid, ApiCall::__MapViewOfFile);
    OutputDebugStringA(buffer);
    SendToPipe(buffer);
    return OriginalMapViewOfFile(hFileMappingObject, dwDesiredAccess, dwFileOffsetHigh, dwFileOffsetLow, dwNumberOfBytesToMap);
}

NTSTATUS NTAPI DetourNtUnmapViewOfSection(HANDLE ProcessHandle, PVOID BaseAddress)
{
    char buffer[8];
    snprintf(buffer, sizeof(buffer), "%u%u", pid, ApiCall::__NtUnmapViewOfSection);
    OutputDebugStringA(buffer);
    SendToPipe(buffer);
    return OriginalNtUnmapViewOfSection(ProcessHandle, BaseAddress);
}

NTSTATUS NTAPI DetourRtlCreateUserThread(HANDLE ProcessHandle, PSECURITY_DESCRIPTOR SecurityDescriptor, BOOLEAN CreateSuspended, ULONG StackZeroBits, SIZE_T StackReserved, SIZE_T StackCommit, PVOID StartAddress, PVOID Parameter, PHANDLE ThreadHandle, PCLIENT_ID ClientId)
{
    char buffer[8];
    snprintf(buffer, sizeof(buffer), "%u%u", pid, ApiCall::__RtlCreateUserThread);
    OutputDebugStringA(buffer);
    SendToPipe(buffer);
    return OriginalRtlCreateUserThread(ProcessHandle, SecurityDescriptor, CreateSuspended, StackZeroBits, StackReserved, StackCommit, StartAddress, Parameter, ThreadHandle, ClientId);
}

HINSTANCE WINAPI DetourShellExecuteW(HWND hwnd, LPCWSTR lpOperation, LPCWSTR lpFile, LPCWSTR lpParameters, LPCWSTR lpDirectory, INT nShowCmd)
{
    char buffer[8];
    snprintf(buffer, sizeof(buffer), "%u%u", pid, ApiCall::__ShellExecuteW);
    OutputDebugStringA(buffer);
    SendToPipe(buffer);
    return OriginalShellExecuteW(hwnd, lpOperation, lpFile, lpParameters, lpDirectory, nShowCmd);
}

UINT WINAPI DetourWinExec(LPCSTR lpCmdLine, UINT uCmdShow)
{
    char buffer[8];
    snprintf(buffer, sizeof(buffer), "%u%u", pid, ApiCall::__WinExec);
    OutputDebugStringA(buffer);
    SendToPipe(buffer);
    return OriginalWinExec(lpCmdLine, uCmdShow);
}

BOOL WINAPI DetourCreateProcessW(LPCWSTR lpApplicationName, LPWSTR lpCommandLine, LPSECURITY_ATTRIBUTES lpProcessAttributes, LPSECURITY_ATTRIBUTES lpThreadAttributes, BOOL bInheritHandles, DWORD dwCreationFlags, LPVOID lpEnvironment, LPCWSTR lpCurrentDirectory, LPSTARTUPINFOW lpStartupInfo, LPPROCESS_INFORMATION lpProcessInformation)
{
    char buffer[8];
    snprintf(buffer, sizeof(buffer), "%u%u", pid, ApiCall::__CreateProcessW);
    OutputDebugStringA(buffer);
    SendToPipe(buffer);
    return OriginalCreateProcessW(lpApplicationName, lpCommandLine, lpProcessAttributes, lpThreadAttributes, bInheritHandles, dwCreationFlags, lpEnvironment, lpCurrentDirectory, lpStartupInfo, lpProcessInformation);
}

BOOL WINAPI DetourCreateProcessWithTokenW(HANDLE hToken, DWORD dwLogonFlags, LPCWSTR lpApplicationName, LPWSTR lpCommandLine, DWORD dwCreationFlags, LPVOID lpEnvironment, LPCWSTR lpCurrentDirectory, LPSTARTUPINFOW lpStartupInfo, LPPROCESS_INFORMATION lpProcessInformation)
{
    char buffer[8];
    snprintf(buffer, sizeof(buffer), "%u%u", pid, ApiCall::__CreateProcessWithTokenW);
    OutputDebugStringA(buffer);
    SendToPipe(buffer);
    return OriginalCreateProcessWithTokenW(hToken, dwLogonFlags, lpApplicationName, lpCommandLine, dwCreationFlags, lpEnvironment, lpCurrentDirectory, lpStartupInfo, lpProcessInformation);
}

HHOOK WINAPI DetourSetWindowsHookExW(int idHook, HOOKPROC lpfn, HINSTANCE hMod, DWORD dwThreadId)
{
    char buffer[8];
    snprintf(buffer, sizeof(buffer), "%u%u", pid, ApiCall::__SetWindowsHookExW);
    OutputDebugStringA(buffer);
    SendToPipe(buffer);
    return OriginalSetWindowsHookExW(idHook, lpfn, hMod, dwThreadId);
}

ATOM WINAPI DetourGlobalAddAtomW(LPCWSTR lpString)
{
    char buffer[8];
    snprintf(buffer, sizeof(buffer), "%u%u", pid, ApiCall::__GlobalAddAtomW);
    OutputDebugStringA(buffer);
    SendToPipe(buffer);
    return OriginalGlobalAddAtomW(lpString);
}

UINT WINAPI DetourGlobalGetAtomNameW(ATOM nAtom, LPWSTR lpBuffer, int nSize)
{
    char buffer[8];
    snprintf(buffer, sizeof(buffer), "%u%u", pid, ApiCall::__GlobalGetAtomNameW);
    OutputDebugStringA(buffer);
    SendToPipe(buffer);
    return OriginalGlobalGetAtomNameW(nAtom, lpBuffer, nSize);
}

// Initialize hooks
void InstallHooks()
{
    // Initialize named pipe (optional)
    InitNamedPipe();

    // Dynamically resolve ntdll functions
    HMODULE hNtDll = GetModuleHandleA("ntdll.dll");
    if (hNtDll) {
        OriginalNtCreateThreadEx = (NTSTATUS(NTAPI*)(PHANDLE, ACCESS_MASK, PVOID, HANDLE, PVOID, PVOID, ULONG, ULONG, ULONG, ULONG, PVOID))
            GetProcAddress(hNtDll, "NtCreateThreadEx");
        OriginalNtUnmapViewOfSection = (NTSTATUS(NTAPI*)(HANDLE, PVOID))
            GetProcAddress(hNtDll, "NtUnmapViewOfSection");
        OriginalRtlCreateUserThread = (NTSTATUS(NTAPI*)(HANDLE, PSECURITY_DESCRIPTOR, BOOLEAN, ULONG, SIZE_T, SIZE_T, PVOID, PVOID, PHANDLE, PCLIENT_ID))
            GetProcAddress(hNtDll, "RtlCreateUserThread");
    }

    if (!OriginalNtCreateThreadEx || !OriginalNtUnmapViewOfSection || !OriginalRtlCreateUserThread) {
        OutputDebugStringA("[ERROR] Failed to resolve one or more ntdll functions\n");
        return;
    }

    // Begin Detours transaction
    DetourTransactionBegin();
    DetourUpdateThread(GetCurrentThread());

    // Attach detours
    DetourAttach(&(PVOID&)OriginalVirtualAlloc, DetourVirtualAlloc);
    DetourAttach(&(PVOID&)OriginalVirtualProtect, DetourVirtualProtect);
    DetourAttach(&(PVOID&)OriginalVirtualAllocEx, DetourVirtualAllocEx);
    DetourAttach(&(PVOID&)OriginalVirtualProtectEx, DetourVirtualProtectEx);
    DetourAttach(&(PVOID&)OriginalWriteProcessMemory, DetourWriteProcessMemory);
    DetourAttach(&(PVOID&)OriginalReadProcessMemory, DetourReadProcessMemory);
    DetourAttach(&(PVOID&)OriginalCreateRemoteThread, DetourCreateRemoteThread);
    DetourAttach(&(PVOID&)OriginalNtCreateThreadEx, DetourNtCreateThreadEx);
    DetourAttach(&(PVOID&)OriginalQueueUserAPC, DetourQueueUserAPC);
    DetourAttach(&(PVOID&)OriginalSetThreadContext, DetourSetThreadContext);
    DetourAttach(&(PVOID&)OriginalSuspendThread, DetourSuspendThread);
    DetourAttach(&(PVOID&)OriginalResumeThread, DetourResumeThread);
    DetourAttach(&(PVOID&)OriginalCreateThread, DetourCreateThread);
    DetourAttach(&(PVOID&)OriginalLoadLibraryA, DetourLoadLibraryA);
    DetourAttach(&(PVOID&)OriginalLoadLibraryW, DetourLoadLibraryW);
    DetourAttach(&(PVOID&)OriginalLoadLibraryExW, DetourLoadLibraryExW);
    DetourAttach(&(PVOID&)OriginalGetProcAddress, DetourGetProcAddress);
    DetourAttach(&(PVOID&)OriginalEnumProcesses, DetourEnumProcesses);
    DetourAttach(&(PVOID&)OriginalEnumProcessModules, DetourEnumProcessModules);
    DetourAttach(&(PVOID&)OriginalEnumProcessModulesEx, DetourEnumProcessModulesEx);
    DetourAttach(&(PVOID&)OriginalOpenProcess, DetourOpenProcess);
    DetourAttach(&(PVOID&)OriginalCreateFileMappingW, DetourCreateFileMappingW);
    DetourAttach(&(PVOID&)OriginalMapViewOfFile, DetourMapViewOfFile);
    DetourAttach(&(PVOID&)OriginalNtUnmapViewOfSection, DetourNtUnmapViewOfSection);
    DetourAttach(&(PVOID&)OriginalRtlCreateUserThread, DetourRtlCreateUserThread);
    DetourAttach(&(PVOID&)OriginalShellExecuteW, DetourShellExecuteW);
    DetourAttach(&(PVOID&)OriginalWinExec, DetourWinExec);
    DetourAttach(&(PVOID&)OriginalCreateProcessW, DetourCreateProcessW);
    DetourAttach(&(PVOID&)OriginalCreateProcessWithTokenW, DetourCreateProcessWithTokenW);
    DetourAttach(&(PVOID&)OriginalSetWindowsHookExW, DetourSetWindowsHookExW);
    DetourAttach(&(PVOID&)OriginalGlobalAddAtomW, DetourGlobalAddAtomW);
    DetourAttach(&(PVOID&)OriginalGlobalGetAtomNameW, DetourGlobalGetAtomNameW);

    // Commit transaction
    LONG error = DetourTransactionCommit();
    if (error != NO_ERROR) {
        char buffer[128];
        snprintf(buffer, sizeof(buffer), "[ERROR] DetourTransactionCommit failed: %ld\n", error);
        OutputDebugStringA(buffer);
    }
    else {
        OutputDebugStringA("[INFO] Hooks installed successfully\n");
    }
}

// Remove hooks
void RemoveHooks()
{
    DetourTransactionBegin();
    DetourUpdateThread(GetCurrentThread());

    // Detach detours
    DetourDetach(&(PVOID&)OriginalVirtualAlloc, DetourVirtualAlloc);
    DetourDetach(&(PVOID&)OriginalVirtualProtect, DetourVirtualProtect);
    DetourDetach(&(PVOID&)OriginalVirtualAllocEx, DetourVirtualAllocEx);
    DetourDetach(&(PVOID&)OriginalVirtualProtectEx, DetourVirtualProtectEx);
    DetourDetach(&(PVOID&)OriginalWriteProcessMemory, DetourWriteProcessMemory);
    DetourDetach(&(PVOID&)OriginalReadProcessMemory, DetourReadProcessMemory);
    DetourDetach(&(PVOID&)OriginalCreateRemoteThread, DetourCreateRemoteThread);
    DetourDetach(&(PVOID&)OriginalNtCreateThreadEx, DetourNtCreateThreadEx);
    DetourDetach(&(PVOID&)OriginalQueueUserAPC, DetourQueueUserAPC);
    DetourDetach(&(PVOID&)OriginalSetThreadContext, DetourSetThreadContext);
    DetourDetach(&(PVOID&)OriginalSuspendThread, DetourSuspendThread);
    DetourDetach(&(PVOID&)OriginalResumeThread, DetourResumeThread);
    DetourDetach(&(PVOID&)OriginalCreateThread, DetourCreateThread);
    DetourDetach(&(PVOID&)OriginalLoadLibraryA, DetourLoadLibraryA);
    DetourDetach(&(PVOID&)OriginalLoadLibraryW, DetourLoadLibraryW);
    DetourDetach(&(PVOID&)OriginalLoadLibraryExW, DetourLoadLibraryExW);
    DetourDetach(&(PVOID&)OriginalGetProcAddress, DetourGetProcAddress);
    DetourDetach(&(PVOID&)OriginalEnumProcesses, DetourEnumProcesses);
    DetourDetach(&(PVOID&)OriginalEnumProcessModules, DetourEnumProcessModules);
    DetourDetach(&(PVOID&)OriginalEnumProcessModulesEx, DetourEnumProcessModulesEx);
    DetourDetach(&(PVOID&)OriginalOpenProcess, DetourOpenProcess);
    DetourDetach(&(PVOID&)OriginalCreateFileMappingW, DetourCreateFileMappingW);
    DetourDetach(&(PVOID&)OriginalMapViewOfFile, DetourMapViewOfFile);
    DetourDetach(&(PVOID&)OriginalNtUnmapViewOfSection, DetourNtUnmapViewOfSection);
    DetourDetach(&(PVOID&)OriginalRtlCreateUserThread, DetourRtlCreateUserThread);
    DetourDetach(&(PVOID&)OriginalShellExecuteW, DetourShellExecuteW);
    DetourDetach(&(PVOID&)OriginalWinExec, DetourWinExec);
    DetourDetach(&(PVOID&)OriginalCreateProcessW, DetourCreateProcessW);
    DetourDetach(&(PVOID&)OriginalCreateProcessWithTokenW, DetourCreateProcessWithTokenW);
    DetourDetach(&(PVOID&)OriginalSetWindowsHookExW, DetourSetWindowsHookExW);
    DetourDetach(&(PVOID&)OriginalGlobalAddAtomW, DetourGlobalAddAtomW);
    DetourDetach(&(PVOID&)OriginalGlobalGetAtomNameW, DetourGlobalGetAtomNameW);

    // Commit transaction
    LONG error = DetourTransactionCommit();
    if (error != NO_ERROR) {
        char buffer[128];
        snprintf(buffer, sizeof(buffer), "[ERROR] DetourTransactionCommit (detach) failed: %ld\n", error);
        OutputDebugStringA(buffer);
    }
    else {
        OutputDebugStringA("[INFO] Hooks removed successfully\n");
    }

    // Close named pipe (optional)
    if (hPipe != INVALID_HANDLE_VALUE) {
        CloseHandle(hPipe);
        hPipe = INVALID_HANDLE_VALUE;
    }
}



// DLL entry point
BOOL APIENTRY DllMain(HMODULE hModule, DWORD ul_reason_for_call, LPVOID lpReserved)
{
    switch (ul_reason_for_call) {
    case DLL_PROCESS_ATTACH:
        pid = GetCurrentProcessId();
        DetourRestoreAfterWith();
        DisableThreadLibraryCalls(hModule);
        InstallHooks();
        break;
    case DLL_PROCESS_DETACH:
        RemoveHooks();
        break;
    }
    return TRUE;
}