#include <windows.h>
#include <stdio.h>
#include <string>
#include <iostream>

// Your ApiCall enum
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

int main() {
    // Example PID and ApiCall value
    DWORD pid = GetCurrentProcessId(); // Example: Use current process ID
    ApiCall apiCall = ApiCall::__VirtualAlloc; // Example: Use __VirtualAlloc

    // Step 1: Format the string using snprintf
    char buffer[64];
    snprintf(buffer, sizeof(buffer), "%u%u", pid, static_cast<DWORD>(apiCall));

    // Step 2: Connect to the named pipe
    HANDLE hPipe = CreateFileW(
        L"\\\\.\\pipe\\_IMonitor_", // Pipe name
        GENERIC_READ | GENERIC_WRITE,
        0,                          // No sharing
        NULL,                       // Default security attributes
        OPEN_EXISTING,              // Open existing pipe
        FILE_FLAG_OVERLAPPED,       // Overlapped mode for async operations
        NULL                        // No template file
    );

    if (hPipe == INVALID_HANDLE_VALUE) {
        std::cerr << "Failed to connect to pipe. Error: " << GetLastError() << std::endl;
        return 1;
    }

    // Step 3: Write the formatted string to the pipe
    DWORD bytesWritten;
    BOOL writeResult = WriteFile(
        hPipe,
        buffer,
        strlen(buffer) + 1, // Include null terminator
        &bytesWritten,
        NULL
    );

    if (!writeResult) {
        std::cerr << "Failed to write to pipe. Error: " << GetLastError() << std::endl;
        CloseHandle(hPipe);
        return 1;
    }

    std::cout << "Sent to pipe: " << buffer << std::endl;

    // Step 4: Create an event for asynchronous reading
    HANDLE hEvent = CreateEventW(
        NULL,   // Default security attributes
        TRUE,   // Manual reset event
        FALSE,  // Initial state is non-signaled
        NULL    // No name
    );

    if (hEvent == NULL) {
        std::cerr << "Failed to create event. Error: " << GetLastError() << std::endl;
        CloseHandle(hPipe);
        return 1;
    }

    // Step 5: Set up overlapped structure for async read
    OVERLAPPED overlapped = { 0 };
    overlapped.hEvent = hEvent;

    char readBuffer[256];
    DWORD bytesRead;

    // Step 6: Initiate asynchronous read
    BOOL readResult = ReadFile(
        hPipe,
        readBuffer,
        sizeof(readBuffer) - 1,
        &bytesRead,
        &overlapped
    );

    if (!readResult && GetLastError() != ERROR_IO_PENDING) {
        std::cerr << "Failed to initiate read. Error: " << GetLastError() << std::endl;
        CloseHandle(hEvent);
        CloseHandle(hPipe);
        return 1;
    }

    // Step 7: Wait for the read operation to complete
    DWORD waitResult = WaitForSingleObject(hEvent, INFINITE);
    if (waitResult == WAIT_OBJECT_0) {
        // Get the result of the overlapped read
        if (GetOverlappedResult(hPipe, &overlapped, &bytesRead, FALSE)) {
            readBuffer[bytesRead] = '\0'; // Null-terminate the string
            std::cout << "Received from pipe: " << readBuffer << std::endl;

            // Step 8: Process the received data
            // Example: Parse the received data (assuming it's in the same format as sent)
            DWORD receivedPid, receivedApiCall;
            if (sscanf_s(readBuffer, "%u%u", &receivedPid, &receivedApiCall) == 2) {
                std::cout << "Parsed PID: " << receivedPid << ", ApiCall: " << receivedApiCall << std::endl;
                // You can cast receivedApiCall back to the ApiCall enum if needed
                ApiCall apiCallValue = static_cast<ApiCall>(receivedApiCall);
                // Add your processing logic here
            }
            else {
                std::cerr << "Failed to parse received data." << std::endl;
            }
        }
        else {
            std::cerr << "Failed to get overlapped result. Error: " << GetLastError() << std::endl;
        }
    }
    else {
        std::cerr << "WaitForSingleObject failed. Error: " << GetLastError() << std::endl;
    }

    // Step 9: Clean up
    CloseHandle(hEvent);
    CloseHandle(hPipe);

    return 0;
}