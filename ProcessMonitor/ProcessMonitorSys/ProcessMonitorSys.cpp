#include <ntifs.h>
#include <ntddk.h>
#include <ntimage.h>

#define DEVICE_NAME L"\\Device\\MonitorDriver"
#define SYMLINK_NAME L"\\DosDevices\\MonitorDriver"
#define FILTER_ALTITUDE L"320000"
#define IOCTL_RECEIVE CTL_CODE(FILE_DEVICE_UNKNOWN, 0x800, METHOD_BUFFERED, FILE_READ_DATA)
#define DbgPrint

// Event data structure
typedef enum __EVENT_TYPE { EVENT_IMAGE_LOAD, EVENT_REGISTRY, EVENT_PROCESS_CREATE, EVENT_FILE_CREATE } __EVENT_TYPE;

typedef struct _EVENT_DATA {
    LIST_ENTRY ListEntry;
    __EVENT_TYPE Type;
    LARGE_INTEGER Timestamp;
    union {
        struct {
            HANDLE ProcessId;
            WCHAR ImagePath[260];
        } ImageLoad;
        struct {
            WCHAR KeyPath[260];
            ULONG Operation;
        } Registry;
        struct {
            HANDLE ProcessId;
            HANDLE ParentId;
            WCHAR ImageName[260];
        } ProcessCreate;
    } Data;
} EVENT_DATA, * PEVENT_DATA;

// Global variables
PDEVICE_OBJECT gDeviceObject = NULL;
KEVENT gEvent;
LIST_ENTRY gEventList;
KSPIN_LOCK gSpinLock;
LARGE_INTEGER gRegCallbackHandle;
LONG gEventCount = 0;
#define MAX_EVENTS 50000

extern "C" NTKERNELAPI PVOID NTAPI PsGetProcessWow64Process(
    _In_ PEPROCESS Process
);

extern "C" NTSTATUS NTAPI RtlCreateUserThread(
    IN HANDLE               ProcessHandle,
    IN PSECURITY_DESCRIPTOR SecurityDescriptor OPTIONAL,
    IN BOOLEAN              CreateSuspended,
    IN ULONG                StackZeroBits,
    IN OUT SIZE_T            StackReserved,
    IN OUT SIZE_T            StackCommit,
    IN PVOID                StartAddress,
    IN PVOID                StartParameter OPTIONAL,
    OUT PHANDLE             ThreadHandle,
    OUT PCLIENT_ID          ClientID);

ULONG LoadLibraryWx64offset = 0;
ULONG LoadLibraryWX86offset = 0;
PVOID LoadLibraryWx64 = NULL;
PVOID LoadLibraryWx86 = NULL;
PVOID kernel32x64 = NULL;
PVOID kernel32x86 = NULL;

namespace WritePath2Process {
#define PROCESS_VM_OPERATION 0x0008
#define PROCESS_VM_WRITE 0x0020
#define PROCESS_VM_READ 0x0010
#define Path2DLLx86 L"C:\\Program Files\\ProcessMonitor\\Library\\Monitor.x86.dll\0"
#define Path2DLLx64 L"C:\\Program Files\\ProcessMonitor\\Library\\Monitor.x64.dll\0"

    BOOLEAN UnicodeStringEndsWith(PUNICODE_STRING FullString, PCWSTR Suffix, BOOLEAN CaseInsensitive)
    {
        if (!FullString || !FullString->Buffer || FullString->Length == 0 || !Suffix) {
            DbgPrint("UnicodeStringEndsWith: Invalid input\n");
            return FALSE;
        }

        UNICODE_STRING suffixUnicode;
        RtlInitUnicodeString(&suffixUnicode, Suffix);

        if (suffixUnicode.Length == 0 || suffixUnicode.Length > FullString->Length) {
            return FALSE;
        }

        // Calculate the starting point of the tail substring
        USHORT offset = FullString->Length - suffixUnicode.Length;
        UNICODE_STRING tail;
        tail.Buffer = (PWCH)((PUCHAR)FullString->Buffer + offset);
        tail.Length = suffixUnicode.Length;
        tail.MaximumLength = suffixUnicode.Length;

        // Validate pointer bounds to ensure tail is within FullString's buffer
        if ((PUCHAR)tail.Buffer < (PUCHAR)FullString->Buffer ||
            (PUCHAR)tail.Buffer + tail.Length >(PUCHAR)FullString->Buffer + FullString->Length) {
            DbgPrint("UnicodeStringEndsWith: Tail is out of bounds\n");
            return FALSE;
        }

        return RtlEqualUnicodeString(&tail, &suffixUnicode, CaseInsensitive);
    }

    BOOLEAN WritePathToProcess(HANDLE ProcessId, PCWSTR Path, PVOID* Address) {
        HANDLE processHandle = NULL;
        OBJECT_ATTRIBUTES objAttr = { 0 };
        CLIENT_ID clientId = { ProcessId, NULL };
        InitializeObjectAttributes(&objAttr, NULL, 0, NULL, NULL);
        SIZE_T memsize = 1000;
        DbgPrint("memsize %llu\n", memsize);

        __try {
            NTSTATUS status = ZwOpenProcess(&processHandle, PROCESS_VM_OPERATION | PROCESS_VM_WRITE, &objAttr, &clientId);
            if (!NT_SUCCESS(status)) {
                DbgPrint("ZwOpenProcess failed with status: 0x%08lX\n", (unsigned long)status);
                return FALSE;
            }
            if (memsize > MAXULONG) {
                DbgPrint("memsize (%zu) exceeds MAXULONG\n", memsize);
                return FALSE;
            }
            status = ZwAllocateVirtualMemory(processHandle, Address, 0, &memsize, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
            if (!NT_SUCCESS(status)) {
                DbgPrint("ZwAllocateVirtualMemory failed with status: 0x%08lX\n", (unsigned long)status);
                return FALSE;
            }

            // Print the allocated address for verification
            DbgPrint("Allocated baseAddress: 0x%p for ProcessId: %d\n", *Address, ProcessId);

            PMDL mdl = nullptr;
            mdl = IoAllocateMdl(*Address, (ULONG)memsize, FALSE, FALSE, NULL);
            if (!mdl) {
                DbgPrint("IoAllocateMdl failed\n");
                ZwFreeVirtualMemory(processHandle, Address, &memsize, MEM_RELEASE);
                return FALSE;
            }

            PVOID mapped = nullptr;
            __try {
                MmProbeAndLockPages(mdl, KernelMode, IoModifyAccess);
                mapped = MmMapLockedPagesSpecifyCache(mdl, KernelMode, MmCached, NULL, FALSE, NormalPagePriority);
                if (mapped) {
                    memcpy(mapped, Path, memsize);
                    //RtlCopyMemory(mapped, Path, memsize); // Copy injectData to mapped memory
                    DbgPrint("Mapped address: 0x%p\n", mapped);
                }
                else {
                    DbgPrint("MmMapLockedPages failed\n");
                }
            }
            __finally {
                if (mapped) {
                    MmUnmapLockedPages(mapped, mdl);
                }
                if (mdl) {
                    MmUnlockPages(mdl);
                    IoFreeMdl(mdl);
                }
            }
        }
        __finally {
            if (processHandle) {
                ZwClose(processHandle);
            }
        }
        return TRUE;
    }

}

namespace ResolveIAT {
#define TAG 'vaRE'
    ULONG RvaToFileOffset(PIMAGE_SECTION_HEADER sections, unsigned short numSections, ULONG rva, ULONG fileSize) {
        for (unsigned short i = 0; i < numSections; ++i) {
            ULONG va = sections[i].VirtualAddress;
            ULONG size = sections[i].Misc.VirtualSize;
            if (rva >= va && rva < va + size) {
                ULONG offset = sections[i].PointerToRawData + (rva - va);
                if (offset < fileSize) return offset;
                break;
            }
        }
        return 0;
    }
    ULONG GetExportOffset(PCWSTR dllPath, PCSTR exportFunction, BOOLEAN IsImage64bit) {
        OBJECT_ATTRIBUTES objAttr;
        UNICODE_STRING uPath;
        IO_STATUS_BLOCK ioStatus;
        HANDLE hFile;
        NTSTATUS status;

        RtlInitUnicodeString(&uPath, dllPath);
        InitializeObjectAttributes(&objAttr, &uPath, OBJ_KERNEL_HANDLE | OBJ_CASE_INSENSITIVE, NULL, NULL);

        status = ZwCreateFile(&hFile, GENERIC_READ, &objAttr, &ioStatus, NULL,
            FILE_ATTRIBUTE_NORMAL, FILE_SHARE_READ, FILE_OPEN,
            FILE_NON_DIRECTORY_FILE | FILE_SYNCHRONOUS_IO_NONALERT, NULL, 0);

        if (!NT_SUCCESS(status)) {
            DbgPrint("[-] Failed to open file: %wZ\n", &uPath);
            return 0;
        }

        FILE_STANDARD_INFORMATION stdInfo;
        status = ZwQueryInformationFile(hFile, &ioStatus, &stdInfo, sizeof(stdInfo), FileStandardInformation);
        if (!NT_SUCCESS(status) || stdInfo.EndOfFile.LowPart == 0) {
            DbgPrint("[-] Invalid file size.\n");
            ZwClose(hFile);
            return 0;
        }

        ULONG fileSize = stdInfo.EndOfFile.LowPart;

        unsigned char* fileData = (unsigned char*)ExAllocatePoolWithTag(NonPagedPool, fileSize, TAG);
        if (!fileData) {
            DbgPrint("[-] Memory allocation failed.\n");
            ZwClose(hFile);
            return 0;
        }

        status = ZwReadFile(hFile, NULL, NULL, NULL, &ioStatus, fileData, fileSize, NULL, NULL);
        ZwClose(hFile);

        if (!NT_SUCCESS(status) || ioStatus.Information != fileSize) {
            DbgPrint("[-] Failed to read file.\n");
            ExFreePoolWithTag(fileData, TAG);
            return 0;
        }

        PIMAGE_DOS_HEADER dosHeader = (PIMAGE_DOS_HEADER)fileData;
        if (dosHeader->e_magic != IMAGE_DOS_SIGNATURE || dosHeader->e_lfanew >= (LONG)fileSize) {
            DbgPrint("[-] Invalid DOS header.\n");
            ExFreePoolWithTag(fileData, TAG);
            return 0;
        }

        unsigned char* ntBase = fileData + dosHeader->e_lfanew;
        if (*(ULONG*)ntBase != IMAGE_NT_SIGNATURE) {
            DbgPrint("[-] Invalid NT signature.\n");
            ExFreePoolWithTag(fileData, TAG);
            return 0;
        }

        ULONG exportDirRVA = 0;
        PIMAGE_SECTION_HEADER sections = NULL;
        unsigned short numSections = 0;

        if (IsImage64bit) {
            PIMAGE_NT_HEADERS64 ntHeaders = (PIMAGE_NT_HEADERS64)ntBase;
            exportDirRVA = ntHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress;
            numSections = ntHeaders->FileHeader.NumberOfSections;
            sections = IMAGE_FIRST_SECTION(ntHeaders);
            DbgPrint("[+] Architecture: x64\n");
        }
        else {
            PIMAGE_NT_HEADERS32 ntHeaders = (PIMAGE_NT_HEADERS32)ntBase;
            exportDirRVA = ntHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress;
            numSections = ntHeaders->FileHeader.NumberOfSections;
            sections = IMAGE_FIRST_SECTION(ntHeaders);
            DbgPrint("[+] Architecture: x86\n");
        }

        ULONG exportOffset = RvaToFileOffset(sections, numSections, exportDirRVA, fileSize);
        if (exportOffset == 0) {
            DbgPrint("[-] Invalid export directory offset.\n");
            ExFreePoolWithTag(fileData, TAG);
            return 0;
        }

        PIMAGE_EXPORT_DIRECTORY exportDir = (PIMAGE_EXPORT_DIRECTORY)(fileData + exportOffset);
        ULONG* nameRVAs = (ULONG*)(fileData + RvaToFileOffset(sections, numSections, exportDir->AddressOfNames, fileSize));
        ULONG* funcRVAs = (ULONG*)(fileData + RvaToFileOffset(sections, numSections, exportDir->AddressOfFunctions, fileSize));
        unsigned short* ordinals = (unsigned short*)(fileData + RvaToFileOffset(sections, numSections, exportDir->AddressOfNameOrdinals, fileSize));

        if (!nameRVAs || !funcRVAs || !ordinals) {
            DbgPrint("[-] Invalid export table data.\n");
            ExFreePoolWithTag(fileData, TAG);
            return 0;
        }

        for (ULONG i = 0; i < exportDir->NumberOfNames; ++i) {
            ULONG nameOffset = RvaToFileOffset(sections, numSections, nameRVAs[i], fileSize);
            if (nameOffset == 0 || nameOffset >= fileSize) continue;

            const char* funcName = (const char*)(fileData + nameOffset);
            if (_stricmp(funcName, exportFunction) == 0) {
                unsigned short ordinal = ordinals[i];
                if (ordinal >= exportDir->NumberOfFunctions) {
                    DbgPrint("[-] Invalid ordinal.\n");
                    ExFreePoolWithTag(fileData, TAG);
                    return 0;
                }
                ULONG funcRVA = funcRVAs[ordinal];
                ExFreePoolWithTag(fileData, TAG);
                return funcRVA;
            }
        }

        DbgPrint("[-] Function not found: %s\n", exportFunction);
        ExFreePoolWithTag(fileData, TAG);
        return 0;
    }
}

typedef NTSTATUS(NTAPI* NtCreateThreadEx_t)(PHANDLE, ACCESS_MASK, PVOID, HANDLE, PVOID, PVOID, ULONG, SIZE_T, SIZE_T, SIZE_T, PVOID);

// Utility to get registry key path
NTSTATUS GetKeyPath(PUNICODE_STRING CompleteName, PUNICODE_STRING KeyPath) {
    if (!CompleteName || !CompleteName->Buffer) return STATUS_INVALID_PARAMETER;

    KeyPath->Length = min(CompleteName->Length, 260 * sizeof(WCHAR) - sizeof(WCHAR));
    KeyPath->MaximumLength = KeyPath->Length + sizeof(WCHAR);
    KeyPath->Buffer = (PWCH)ExAllocatePoolWithTag(NonPagedPoolNx, KeyPath->MaximumLength, 'kpth');
    if (!KeyPath->Buffer) return STATUS_INSUFFICIENT_RESOURCES;

    RtlCopyMemory(KeyPath->Buffer, CompleteName->Buffer, KeyPath->Length);
    KeyPath->Buffer[KeyPath->Length / sizeof(WCHAR)] = L'\0';
    return STATUS_SUCCESS;
}

// Utility to get current time
VOID GetFormattedTime(PLARGE_INTEGER Time) {
    KeQuerySystemTime(Time);
}

// Queue event data
BOOLEAN QueueEventData(__EVENT_TYPE Type, PVOID Data1, PVOID Data2, PVOID Data3) {
    if (InterlockedIncrement(&gEventCount) > MAX_EVENTS) {
        InterlockedDecrement(&gEventCount);
        DbgPrint("ProcMon: Event queue full, dropping event\n");
        return FALSE;
    }

    PEVENT_DATA event = (PEVENT_DATA)ExAllocatePoolWithTag(NonPagedPoolNx, sizeof(EVENT_DATA), 'evnt');
    if (!event) {
        InterlockedDecrement(&gEventCount);
        return FALSE;
    }

    RtlZeroMemory(event, sizeof(EVENT_DATA));
    event->Type = Type;
    GetFormattedTime(&event->Timestamp);

    switch (Type) {
    case EVENT_IMAGE_LOAD: {
        PUNICODE_STRING imagePath = (PUNICODE_STRING)Data2;
        event->Data.ImageLoad.ProcessId = (HANDLE)Data1;
        if (imagePath && imagePath->Buffer && imagePath->Length < sizeof(event->Data.ImageLoad.ImagePath)) {
            RtlCopyMemory(event->Data.ImageLoad.ImagePath, imagePath->Buffer, imagePath->Length);
            event->Data.ImageLoad.ImagePath[imagePath->Length / sizeof(WCHAR)] = L'\0';
        }
        break;
    }
    case EVENT_REGISTRY: {
        PUNICODE_STRING keyPath = (PUNICODE_STRING)Data1;
        if (keyPath && keyPath->Buffer && keyPath->Length < sizeof(event->Data.Registry.KeyPath)) {
            RtlCopyMemory(event->Data.Registry.KeyPath, keyPath->Buffer, keyPath->Length);
            event->Data.Registry.KeyPath[keyPath->Length / sizeof(WCHAR)] = L'\0';
        }
        event->Data.Registry.Operation = (ULONG)(ULONG_PTR)Data2;
        break;
    }
    case EVENT_PROCESS_CREATE: {
        PUNICODE_STRING imageName = (PUNICODE_STRING)Data3;
        event->Data.ProcessCreate.ProcessId = (HANDLE)Data1;
        event->Data.ProcessCreate.ParentId = (HANDLE)Data2;
        if (imageName && imageName->Buffer && imageName->Length < sizeof(event->Data.ProcessCreate.ImageName)) {
            RtlCopyMemory(event->Data.ProcessCreate.ImageName, imageName->Buffer, imageName->Length);
            event->Data.ProcessCreate.ImageName[imageName->Length / sizeof(WCHAR)] = L'\0';
        }
        break;
    }
    default:
        ExFreePoolWithTag(event, 'evnt');
        InterlockedDecrement(&gEventCount);
        return FALSE;
    }

    KIRQL irql;
    KeAcquireSpinLock(&gSpinLock, &irql);
    InsertTailList(&gEventList, &event->ListEntry);
    KeReleaseSpinLock(&gSpinLock, irql);
    KeSetEvent(&gEvent, 0, FALSE);
    return TRUE;
}

// LoadImageNotifyCallback
VOID LoadImageNotifyCallback(PUNICODE_STRING FullImageName, HANDLE ProcessId, PIMAGE_INFO ImageInfo) {
    UNREFERENCED_PARAMETER(ImageInfo);
    if (FullImageName) {
        QueueEventData(EVENT_IMAGE_LOAD, ProcessId, FullImageName, NULL);
    }
    if (LoadLibraryWX86offset == 0 || LoadLibraryWx64offset == 0) {
        return;
    }

    if (FullImageName && WritePath2Process::UnicodeStringEndsWith(FullImageName, L"msvcrt.dll", TRUE)) {
        BOOLEAN isImagex64 = WritePath2Process::UnicodeStringEndsWith(FullImageName, L"system32\\msvcrt.dll", TRUE);
        PEPROCESS Process = NULL;
        NTSTATUS status = PsLookupProcessByProcessId(ProcessId, &Process);
        BOOLEAN isProcessx64 = FALSE;
        if (NT_SUCCESS(status)) {
            isProcessx64 = (PsGetProcessWow64Process(Process) == NULL);
            ObDereferenceObject(Process);
        }
        else {
            return;
        }

        DbgPrint("x64");
        PVOID Address2Path = NULL;
        if (isImagex64 == TRUE && isProcessx64 == TRUE) {
            if (WritePath2Process::WritePathToProcess(ProcessId, Path2DLLx64, &Address2Path)) {
                DbgPrint("x64 Address2Path: 0x%p\n", Address2Path);
                HANDLE hThread = NULL;
                HANDLE processHandle;
                OBJECT_ATTRIBUTES objAttr = { 0 };
                CLIENT_ID clientId = { ProcessId, 0 };
                /*PEPROCESS targetProcess = NULL;
                KAPC_STATE apcState;*/
                InitializeObjectAttributes(&objAttr, NULL, OBJ_KERNEL_HANDLE, NULL, NULL);
                status = ZwOpenProcess(&processHandle, PROCESS_ALL_ACCESS, &objAttr, &clientId);
                if (!NT_SUCCESS(status)) {
                    DbgPrint("ZwOpenProcess failed: 0x%X\n", status);
                    return;
                }
                DbgPrint("address2LoadLibraryW: 0x%p\n", LoadLibraryWx64);
                __try {
                    ProbeForRead(LoadLibraryWx64, sizeof(PVOID), sizeof(PVOID));
                    ProbeForRead(Address2Path, sizeof(PVOID), sizeof(PVOID));
                }
                __except (EXCEPTION_EXECUTE_HANDLER) {
                    DbgPrint("Invalid LoadLibraryWx64 address\n");
                    ZwClose(processHandle);
                    return;
                }
                PUCHAR pPrevMode = (PUCHAR)PsGetCurrentThread() + 0x232;
                UCHAR prevMode = *pPrevMode;
                
                if (STATUS_SUCCESS != (status = RtlCreateUserThread(processHandle, NULL, FALSE, 0, 0x1000, 0x100000, LoadLibraryWx64, Address2Path, &hThread, NULL))) {
                    DbgPrint("RtlCreateUserThread failed: 0x%X\n", status);
                    ZwClose(processHandle);
                    return;
                }
                ZwClose(hThread);
                *pPrevMode = prevMode;
            }
            else {
                DbgPrint("x64 not found");
            }
        }
        else if (isImagex64 == FALSE && isProcessx64 == FALSE) {
            if (WritePath2Process::WritePathToProcess(ProcessId, Path2DLLx86, &Address2Path)) {
                DbgPrint("x86 Address2Path: 0x%p\n", Address2Path);
                HANDLE hThread = NULL;
                HANDLE processHandle;
                OBJECT_ATTRIBUTES objAttr = { 0 };
                CLIENT_ID clientId = { ProcessId, 0 };
                InitializeObjectAttributes(&objAttr, NULL, OBJ_KERNEL_HANDLE, NULL, NULL);
                status = ZwOpenProcess(&processHandle, PROCESS_ALL_ACCESS, &objAttr, &clientId);
                if (!NT_SUCCESS(status)) {
                    DbgPrint("ZwOpenProcess failed: 0x%X\n", status);
                    return;
                }
                DbgPrint("address2LoadLibraryW: 0x%p\n", LoadLibraryWx86);
                PUCHAR pPrevMode = (PUCHAR)PsGetCurrentThread() + 0x232;
                UCHAR prevMode = *pPrevMode;
                __try {
                    ProbeForRead(LoadLibraryWx86, sizeof(PVOID), sizeof(PVOID));
                    ProbeForRead(Address2Path, sizeof(PVOID), sizeof(PVOID));
                }
                __except (EXCEPTION_EXECUTE_HANDLER) {
                    DbgPrint("Invalid LoadLibraryWx64 address\n");
                    ZwClose(processHandle);
                    return;
                }
                if (STATUS_SUCCESS != (status = RtlCreateUserThread(processHandle, NULL, FALSE, 0, 0x1000, 0x100000, LoadLibraryWx86, Address2Path, &hThread, NULL))) {
                    DbgPrint("RtlCreateUserThread failed: 0x%X\n", status);
                    ZwClose(processHandle);
                    return;
                }
                ZwClose(hThread);
                *pPrevMode = prevMode;
            }
            else {
                DbgPrint("x64 not found");
            }
        }
    }

    if (LoadLibraryWx86 == NULL || LoadLibraryWx64 == NULL) {
        if (FullImageName && WritePath2Process::UnicodeStringEndsWith(FullImageName, L"kernel32.dll", TRUE)) {
            BOOLEAN isImagex64 = WritePath2Process::UnicodeStringEndsWith(FullImageName, L"system32\\kernel32.dll", TRUE);
            PEPROCESS Process = NULL;
            NTSTATUS status = PsLookupProcessByProcessId(ProcessId, &Process);
            BOOLEAN isProcessx64 = FALSE;
            if (NT_SUCCESS(status)) {
                isProcessx64 = (PsGetProcessWow64Process(Process) == NULL);
                ObDereferenceObject(Process);
            }
            else {
                return;
            }

            DbgPrint("??");

            if (isImagex64 == TRUE && isProcessx64 == TRUE) {
                LoadLibraryWx64 = (PVOID)((ULONG_PTR)ImageInfo->ImageBase + LoadLibraryWx64offset);
                kernel32x64 = ImageInfo->ImageBase;
            }
            else if (FALSE == isImagex64 && isProcessx64 == FALSE) {
                LoadLibraryWx86 = (PVOID)((ULONG_PTR)ImageInfo->ImageBase + LoadLibraryWX86offset);
                kernel32x86 = ImageInfo->ImageBase;
            }
        }
    }

}

// RegistryNotifyCallback
NTSTATUS RegistryNotifyCallback(PVOID CallbackContext, PVOID Argument1, PVOID Argument2) {
    UNREFERENCED_PARAMETER(CallbackContext);
    REG_NOTIFY_CLASS op = (REG_NOTIFY_CLASS)(ULONG_PTR)Argument1;
    UNICODE_STRING keyPath = { 0 };

    switch (op) {
    case RegNtPreCreateKey: {
        PREG_CREATE_KEY_INFORMATION createInfo = (PREG_CREATE_KEY_INFORMATION)Argument2;
        if (createInfo && createInfo->CompleteName) {
            if (NT_SUCCESS(GetKeyPath(createInfo->CompleteName, &keyPath))) {
                QueueEventData(EVENT_REGISTRY, &keyPath, (PVOID)(ULONG_PTR)op, NULL);
                if (keyPath.Buffer) ExFreePoolWithTag(keyPath.Buffer, 'kpth');
            }
        }
        break;
    }
    case RegNtPreSetValueKey:
    case RegNtPreDeleteKey:
    case RegNtPreDeleteValueKey: {
        PREG_SET_VALUE_KEY_INFORMATION setInfo = (PREG_SET_VALUE_KEY_INFORMATION)Argument2;
        if (setInfo && setInfo->Object) {
            UNICODE_STRING tempPath = { 0 };
            ULONG requiredLength;
            NTSTATUS status = ZwQueryKey(setInfo->Object, KeyNameInformation, NULL, 0, &requiredLength);
            if (status == STATUS_BUFFER_TOO_SMALL) {
                tempPath.Buffer = (PWCH)ExAllocatePoolWithTag(NonPagedPoolNx, requiredLength, 'kpth');
                if (tempPath.Buffer) {
                    tempPath.MaximumLength = (USHORT)requiredLength;
                    status = ZwQueryKey(setInfo->Object, KeyNameInformation, tempPath.Buffer, requiredLength, &requiredLength);
                    if (NT_SUCCESS(status)) {
                        tempPath.Length = (USHORT)(requiredLength - sizeof(UNICODE_STRING));
                        QueueEventData(EVENT_REGISTRY, &tempPath, (PVOID)(ULONG_PTR)op, NULL);
                    }
                    ExFreePoolWithTag(tempPath.Buffer, 'kpth');
                }
            }
        }
        break;
    }
    default:
        break;
    }
    return STATUS_SUCCESS;
}

// ProcessNotifyCallback
VOID ProcessNotifyCallback(PEPROCESS Process, HANDLE ProcessId, PPS_CREATE_NOTIFY_INFO CreateInfo) {
    UNREFERENCED_PARAMETER(Process);
    if (CreateInfo && CreateInfo->ImageFileName) {
        QueueEventData(EVENT_PROCESS_CREATE, ProcessId, CreateInfo->ParentProcessId, (PVOID)CreateInfo->ImageFileName);
    }
}

// IOCTL dispatch
NTSTATUS DispatchDeviceControl(PDEVICE_OBJECT DeviceObject, PIRP Irp) {
    UNREFERENCED_PARAMETER(DeviceObject);
    PIO_STACK_LOCATION irpSp = IoGetCurrentIrpStackLocation(Irp);
    NTSTATUS status = STATUS_SUCCESS;
    PVOID buffer = Irp->AssociatedIrp.SystemBuffer;
    ULONG returnLength = 0;

    switch (irpSp->Parameters.DeviceIoControl.IoControlCode) {
    case IOCTL_RECEIVE: {
        KIRQL irql;
        KeAcquireSpinLock(&gSpinLock, &irql);
        if (!IsListEmpty(&gEventList)) {
            PLIST_ENTRY entry = RemoveHeadList(&gEventList);
            PEVENT_DATA event = CONTAINING_RECORD(entry, EVENT_DATA, ListEntry);
            if (irpSp->Parameters.DeviceIoControl.OutputBufferLength >= sizeof(EVENT_DATA)) {
                RtlCopyMemory(buffer, event, sizeof(EVENT_DATA));
                returnLength = sizeof(EVENT_DATA);
                InterlockedDecrement(&gEventCount);
            }
            else {
                status = STATUS_BUFFER_TOO_SMALL;
            }
            ExFreePoolWithTag(event, 'evnt');
        }
        else {
            status = STATUS_NO_MORE_ENTRIES;
        }
        KeReleaseSpinLock(&gSpinLock, irql);
        break;
    }
    default:
        status = STATUS_INVALID_PARAMETER;
        break;
    }

    Irp->IoStatus.Status = status;
    Irp->IoStatus.Information = returnLength;
    IoCompleteRequest(Irp, IO_NO_INCREMENT);
    return status;
}

// Driver unload
VOID DriverUnload(PDRIVER_OBJECT DriverObject) {
    UNICODE_STRING symlinkName;
    RtlInitUnicodeString(&symlinkName, SYMLINK_NAME);
    IoDeleteSymbolicLink(&symlinkName);
    IoDeleteDevice(DriverObject->DeviceObject);

    // Unregister callbacks
    PsRemoveLoadImageNotifyRoutine(LoadImageNotifyCallback);
    PsSetCreateProcessNotifyRoutineEx(ProcessNotifyCallback, TRUE);
    if (gRegCallbackHandle.QuadPart) CmUnRegisterCallback(gRegCallbackHandle);

    // Clean up queued data
    KIRQL irql;
    KeAcquireSpinLock(&gSpinLock, &irql);
    while (!IsListEmpty(&gEventList)) {
        PLIST_ENTRY entry = RemoveHeadList(&gEventList);
        PEVENT_DATA event = CONTAINING_RECORD(entry, EVENT_DATA, ListEntry);
        ExFreePoolWithTag(event, 'evnt');
        InterlockedDecrement(&gEventCount);
    }
    KeReleaseSpinLock(&gSpinLock, irql);

    DbgPrint("ProcMon: Driver unloaded\n");
}

NTSTATUS HandleCreate(PDEVICE_OBJECT DeviceObject, PIRP Irp) {
    UNREFERENCED_PARAMETER(DeviceObject);
    Irp->IoStatus.Status = STATUS_SUCCESS;
    Irp->IoStatus.Information = 0;
    IoCompleteRequest(Irp, IO_NO_INCREMENT);
    return STATUS_SUCCESS;
}

NTSTATUS HandleClose(PDEVICE_OBJECT DeviceObject, PIRP Irp) {
    UNREFERENCED_PARAMETER(DeviceObject);
    Irp->IoStatus.Status = STATUS_SUCCESS;
    Irp->IoStatus.Information = 0;
    IoCompleteRequest(Irp, IO_NO_INCREMENT);
    return STATUS_SUCCESS;
}

// DriverEntry
extern "C" NTSTATUS DriverEntry(PDRIVER_OBJECT DriverObject, PUNICODE_STRING RegistryPath) {
    UNREFERENCED_PARAMETER(RegistryPath);
    NTSTATUS status;
    UNICODE_STRING deviceName, symlinkName, altitude;

    LoadLibraryWx64offset = ResolveIAT::GetExportOffset(L"\\??\\C:\\Windows\\System32\\kernel32.dll", "LoadLibraryW", TRUE);
    LoadLibraryWX86offset = ResolveIAT::GetExportOffset(L"\\??\\C:\\Windows\\syswow64\\kernel32.dll", "LoadLibraryW", FALSE);
    if (LoadLibraryWX86offset != 0 || LoadLibraryWx64offset != 0) {
        DbgPrint("[+] LoadLibraryW RVA: 0x%08X\n", LoadLibraryWx64offset);
        DbgPrint("[+] LoadLibraryW RVA: 0x%08X\n", LoadLibraryWX86offset);
    }
    else {
        DbgPrint("[-] Failed to find export offset.\n");
    }

    // Initialize globals
    KeInitializeEvent(&gEvent, SynchronizationEvent, FALSE);
    InitializeListHead(&gEventList);
    KeInitializeSpinLock(&gSpinLock);
    gEventCount = 0;

    // Create device
    RtlInitUnicodeString(&deviceName, DEVICE_NAME);
    status = IoCreateDevice(DriverObject, 0, &deviceName, FILE_DEVICE_UNKNOWN, 0, FALSE, &gDeviceObject);
    if (!NT_SUCCESS(status)) {
        DbgPrint("ProcMon: IoCreateDevice failed: 0x%X\n", status);
        goto Cleanup;
    }

    // Create symbolic link
    RtlInitUnicodeString(&symlinkName, SYMLINK_NAME);
    status = IoCreateSymbolicLink(&symlinkName, &deviceName);
    if (!NT_SUCCESS(status)) {
        DbgPrint("ProcMon: IoCreateSymbolicLink failed: 0x%X\n", status);
        IoDeleteDevice(gDeviceObject);
        goto Cleanup;
    }

    // Set dispatch routines
    DriverObject->DriverUnload = DriverUnload;
    DriverObject->MajorFunction[IRP_MJ_CREATE] = HandleCreate;
    DriverObject->MajorFunction[IRP_MJ_CLOSE] = HandleClose;
    DriverObject->MajorFunction[IRP_MJ_DEVICE_CONTROL] = DispatchDeviceControl;

    // Register callbacks
    status = PsSetCreateProcessNotifyRoutineEx(ProcessNotifyCallback, FALSE);
    if (!NT_SUCCESS(status)) {
        DbgPrint("ProcMon: PsSetCreateProcessNotifyRoutineEx failed: 0x%X\n", status);
        goto Cleanup;
    }

    status = PsSetLoadImageNotifyRoutine(LoadImageNotifyCallback);
    if (!NT_SUCCESS(status)) {
        DbgPrint("ProcMon: PsSetLoadImageNotifyRoutine failed: 0x%X\n", status);
        PsSetCreateProcessNotifyRoutineEx(ProcessNotifyCallback, TRUE);
        goto Cleanup;
    }

    RtlInitUnicodeString(&altitude, FILTER_ALTITUDE);
    status = CmRegisterCallbackEx(RegistryNotifyCallback, &altitude, DriverObject, NULL, &gRegCallbackHandle, NULL);
    if (!NT_SUCCESS(status)) {
        DbgPrint("ProcMon: CmRegisterCallbackEx failed: 0x%X\n", status);
        PsSetCreateProcessNotifyRoutineEx(ProcessNotifyCallback, TRUE);
        PsRemoveLoadImageNotifyRoutine(LoadImageNotifyCallback);
        goto Cleanup;
    }

    DbgPrint("ProcMon: Driver loaded successfully\n");
    return STATUS_SUCCESS;

Cleanup:
    if (gDeviceObject) {
        IoDeleteSymbolicLink(&symlinkName);
        IoDeleteDevice(gDeviceObject);
    }
    return status;
}