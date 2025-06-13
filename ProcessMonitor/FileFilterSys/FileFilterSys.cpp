#include <ntifs.h>
#include <ntddk.h>
#include <fltKernel.h>
#include <dontuse.h>
#include <ntstrsafe.h>

#define DEVICE_NAME L"\\Device\\FileFilterDriver"
#define SYMLINK_NAME L"\\DosDevices\\FileFilterDriver"
#define FILE_FILTER_ALTITUDE L"385201"
#define IOCTL_RECEIVE CTL_CODE(FILE_DEVICE_UNKNOWN, 0x800, METHOD_BUFFERED, FILE_READ_DATA)
#define MAX_EVENTS 50000 // Max event can push to list
#define DbgPrintEx

// Event types
typedef enum __EVENT_TYPE { EVENT_IMAGE_LOAD, EVENT_REGISTRY, EVENT_PROCESS_CREATE, EVENT_FILE_CREATE, EVENT_FILE_WRITE } __EVENT_TYPE;

typedef struct _EVENT_DATA {
    LIST_ENTRY ListEntry;
    __EVENT_TYPE Type;
    LARGE_INTEGER Timestamp;
    struct {
        HANDLE ProcessId;
        WCHAR FilePath[260]; // Maximum length
        ACCESS_MASK DesiredAccess; // Only monitor CREATE/WRITE
    } FileCreate;
} EVENT_DATA, * PEVENT_DATA;

// Globals
PDEVICE_OBJECT gDeviceObject = NULL; // for I/O 
PFLT_FILTER gFilterHandle = NULL; // reg filter
KEVENT gEvent; // 
LIST_ENTRY gEventList; // List Event
KSPIN_LOCK gSpinLock; // protect dât in gEventList
LONG gEventCount = 0; // count event

// Cleanup resources
VOID CleanupResources() {
    if (gDeviceObject) {
        UNICODE_STRING symlinkName;
        RtlInitUnicodeString(&symlinkName, SYMLINK_NAME);
        IoDeleteSymbolicLink(&symlinkName);
        IoDeleteDevice(gDeviceObject);
        gDeviceObject = NULL;
    }

    KIRQL irql;
    KeAcquireSpinLock(&gSpinLock, &irql);
    while (!IsListEmpty(&gEventList)) {
        PLIST_ENTRY entry = RemoveHeadList(&gEventList);
        PEVENT_DATA event = CONTAINING_RECORD(entry, EVENT_DATA, ListEntry);
        ExFreePoolWithTag(event, 'evnt');
        InterlockedDecrement(&gEventCount);
    }
    KeReleaseSpinLock(&gSpinLock, irql);
}

// Queue event
BOOLEAN QueueEventData(__EVENT_TYPE Type, HANDLE ProcessId, PUNICODE_STRING FilePath, ACCESS_MASK DesiredAccess) {
    if (ProcessId == (HANDLE)4) {
        DbgPrintEx("FileFilter: Skipping event from System process (PID=4)\n");
        return FALSE;
    }

    if (InterlockedIncrement(&gEventCount) > MAX_EVENTS) {
        InterlockedDecrement(&gEventCount);
        DbgPrintEx("FileFilter: Event queue full, dropping event\n");
        return FALSE;
    }

    PEVENT_DATA event = (PEVENT_DATA)ExAllocatePoolWithTag(NonPagedPoolNx, sizeof(EVENT_DATA), 'evnt');
    if (!event) {
        InterlockedDecrement(&gEventCount);
        DbgPrintEx("FileFilter: Failed to allocate EVENT_DATA\n");
        return FALSE;
    }

    RtlZeroMemory(event, sizeof(EVENT_DATA));
    event->Type = Type;
    event->FileCreate.ProcessId = ProcessId;
    event->FileCreate.DesiredAccess = DesiredAccess;

    if (FilePath && FilePath->Buffer) {
        NTSTATUS status = RtlStringCchCopyW(event->FileCreate.FilePath,
            sizeof(event->FileCreate.FilePath) / sizeof(WCHAR),
            FilePath->Buffer);
        if (!NT_SUCCESS(status)) {
            DbgPrintEx("FileFilter: Failed to copy file path: 0x%X\n", status);
            ExFreePoolWithTag(event, 'evnt');
            InterlockedDecrement(&gEventCount);
            return FALSE;
        }
    }

    KIRQL irql;
    KeAcquireSpinLock(&gSpinLock, &irql);
    InsertTailList(&gEventList, &event->ListEntry);
    KeReleaseSpinLock(&gSpinLock, irql);
    KeSetEvent(&gEvent, 0, FALSE);
    return TRUE;
}

// File I/O callback
FLT_PREOP_CALLBACK_STATUS FileCreatePreOperation(PFLT_CALLBACK_DATA Data, PCFLT_RELATED_OBJECTS FltObjects, PVOID* CompletionContext) {
    UNREFERENCED_PARAMETER(FltObjects);
    UNREFERENCED_PARAMETER(CompletionContext);

    HANDLE processId = PsGetProcessId(PsGetCurrentProcess());
    PFLT_FILE_NAME_INFORMATION fileNameInfo = NULL;

    NTSTATUS status = FltGetFileNameInformation(Data, FLT_FILE_NAME_NORMALIZED | FLT_FILE_NAME_QUERY_ALWAYS_ALLOW_CACHE_LOOKUP, &fileNameInfo);
    if (!NT_SUCCESS(status)) {
        DbgPrintEx("FileFilter: FltGetFileNameInformation failed for PID %p, Operation %d: 0x%X\n", processId, Data->Iopb->MajorFunction, status);
        return FLT_PREOP_SUCCESS_NO_CALLBACK;
    }

    status = FltParseFileNameInformation(fileNameInfo);
    if (!NT_SUCCESS(status)) {
        DbgPrintEx("FileFilter: FltParseFileNameInformation failed: 0x%X\n", status);
        FltReleaseFileNameInformation(fileNameInfo);
        return FLT_PREOP_SUCCESS_NO_CALLBACK;
    }

    switch (Data->Iopb->MajorFunction) {
    case IRP_MJ_CREATE: // 0x00
        DbgPrintEx("FileFilter: IRP_MJ_CREATE intercepted (PID: %p, File: %wZ)\n", processId, &fileNameInfo->Name);
        QueueEventData(EVENT_FILE_CREATE, processId, &fileNameInfo->Name, Data->Iopb->Parameters.Create.SecurityContext->DesiredAccess);
        break;
    case IRP_MJ_WRITE: // 0x04
        DbgPrintEx("FileFilter: IRP_MJ_WRITE intercepted (PID: %p, File: %wZ, Length: %lu)\n",processId, &fileNameInfo->Name, Data->Iopb->Parameters.Write.Length);
        QueueEventData(EVENT_FILE_WRITE, processId, &fileNameInfo->Name, Data->Iopb->Parameters.Write.Length);
        break;
    }
    FltReleaseFileNameInformation(fileNameInfo);
    return FLT_PREOP_SUCCESS_NO_CALLBACK;
}

// Minifilter unload routine
NTSTATUS FilterUnload(FLT_FILTER_UNLOAD_FLAGS Flags) {
    UNREFERENCED_PARAMETER(Flags); // no use Flags
    if (gFilterHandle) {
        FltUnregisterFilter(gFilterHandle);
        gFilterHandle = NULL;
    }
    CleanupResources();
    DbgPrintEx("FileFilter: Driver unloaded\n");
    return STATUS_SUCCESS;
}

CONST FLT_OPERATION_REGISTRATION Callbacks[] = {
    { IRP_MJ_CREATE, 0, FileCreatePreOperation, NULL }, // Callback when FileCreate
    { IRP_MJ_WRITE, 0, FileCreatePreOperation, NULL }, // Callback when FileWrite
    { IRP_MJ_OPERATION_END }
};

CONST FLT_REGISTRATION FilterRegistration = {
    sizeof(FLT_REGISTRATION), 
    FLT_REGISTRATION_VERSION, // Minifilter drivers must set this member to FLT_REGISTRATION_VERSION.
    0,
    NULL,
    Callbacks, // callback FLT_OPERATION_REGISTRATION
    FilterUnload, // FilterUnload
    NULL, NULL, NULL, NULL, NULL, NULL, NULL
};

// Dispatch handlers
NTSTATUS DispatchDeviceControl(PDEVICE_OBJECT DeviceObject, PIRP Irp) {
    UNREFERENCED_PARAMETER(DeviceObject);
    PIO_STACK_LOCATION irpSp = IoGetCurrentIrpStackLocation(Irp);
    PVOID buffer = Irp->AssociatedIrp.SystemBuffer;
    ULONG returnLength = 0;
    NTSTATUS status = STATUS_SUCCESS;

    if (!buffer) {
        status = STATUS_INVALID_PARAMETER;
        DbgPrintEx("FileFilter: Invalid buffer in DeviceControl\n");
    }
    else if (irpSp->Parameters.DeviceIoControl.IoControlCode == IOCTL_RECEIVE) {
        if (irpSp->Parameters.DeviceIoControl.OutputBufferLength < sizeof(EVENT_DATA)) {
            status = STATUS_BUFFER_TOO_SMALL;
            DbgPrintEx("FileFilter: Output buffer too small\n");
        }
        else {
            KIRQL irql;
            KeAcquireSpinLock(&gSpinLock, &irql);
            if (!IsListEmpty(&gEventList)) {
                PLIST_ENTRY entry = RemoveHeadList(&gEventList);
                PEVENT_DATA event = CONTAINING_RECORD(entry, EVENT_DATA, ListEntry);
                RtlCopyMemory(buffer, event, sizeof(EVENT_DATA));
                returnLength = sizeof(EVENT_DATA);
                ExFreePoolWithTag(event, 'evnt');
                InterlockedDecrement(&gEventCount);
            }
            else {
                status = STATUS_NO_MORE_ENTRIES;
            }
            KeReleaseSpinLock(&gSpinLock, irql);
        }
    }
    else {
        status = STATUS_INVALID_DEVICE_REQUEST;
        DbgPrintEx("FileFilter: Invalid IOCTL code\n");
    }

    Irp->IoStatus.Status = status;
    Irp->IoStatus.Information = returnLength;
    IoCompleteRequest(Irp, IO_NO_INCREMENT);
    return status;
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
    UNICODE_STRING deviceName, symlinkName;

    // Initialize globals
    KeInitializeEvent(&gEvent, SynchronizationEvent, FALSE); // 1 thread cho manager
    InitializeListHead(&gEventList); 
    KeInitializeSpinLock(&gSpinLock);

    // Create device
    RtlInitUnicodeString(&deviceName, DEVICE_NAME);
    status = IoCreateDevice(DriverObject, 0, &deviceName, FILE_DEVICE_UNKNOWN, 0, FALSE, &gDeviceObject);
    if (!NT_SUCCESS(status)) {
        DbgPrintEx("FileFilter: Failed to create device: 0x%X\n", status);
        return status;
    }

    // Create symbolic link
    RtlInitUnicodeString(&symlinkName, SYMLINK_NAME); 
    status = IoCreateSymbolicLink(&symlinkName, &deviceName);
    if (!NT_SUCCESS(status)) {
        DbgPrintEx("FileFilter: Failed to create symbolic link: 0x%X\n", status);
        CleanupResources();
        return status;
    }

    // Set dispatch routines
    DriverObject->MajorFunction[IRP_MJ_CREATE] = HandleCreate;
    DriverObject->MajorFunction[IRP_MJ_CLOSE] = HandleClose;
    DriverObject->MajorFunction[IRP_MJ_DEVICE_CONTROL] = DispatchDeviceControl; // comunicate

    // Register mini-filter
    UNICODE_STRING altitude;
    RtlInitUnicodeString(&altitude, FILE_FILTER_ALTITUDE);
    status = FltRegisterFilter(DriverObject, &FilterRegistration, &gFilterHandle);
    if (!NT_SUCCESS(status)) {
        DbgPrintEx("FileFilter: Failed to register filter: 0x%X\n", status);
        CleanupResources();
        return status;
    }

    // Start filtering
    status = FltStartFiltering(gFilterHandle);
    if (!NT_SUCCESS(status)) {
        DbgPrintEx("FileFilter: Failed to start filtering: 0x%X\n", status);
        FltUnregisterFilter(gFilterHandle);
        CleanupResources();
        return status;
    }

    DbgPrintEx("FileFilter: Driver loaded and filtering started.\n");
    return STATUS_SUCCESS;
}