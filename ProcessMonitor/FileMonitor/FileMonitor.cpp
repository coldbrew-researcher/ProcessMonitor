#include <ntifs.h>
#include <ntddk.h>
#include <fltKernel.h>
#include <wdf.h>


#define FILE_FILTER_ALTITUDE L"320100" // Unique altitude for file monitoring
#define MONITOR_DEVICE_NAME L"\\Device\\MonitorDriver" // Device name of MonitorDriver
#define IOCTL_SUBMIT_EVENT CTL_CODE(FILE_DEVICE_UNKNOWN, 0x801, METHOD_BUFFERED, FILE_WRITE_DATA)

// Shared event data structure (same as MonitorDriver)
typedef enum { EVENT_IMAGE_LOAD, EVENT_REGISTRY, EVENT_PROCESS_CREATE, EVENT_FILE_CREATE } __EVENT_TYPE;

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
        struct {
            HANDLE ProcessId;
            WCHAR FilePath[260];
            ACCESS_MASK DesiredAccess;
        } FileCreate;
    } Data;
} EVENT_DATA, * PEVENT_DATA;


PFLT_FILTER gFilterHandle = NULL;
PDEVICE_OBJECT gMonitorDeviceObject = NULL;

// Utility to get current time
VOID GetFormattedTime(PLARGE_INTEGER Time) {
    KeQuerySystemTime(Time);
}

// Queue event data to MonitorDriver
NTSTATUS QueueEventData(__EVENT_TYPE Type, PVOID Data1, PVOID Data2, PVOID Data3) {
    NTSTATUS status = STATUS_SUCCESS;
    PEVENT_DATA event = NULL;
    PIRP irp = NULL;

    // Allocate event data
    event = (PEVENT_DATA)ExAllocatePoolWithTag(NonPagedPoolNx, sizeof(EVENT_DATA), 'evnt');
    if (!event) {
        return STATUS_INSUFFICIENT_RESOURCES;
    }

    RtlZeroMemory(event, sizeof(EVENT_DATA));
    event->Type = Type;
    GetFormattedTime(&event->Timestamp);

    if (Type == EVENT_FILE_CREATE) {
        PUNICODE_STRING filePath = (PUNICODE_STRING)Data2;
        event->Data.FileCreate.ProcessId = (HANDLE)Data1;
        if (filePath && filePath->Buffer && filePath->Length < sizeof(event->Data.FileCreate.FilePath)) {
            RtlCopyMemory(event->Data.FileCreate.FilePath, filePath->Buffer, filePath->Length);
            event->Data.FileCreate.FilePath[filePath->Length / sizeof(WCHAR)] = L'\0';
        }
        event->Data.FileCreate.DesiredAccess = (ACCESS_MASK)(ULONG_PTR)Data3;
    }

    // Send event to MonitorDriver via IRP
    irp = IoBuildDeviceIoControlRequest(
        IOCTL_SUBMIT_EVENT,
        gMonitorDeviceObject,
        event,
        sizeof(EVENT_DATA),
        NULL,
        0,
        FALSE,
        NULL,
        NULL
    );

    if (!irp) {
        ExFreePool(event);
        return STATUS_INSUFFICIENT_RESOURCES;
    }

    status = IoCallDriver(gMonitorDeviceObject, irp);
    if (!NT_SUCCESS(status)) {
        DbgPrint("FileMonitorFilter: Failed to send event to MonitorDriver: 0x%X\n", status);
        ExFreePool(event);
    }

    return status;
}

// Pre-operation callback for file creation
FLT_PREOP_CALLBACK_STATUS FileCreatePreOperation(
    PFLT_CALLBACK_DATA Data,
    PCFLT_RELATED_OBJECTS FltObjects,
    PVOID* CompletionContext
) {
    UNREFERENCED_PARAMETER(FltObjects);
    UNREFERENCED_PARAMETER(CompletionContext);

    if (Data->Iopb->MajorFunction == IRP_MJ_CREATE) {
        PUNICODE_STRING fileName = &Data->Iopb->TargetFileObject->FileName;
        HANDLE processId = PsGetProcessId(PsGetCurrentProcess());

        DbgPrint("FileMonitorFilter: File create detected, PID: %p, FileName Length: %u\n",
            processId, fileName->Length);

        if (fileName->Length > 0 && fileName->Buffer != NULL) {
            DbgPrint("FileMonitorFilter: File create: %wZ (PID: %p)\n", fileName, processId);
            QueueEventData(
                EVENT_FILE_CREATE,
                processId,
                fileName,
                (PVOID)(ULONG_PTR)Data->Iopb->Parameters.Create.SecurityContext->DesiredAccess
            );
        }
        else {
            DbgPrint("FileMonitorFilter: Skipping event due to empty or invalid file name\n");
        }
    }

    return FLT_PREOP_SUCCESS_NO_CALLBACK;
}

// Minifilter unload routine
extern "C" NTSTATUS FilterUnload(FLT_FILTER_UNLOAD_FLAGS Flags) {
    UNREFERENCED_PARAMETER(Flags);
    if (gFilterHandle) {
        FltUnregisterFilter(gFilterHandle);
        gFilterHandle = NULL;
    }
    if (gMonitorDeviceObject) {
        // Dereference the device object
        ObDereferenceObject(gMonitorDeviceObject);
        gMonitorDeviceObject = NULL;
    }
    DbgPrint("FileMonitorFilter: Driver unloaded\n");
    return STATUS_SUCCESS;
}

// Minifilter configuration
CONST FLT_OPERATION_REGISTRATION Callbacks[] = {
    { IRP_MJ_CREATE, 0, FileCreatePreOperation, NULL },
    { IRP_MJ_OPERATION_END }
};

CONST FLT_REGISTRATION FilterRegistration = {
    sizeof(FLT_REGISTRATION),
    FLT_REGISTRATION_VERSION,
    0,
    NULL,
    Callbacks,
    FilterUnload,
    NULL,
    NULL,
    NULL,
    NULL,
    NULL,
    NULL,
    NULL
};

// DriverEntry
extern "C" NTSTATUS DriverEntry(PDRIVER_OBJECT DriverObject, PUNICODE_STRING RegistryPath) {
    UNREFERENCED_PARAMETER(RegistryPath);
    NTSTATUS status;
    UNICODE_STRING monitorDeviceName;
    ULONG retryCount = 0;
    const ULONG maxRetries = 5;

    // Register minifilter
    status = FltRegisterFilter(DriverObject, &FilterRegistration, &gFilterHandle);
    if (!NT_SUCCESS(status)) {
        DbgPrint("FileMonitorFilter: FltRegisterFilter failed: 0x%X\n", status);
        return status;
    }

    // Retry getting MonitorDriver's device object
    RtlInitUnicodeString(&monitorDeviceName, MONITOR_DEVICE_NAME);
    do {
        status = IoGetDeviceObjectPointer(&monitorDeviceName, FILE_WRITE_DATA, NULL, &gMonitorDeviceObject);
        if (NT_SUCCESS(status)) break;
        DbgPrint("FileMonitorFilter: IoGetDeviceObjectPointer failed: 0x%X, retry %u\n", status, retryCount + 1);
        LARGE_INTEGER interval;
        interval.QuadPart = -10000000LL;
        KeDelayExecutionThread(KernelMode, FALSE, &interval); // Wait 1 second
        retryCount++;
    } while (retryCount < maxRetries);

    if (!NT_SUCCESS(status)) {
        DbgPrint("FileMonitorFilter: Failed to get MonitorDeviceObject after retries\n");
        FltUnregisterFilter(gFilterHandle);
        return status;
    }

    // Start filtering
    status = FltStartFiltering(gFilterHandle);
    if (!NT_SUCCESS(status)) {
        DbgPrint("FileMonitorFilter: FltStartFiltering failed: 0x%X\n", status);
        ObDereferenceObject(gMonitorDeviceObject);
        FltUnregisterFilter(gFilterHandle);
        return status;
    }

    DbgPrint("FileMonitorFilter: Driver loaded successfully\n");
    return STATUS_SUCCESS;
}