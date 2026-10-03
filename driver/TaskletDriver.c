#include <ntddk.h>
#include <wdf.h>

#include "../shared/telemetry_protocol.h"

#define TASKLET_QUEUE_CAPACITY 1024

static const WCHAR g_DeviceNameBuffer[] = L"\\Device\\TaskletTelemetry";
static const WCHAR g_SymbolicLinkBuffer[] = L"\\DosDevices\\TaskletTelemetry";

static WDFDRIVER g_Driver;
static WDFDEVICE g_Device;
static KSPIN_LOCK g_EventLock;
static TASKLET_EVENT_RECORD g_Events[TASKLET_QUEUE_CAPACITY];
static ULONG g_EventHead;
static ULONG g_EventCount;
static ULONG g_DroppedRecords;
static ULONGLONG g_NextSequence = 1;
static BOOLEAN g_ProcessCallbackRegistered;
static BOOLEAN g_ThreadCallbackRegistered;
static BOOLEAN g_ImageCallbackRegistered;

static KTIMER g_HeartbeatTimer;
static KDPC g_HeartbeatDpc;
static BOOLEAN g_HeartbeatTimerActive;

static VOID TaskletQueueEvent(
    TASKLET_EVENT_KIND kind,
    HANDLE processId,
    HANDLE parentProcessId,
    HANDLE threadId)
{
    KIRQL oldIrql;
    TASKLET_EVENT_RECORD event;

    RtlZeroMemory(&event, sizeof(event));
    event.Size = sizeof(event);
    event.Version = TASKLET_PROTOCOL_VERSION;
    event.Kind = (TASKLET_U32)kind;
    event.ProcessId = HandleToULong(processId);
    event.ParentProcessId = HandleToULong(parentProcessId);
    event.ThreadId = HandleToULong(threadId);
    event.InterruptTime100ns = KeQueryInterruptTime();

    KeAcquireSpinLock(&g_EventLock, &oldIrql);
    event.Sequence = g_NextSequence++;

    if (g_EventCount == TASKLET_QUEUE_CAPACITY)
    {
        g_EventHead = (g_EventHead + 1) % TASKLET_QUEUE_CAPACITY;
        --g_EventCount;
        ++g_DroppedRecords;
    }

    {
        ULONG tail = (g_EventHead + g_EventCount) % TASKLET_QUEUE_CAPACITY;
        g_Events[tail] = event;
        ++g_EventCount;
    }

    KeReleaseSpinLock(&g_EventLock, oldIrql);
}

static VOID TaskletProcessNotify(
    PEPROCESS process,
    HANDLE processId,
    PPS_CREATE_NOTIFY_INFO createInfo)
{
    UNREFERENCED_PARAMETER(process);
    TaskletQueueEvent(
        createInfo ? TaskletProcessStarted : TaskletProcessExited,
        processId,
        createInfo ? createInfo->ParentProcessId : NULL,
        NULL);
}

static VOID TaskletThreadNotify(
    HANDLE processId,
    HANDLE threadId,
    BOOLEAN create)
{
    TaskletQueueEvent(
        create ? TaskletThreadStarted : TaskletThreadExited,
        processId,
        NULL,
        threadId);
}

static VOID TaskletImageNotify(
    PUNICODE_STRING fullImageName,
    HANDLE processId,
    PIMAGE_INFO imageInfo)
{
    UNREFERENCED_PARAMETER(fullImageName);
    UNREFERENCED_PARAMETER(imageInfo);

    TaskletQueueEvent(
        TaskletImageLoaded,
        processId,
        NULL,
        NULL);
}

static VOID TaskletHeartbeatDpcRoutine(
    PKDPC dpc,
    PVOID deferredContext,
    PVOID systemArgument1,
    PVOID systemArgument2)
{
    UNREFERENCED_PARAMETER(dpc);
    UNREFERENCED_PARAMETER(deferredContext);
    UNREFERENCED_PARAMETER(systemArgument1);
    UNREFERENCED_PARAMETER(systemArgument2);

    TaskletQueueEvent(
        TaskletKernelHeartbeat,
        NULL,
        NULL,
        NULL);
}

static VOID TaskletCompleteRequest(
    WDFREQUEST request,
    NTSTATUS status,
    ULONG_PTR information)
{
    WdfRequestCompleteWithInformation(request, status, information);
}

static VOID TaskletEvtIoDeviceControl(
    WDFQUEUE queue,
    WDFREQUEST request,
    size_t outputBufferLength,
    size_t inputBufferLength,
    ULONG ioControlCode)
{
    NTSTATUS status;
    PVOID outputBuffer = NULL;
    size_t outputLength = 0;

    UNREFERENCED_PARAMETER(queue);

    if (inputBufferLength != 0)
    {
        TaskletCompleteRequest(request, STATUS_INVALID_PARAMETER, 0);
        return;
    }
    UNREFERENCED_PARAMETER(outputBufferLength);

    if (ioControlCode == IOCTL_TASKLET_FLUSH_QUEUE)
    {
        KIRQL oldIrql;
        KeAcquireSpinLock(&g_EventLock, &oldIrql);
        g_EventHead = 0;
        g_EventCount = 0;
        KeReleaseSpinLock(&g_EventLock, oldIrql);
        TaskletCompleteRequest(request, STATUS_SUCCESS, 0);
        return;
    }

    if (ioControlCode != IOCTL_TASKLET_GET_STATUS &&
        ioControlCode != IOCTL_TASKLET_GET_EVENTS)
    {
        TaskletCompleteRequest(request, STATUS_INVALID_DEVICE_REQUEST, 0);
        return;
    }

    status = WdfRequestRetrieveOutputBuffer(
        request,
        ioControlCode == IOCTL_TASKLET_GET_STATUS
            ? sizeof(TASKLET_DRIVER_STATUS)
            : FIELD_OFFSET(TASKLET_EVENT_BATCH, Records) +
                sizeof(TASKLET_EVENT_RECORD),
        &outputBuffer,
        &outputLength);
    if (!NT_SUCCESS(status))
    {
        TaskletCompleteRequest(request, status, 0);
        return;
    }

    if (ioControlCode == IOCTL_TASKLET_GET_STATUS)
    {
        TASKLET_DRIVER_STATUS* result = (TASKLET_DRIVER_STATUS*)outputBuffer;
        KIRQL oldIrql;

        KeAcquireSpinLock(&g_EventLock, &oldIrql);
        result->Size = sizeof(*result);
        result->Version = TASKLET_PROTOCOL_VERSION;
        result->QueuedRecords = g_EventCount;
        result->DroppedRecords = g_DroppedRecords;
        result->NextSequence = g_NextSequence;
        KeReleaseSpinLock(&g_EventLock, oldIrql);

        TaskletCompleteRequest(request, STATUS_SUCCESS, sizeof(*result));
        return;
    }

    {
        const size_t headerSize = FIELD_OFFSET(TASKLET_EVENT_BATCH, Records);
        size_t capacity = (outputLength - headerSize) /
            sizeof(TASKLET_EVENT_RECORD);
        ULONG copied = 0;
        KIRQL oldIrql;
        TASKLET_EVENT_BATCH* result = (TASKLET_EVENT_BATCH*)outputBuffer;

        if (capacity > TASKLET_MAX_BATCH_EVENTS)
            capacity = TASKLET_MAX_BATCH_EVENTS;

        KeAcquireSpinLock(&g_EventLock, &oldIrql);
        while (copied < capacity && g_EventCount != 0)
        {
            ULONG index = (g_EventHead + copied) % TASKLET_QUEUE_CAPACITY;
            result->Records[copied] = g_Events[index];
            ++copied;
        }

        g_EventHead = (g_EventHead + copied) % TASKLET_QUEUE_CAPACITY;
        g_EventCount -= copied;

        result->Size = (TASKLET_U32)(
            headerSize + copied * sizeof(TASKLET_EVENT_RECORD));
        result->Version = TASKLET_PROTOCOL_VERSION;
        result->RecordCount = copied;
        result->DroppedRecords = g_DroppedRecords;
        result->NextSequence = g_NextSequence;
        KeReleaseSpinLock(&g_EventLock, oldIrql);

        TaskletCompleteRequest(request, STATUS_SUCCESS, result->Size);
    }
}

static VOID TaskletEvtDriverUnload(WDFDRIVER driver)
{
    UNREFERENCED_PARAMETER(driver);

    if (g_HeartbeatTimerActive)
    {
        KeCancelTimer(&g_HeartbeatTimer);
        g_HeartbeatTimerActive = FALSE;
    }

    if (g_ImageCallbackRegistered)
    {
        PsRemoveLoadImageNotifyRoutine(TaskletImageNotify);
        g_ImageCallbackRegistered = FALSE;
    }

    if (g_ThreadCallbackRegistered)
    {
        PsRemoveCreateThreadNotifyRoutine(TaskletThreadNotify);
        g_ThreadCallbackRegistered = FALSE;
    }

    if (g_ProcessCallbackRegistered)
    {
        PsSetCreateProcessNotifyRoutineEx(TaskletProcessNotify, TRUE);
        g_ProcessCallbackRegistered = FALSE;
    }

    if (g_Device)
    {
        WdfObjectDelete(g_Device);
        g_Device = NULL;
    }
}

NTSTATUS DriverEntry(
    PDRIVER_OBJECT driverObject,
    PUNICODE_STRING registryPath)
{
    NTSTATUS status;
    WDF_DRIVER_CONFIG driverConfig;
    WDF_OBJECT_ATTRIBUTES driverAttributes;
    WDF_OBJECT_ATTRIBUTES deviceAttributes;
    WDF_IO_QUEUE_CONFIG queueConfig;
    WDFDEVICE_INIT* deviceInit;
    UNICODE_STRING sddl;
    UNICODE_STRING deviceName;
    UNICODE_STRING symbolicLink;
    LARGE_INTEGER dueTime;

    KeInitializeSpinLock(&g_EventLock);
    RtlInitUnicodeString(&sddl, L"D:P(A;;GA;;;SY)(A;;GR;;;BA)");

    WDF_DRIVER_CONFIG_INIT(&driverConfig, WDF_NO_EVENT_CALLBACK);
    driverConfig.DriverInitFlags = WdfDriverInitNonPnpDriver;
    driverConfig.EvtDriverUnload = TaskletEvtDriverUnload;
    WDF_OBJECT_ATTRIBUTES_INIT(&driverAttributes);

    status = WdfDriverCreate(
        driverObject,
        registryPath,
        &driverAttributes,
        &driverConfig,
        &g_Driver);
    if (!NT_SUCCESS(status))
        return status;

    deviceInit = WdfControlDeviceInitAllocate(g_Driver, &sddl);
    if (!deviceInit)
        return STATUS_INSUFFICIENT_RESOURCES;

    RtlInitUnicodeString(&deviceName, g_DeviceNameBuffer);
    status = WdfDeviceInitAssignName(deviceInit, &deviceName);
    if (!NT_SUCCESS(status))
    {
        WdfDeviceInitFree(deviceInit);
        return status;
    }

    WdfDeviceInitSetDeviceType(deviceInit, FILE_DEVICE_UNKNOWN);
    WdfDeviceInitSetCharacteristics(deviceInit, FILE_DEVICE_SECURE_OPEN, FALSE);
    WDF_OBJECT_ATTRIBUTES_INIT(&deviceAttributes);

    status = WdfDeviceCreate(&deviceInit, &deviceAttributes, &g_Device);
    if (!NT_SUCCESS(status))
    {
        if (deviceInit)
            WdfDeviceInitFree(deviceInit);
        return status;
    }

    RtlInitUnicodeString(&symbolicLink, g_SymbolicLinkBuffer);
    status = WdfDeviceCreateSymbolicLink(g_Device, &symbolicLink);
    if (!NT_SUCCESS(status))
    {
        WdfObjectDelete(g_Device);
        g_Device = NULL;
        return status;
    }

    WDF_IO_QUEUE_CONFIG_INIT_DEFAULT_QUEUE(
        &queueConfig,
        WdfIoQueueDispatchSequential);
    queueConfig.EvtIoDeviceControl = TaskletEvtIoDeviceControl;
    queueConfig.PowerManaged = WdfFalse;
    status = WdfIoQueueCreate(
        g_Device,
        &queueConfig,
        WDF_NO_OBJECT_ATTRIBUTES,
        WDF_NO_HANDLE);
    if (!NT_SUCCESS(status))
    {
        WdfObjectDelete(g_Device);
        g_Device = NULL;
        return status;
    }

    status = PsSetCreateProcessNotifyRoutineEx(TaskletProcessNotify, FALSE);
    if (!NT_SUCCESS(status))
    {
        WdfObjectDelete(g_Device);
        g_Device = NULL;
        return status;
    }
    g_ProcessCallbackRegistered = TRUE;

    status = PsSetCreateThreadNotifyRoutine(TaskletThreadNotify);
    if (!NT_SUCCESS(status))
    {
        PsSetCreateProcessNotifyRoutineEx(TaskletProcessNotify, TRUE);
        g_ProcessCallbackRegistered = FALSE;
        WdfObjectDelete(g_Device);
        g_Device = NULL;
        return status;
    }
    g_ThreadCallbackRegistered = TRUE;

    status = PsSetLoadImageNotifyRoutine(TaskletImageNotify);
    if (NT_SUCCESS(status))
    {
        g_ImageCallbackRegistered = TRUE;
    }

    // Initialize 1000ms periodic heartbeat timer
    KeInitializeTimer(&g_HeartbeatTimer);
    KeInitializeDpc(&g_HeartbeatDpc, TaskletHeartbeatDpcRoutine, NULL);
    dueTime.QuadPart = -10000000LL; // 1 second relative
    KeSetTimerEx(&g_HeartbeatTimer, dueTime, 1000, &g_HeartbeatDpc);
    g_HeartbeatTimerActive = TRUE;

    WdfControlFinishInitializing(g_Device);
    return STATUS_SUCCESS;
}
