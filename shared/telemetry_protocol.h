#pragma once

#ifdef _KERNEL_MODE
#include <ntddk.h>
#define TASKLET_CTL_CODE(function, access) \
    CTL_CODE(FILE_DEVICE_UNKNOWN, (function), METHOD_BUFFERED, (access))
typedef ULONG TASKLET_U32;
typedef ULONGLONG TASKLET_U64;
#else
#include <Windows.h>
#include <winioctl.h>
typedef unsigned long TASKLET_U32;
typedef unsigned __int64 TASKLET_U64;
#define TASKLET_CTL_CODE(function, access) \
    CTL_CODE(FILE_DEVICE_UNKNOWN, (function), METHOD_BUFFERED, (access))
#endif

#define TASKLET_PROTOCOL_VERSION 1
#define TASKLET_MAX_BATCH_EVENTS 64
#define TASKLET_DEVICE_PATH L"\\\\.\\TaskletTelemetry"

#define IOCTL_TASKLET_GET_STATUS \
    TASKLET_CTL_CODE(0x800, FILE_READ_ACCESS)
#define IOCTL_TASKLET_GET_EVENTS \
    TASKLET_CTL_CODE(0x801, FILE_READ_ACCESS)
#define IOCTL_TASKLET_FLUSH_QUEUE \
    TASKLET_CTL_CODE(0x802, FILE_READ_ACCESS | FILE_WRITE_ACCESS)

typedef enum TASKLET_EVENT_KIND
{
    TaskletProcessStarted = 1,
    TaskletProcessExited = 2,
    TaskletThreadStarted = 3,
    TaskletThreadExited = 4,
    TaskletImageLoaded = 5,
    TaskletKernelHeartbeat = 6
} TASKLET_EVENT_KIND;

typedef struct TASKLET_EVENT_RECORD
{
    TASKLET_U32 Size;
    TASKLET_U32 Version;
    TASKLET_U32 Kind;
    TASKLET_U32 ProcessId;
    TASKLET_U32 ParentProcessId;
    TASKLET_U32 ThreadId;
    TASKLET_U64 Sequence;
    TASKLET_U64 InterruptTime100ns;
} TASKLET_EVENT_RECORD;

typedef struct TASKLET_EVENT_BATCH
{
    TASKLET_U32 Size;
    TASKLET_U32 Version;
    TASKLET_U32 RecordCount;
    TASKLET_U32 DroppedRecords;
    TASKLET_U64 NextSequence;
    TASKLET_EVENT_RECORD Records[1];
} TASKLET_EVENT_BATCH;

typedef struct TASKLET_DRIVER_STATUS
{
    TASKLET_U32 Size;
    TASKLET_U32 Version;
    TASKLET_U32 QueuedRecords;
    TASKLET_U32 DroppedRecords;
    TASKLET_U64 NextSequence;
} TASKLET_DRIVER_STATUS;

#ifdef __cplusplus
static_assert(sizeof(TASKLET_EVENT_RECORD) == 40, "wire event layout changed");
static_assert(sizeof(TASKLET_DRIVER_STATUS) == 24, "wire status layout changed");
#endif
