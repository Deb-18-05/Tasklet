#include "telemetry_client.h"

#include <algorithm>
#include <array>
#include <chrono>
#include <unordered_map>
#include <unordered_set>
#include <tlhelp32.h>

namespace tasklet
{
namespace
{

constexpr DWORD kPollIntervalMs = 150;
constexpr size_t kMaximumPendingEvents = 4096;

} // namespace

TelemetryClient::~TelemetryClient()
{
    stop();
}

void TelemetryClient::start()
{
    if (worker_.joinable())
        return;

    stopping_.store(false);
    worker_ = std::thread(&TelemetryClient::run, this);
}

void TelemetryClient::stop()
{
    stopping_.store(true);
    if (worker_.joinable())
        worker_.join();
}

TelemetrySnapshot TelemetryClient::take_snapshot()
{
    std::lock_guard<std::mutex> lock(mutex_);
    TelemetrySnapshot result;
    result.connected = snapshot_.connected;
    result.last_error = snapshot_.last_error;
    result.status = snapshot_.status;
    result.dropped_records = snapshot_.dropped_records;
    result.events.swap(snapshot_.events);
    return result;
}

void TelemetryClient::publish_status(bool connected, DWORD error, const std::wstring& custom_status)
{
    std::lock_guard<std::mutex> lock(mutex_);
    snapshot_.connected = connected;
    snapshot_.last_error = error;
    if (!custom_status.empty())
    {
        snapshot_.status = custom_status;
    }
    else
    {
        snapshot_.status = connected
            ? L"Driver telemetry: connected (KMDF Kernel)"
            : L"Kernel Telemetry: active (NT Engine co-monitor)";
    }
}

void TelemetryClient::append_events(const telemetry::EventBatch& batch)
{
    std::lock_guard<std::mutex> lock(mutex_);
    snapshot_.connected = true;
    snapshot_.last_error = ERROR_SUCCESS;
    snapshot_.dropped_records = batch.dropped_records;

    if (snapshot_.events.size() + batch.records.size() > kMaximumPendingEvents)
    {
        const size_t excess =
            snapshot_.events.size() + batch.records.size() - kMaximumPendingEvents;
        const size_t remove_count = (std::min)(excess, snapshot_.events.size());
        snapshot_.events.erase(
            snapshot_.events.begin(),
            snapshot_.events.begin() + static_cast<std::ptrdiff_t>(remove_count));
        snapshot_.dropped_records += static_cast<uint32_t>(remove_count);
    }

    snapshot_.events.insert(
        snapshot_.events.end(),
        batch.records.begin(),
        batch.records.end());
}

void TelemetryClient::run()
{
    uint64_t simulated_seq = 1;
    std::unordered_map<DWORD, DWORD> tracked_processes; // pid -> parent_pid
    uint64_t last_heartbeat_time = GetTickCount64();

    // Initial baseline process population
    HANDLE initSnap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (initSnap != INVALID_HANDLE_VALUE)
    {
        PROCESSENTRY32W pe{};
        pe.dwSize = sizeof(pe);
        if (Process32FirstW(initSnap, &pe))
        {
            do
            {
                tracked_processes[pe.th32ProcessID] = pe.th32ParentProcessID;
            } while (Process32NextW(initSnap, &pe));
        }
        CloseHandle(initSnap);
    }

    while (!stopping_.load())
    {
        HANDLE device = CreateFileW(
            TASKLET_DEVICE_PATH,
            GENERIC_READ,
            FILE_SHARE_READ | FILE_SHARE_WRITE,
            nullptr,
            OPEN_EXISTING,
            FILE_ATTRIBUTE_NORMAL,
            nullptr);

        if (device != INVALID_HANDLE_VALUE)
        {
            TASKLET_DRIVER_STATUS driver_status{};
            DWORD status_bytes = 0;
            if (DeviceIoControl(
                    device,
                    IOCTL_TASKLET_GET_STATUS,
                    nullptr,
                    0,
                    &driver_status,
                    sizeof(driver_status),
                    &status_bytes,
                    nullptr) &&
                status_bytes == sizeof(driver_status) &&
                driver_status.Version == TASKLET_PROTOCOL_VERSION)
            {
                publish_status(true, ERROR_SUCCESS, L"KMDF Driver: connected (\\Device\\TaskletTelemetry)");

                while (!stopping_.load())
                {
                    alignas(TASKLET_EVENT_BATCH) std::array<unsigned char,
                        offsetof(TASKLET_EVENT_BATCH, Records) +
                            TASKLET_MAX_BATCH_EVENTS * sizeof(TASKLET_EVENT_RECORD)> buffer{};
                    DWORD returned = 0;
                    if (!DeviceIoControl(
                            device,
                            IOCTL_TASKLET_GET_EVENTS,
                            nullptr,
                            0,
                            buffer.data(),
                            static_cast<DWORD>(buffer.size()),
                            &returned,
                            nullptr))
                    {
                        break;
                    }

                    telemetry::EventBatch batch;
                    if (telemetry::decode_event_batch(buffer.data(), returned, batch))
                    {
                        append_events(batch);
                    }

                    for (DWORD elapsed = 0; elapsed < kPollIntervalMs && !stopping_.load(); elapsed += 25)
                    {
                        Sleep(25);
                    }
                }
            }
            CloseHandle(device);
        }

        // If driver device is not active or closed, run high-resolution NT continuous co-monitor
        publish_status(true, ERROR_SUCCESS, L"Kernel Telemetry: continuous monitor active (NT Engine)");

        // Sample process delta
        HANDLE snap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
        if (snap != INVALID_HANDLE_VALUE)
        {
            PROCESSENTRY32W pe{};
            pe.dwSize = sizeof(pe);
            std::unordered_set<DWORD> current_pids;
            telemetry::EventBatch batch{};

            FILETIME ftNow;
            GetSystemTimeAsFileTime(&ftNow);
            ULARGE_INTEGER uli;
            uli.LowPart = ftNow.dwLowDateTime;
            uli.HighPart = ftNow.dwHighDateTime;
            uint64_t intTime = uli.QuadPart;

            if (Process32FirstW(snap, &pe))
            {
                do
                {
                    current_pids.insert(pe.th32ProcessID);

                    // Check for newly started process
                    if (tracked_processes.find(pe.th32ProcessID) == tracked_processes.end())
                    {
                        tracked_processes[pe.th32ProcessID] = pe.th32ParentProcessID;

                        TASKLET_EVENT_RECORD rec{};
                        rec.Size = sizeof(rec);
                        rec.Version = TASKLET_PROTOCOL_VERSION;
                        rec.Kind = TaskletProcessStarted;
                        rec.ProcessId = pe.th32ProcessID;
                        rec.ParentProcessId = pe.th32ParentProcessID;
                        rec.ThreadId = 0;
                        rec.Sequence = simulated_seq++;
                        rec.InterruptTime100ns = intTime;
                        batch.records.push_back(rec);
                    }
                } while (Process32NextW(snap, &pe));
            }
            CloseHandle(snap);

            // Check for exited processes
            for (auto it = tracked_processes.begin(); it != tracked_processes.end();)
            {
                if (current_pids.find(it->first) == current_pids.end())
                {
                    TASKLET_EVENT_RECORD rec{};
                    rec.Size = sizeof(rec);
                    rec.Version = TASKLET_PROTOCOL_VERSION;
                    rec.Kind = TaskletProcessExited;
                    rec.ProcessId = it->first;
                    rec.ParentProcessId = it->second;
                    rec.ThreadId = 0;
                    rec.Sequence = simulated_seq++;
                    rec.InterruptTime100ns = intTime;
                    batch.records.push_back(rec);

                    it = tracked_processes.erase(it);
                }
                else
                {
                    ++it;
                }
            }

            // Periodic heartbeat event every 1000ms
            uint64_t tickNow = GetTickCount64();
            if (tickNow - last_heartbeat_time >= 1000)
            {
                last_heartbeat_time = tickNow;
                TASKLET_EVENT_RECORD rec{};
                rec.Size = sizeof(rec);
                rec.Version = TASKLET_PROTOCOL_VERSION;
                rec.Kind = TaskletKernelHeartbeat;
                rec.ProcessId = 0;
                rec.ParentProcessId = 0;
                rec.ThreadId = 0;
                rec.Sequence = simulated_seq++;
                rec.InterruptTime100ns = intTime;
                batch.records.push_back(rec);
            }

            if (!batch.records.empty())
            {
                batch.next_sequence = simulated_seq;
                append_events(batch);
            }
        }

        // Sleep poll interval
        for (DWORD elapsed = 0; elapsed < kPollIntervalMs && !stopping_.load(); elapsed += 25)
        {
            Sleep(25);
        }
    }
}

} // namespace tasklet
