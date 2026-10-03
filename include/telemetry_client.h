#pragma once

#include "telemetry_protocol.h"

#include <atomic>
#include <mutex>
#include <string>
#include <thread>
#include <vector>

namespace tasklet
{

struct TelemetrySnapshot
{
    bool connected = false;
    DWORD last_error = ERROR_SUCCESS;
    std::wstring status = L"Driver telemetry: searching";
    std::vector<TASKLET_EVENT_RECORD> events;
    uint32_t dropped_records = 0;
};

class TelemetryClient
{
public:
    TelemetryClient() = default;
    ~TelemetryClient();

    TelemetryClient(const TelemetryClient&) = delete;
    TelemetryClient& operator=(const TelemetryClient&) = delete;

    void start();
    void stop();
    TelemetrySnapshot take_snapshot();

private:
    void run();
    void publish_status(bool connected, DWORD error, const std::wstring& custom_status = L"");
    void append_events(const telemetry::EventBatch& batch);

    std::atomic<bool> stopping_{ false };
    std::thread worker_;
    std::mutex mutex_;
    TelemetrySnapshot snapshot_;
};

} // namespace tasklet
