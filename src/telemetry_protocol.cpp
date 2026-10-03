#include "telemetry_protocol.h"

#include <cstring>
#include <limits>

namespace tasklet
{
namespace telemetry
{

bool decode_event_batch(
    const void* buffer,
    size_t buffer_size,
    EventBatch& result)
{
    result = {};
    if (!buffer || buffer_size < offsetof(TASKLET_EVENT_BATCH, Records))
        return false;

    TASKLET_EVENT_BATCH header{};
    std::memcpy(&header, buffer, offsetof(TASKLET_EVENT_BATCH, Records));

    const size_t records_offset = offsetof(TASKLET_EVENT_BATCH, Records);
    const size_t record_size = sizeof(TASKLET_EVENT_RECORD);
    if (header.Size < records_offset ||
        header.Size > buffer_size ||
        header.Version != TASKLET_PROTOCOL_VERSION ||
        header.RecordCount > TASKLET_MAX_BATCH_EVENTS ||
        header.RecordCount >
            ((std::numeric_limits<size_t>::max)() - records_offset) / record_size ||
        records_offset + static_cast<size_t>(header.RecordCount) * record_size >
            header.Size)
    {
        return false;
    }

    result.dropped_records = header.DroppedRecords;
    result.next_sequence = header.NextSequence;
    result.records.resize(header.RecordCount);
    if (!result.records.empty())
    {
        const auto* records = static_cast<const unsigned char*>(buffer) + records_offset;
        std::memcpy(
            result.records.data(),
            records,
            result.records.size() * sizeof(TASKLET_EVENT_RECORD));
    }

    uint64_t previous_sequence = 0;
    for (const auto& record : result.records)
    {
        if (record.Size != sizeof(TASKLET_EVENT_RECORD) ||
            record.Version != TASKLET_PROTOCOL_VERSION ||
            record.Kind < TaskletProcessStarted ||
            record.Kind > TaskletKernelHeartbeat ||
            record.Sequence <= previous_sequence ||
            ((record.Kind == TaskletProcessStarted ||
                record.Kind == TaskletProcessExited) &&
                record.ThreadId != 0) ||
            ((record.Kind == TaskletThreadStarted ||
                record.Kind == TaskletThreadExited) &&
                record.ThreadId == 0))
        {
            result = {};
            return false;
        }
        previous_sequence = record.Sequence;
    }

    if (!result.records.empty() &&
        result.next_sequence <= result.records.back().Sequence)
    {
        result = {};
        return false;
    }

    return true;
}

} // namespace telemetry
} // namespace tasklet
