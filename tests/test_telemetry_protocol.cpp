#include "telemetry_protocol.h"

#include <cstddef>
#include <cstring>
#include <iostream>
#include <vector>

namespace
{

bool expect(bool condition, const char* message)
{
    if (!condition)
        std::cerr << message << '\n';
    return condition;
}

std::vector<unsigned char> valid_packet()
{
    const size_t offset = offsetof(TASKLET_EVENT_BATCH, Records);
    std::vector<unsigned char> bytes(
        offset + sizeof(TASKLET_EVENT_RECORD));

    TASKLET_EVENT_BATCH header{};
    header.Size = static_cast<TASKLET_U32>(bytes.size());
    header.Version = TASKLET_PROTOCOL_VERSION;
    header.RecordCount = 1;
    header.DroppedRecords = 2;
    header.NextSequence = 12;
    std::memcpy(bytes.data(), &header, offset);

    TASKLET_EVENT_RECORD event{};
    event.Size = sizeof(event);
    event.Version = TASKLET_PROTOCOL_VERSION;
    event.Kind = TaskletThreadStarted;
    event.ProcessId = 50;
    event.ThreadId = 51;
    event.Sequence = 11;
    std::memcpy(bytes.data() + offset, &event, sizeof(event));
    return bytes;
}

} // namespace

int main()
{
    bool passed = true;
    auto bytes = valid_packet();
    tasklet::telemetry::EventBatch batch;

    passed &= expect(
        tasklet::telemetry::decode_event_batch(
            bytes.data(), bytes.size(), batch),
        "valid packet rejected");
    passed &= expect(
        batch.records.size() == 1 &&
            batch.records[0].ThreadId == 51 &&
            batch.dropped_records == 2 &&
            batch.next_sequence == 12,
        "valid packet decoded incorrectly");
    passed &= expect(
        !tasklet::telemetry::decode_event_batch(
            bytes.data(), offsetof(TASKLET_EVENT_BATCH, Records) - 1, batch),
        "truncated header accepted");

    auto wrong_version = valid_packet();
    TASKLET_EVENT_BATCH header{};
    std::memcpy(
        &header,
        wrong_version.data(),
        offsetof(TASKLET_EVENT_BATCH, Records));
    header.Version++;
    std::memcpy(
        wrong_version.data(),
        &header,
        offsetof(TASKLET_EVENT_BATCH, Records));
    passed &= expect(
        !tasklet::telemetry::decode_event_batch(
            wrong_version.data(), wrong_version.size(), batch),
        "unknown protocol version accepted");

    auto unknown_kind = valid_packet();
    TASKLET_EVENT_RECORD event{};
    const size_t offset = offsetof(TASKLET_EVENT_BATCH, Records);
    std::memcpy(&event, unknown_kind.data() + offset, sizeof(event));
    event.Kind = 999;
    std::memcpy(unknown_kind.data() + offset, &event, sizeof(event));
    passed &= expect(
        !tasklet::telemetry::decode_event_batch(
            unknown_kind.data(), unknown_kind.size(), batch),
        "unknown event kind accepted");

    auto oversized_count = valid_packet();
    std::memcpy(&header, oversized_count.data(), offset);
    header.RecordCount = TASKLET_MAX_BATCH_EVENTS + 1;
    std::memcpy(oversized_count.data(), &header, offset);
    passed &= expect(
        !tasklet::telemetry::decode_event_batch(
            oversized_count.data(), oversized_count.size(), batch),
        "oversized record count accepted");

    auto truncated_record = valid_packet();
    std::memcpy(&header, truncated_record.data(), offset);
    header.Size--;
    std::memcpy(truncated_record.data(), &header, offset);
    passed &= expect(
        !tasklet::telemetry::decode_event_batch(
            truncated_record.data(), truncated_record.size(), batch),
        "truncated record accepted");

    auto empty = std::vector<unsigned char>(offset);
    TASKLET_EVENT_BATCH empty_header{};
    empty_header.Size = static_cast<TASKLET_U32>(offset);
    empty_header.Version = TASKLET_PROTOCOL_VERSION;
    empty_header.NextSequence = 1;
    std::memcpy(empty.data(), &empty_header, offset);
    passed &= expect(
        tasklet::telemetry::decode_event_batch(
            empty.data(), empty.size(), batch) && batch.records.empty(),
        "empty batch rejected");

    return passed ? 0 : 1;
}
