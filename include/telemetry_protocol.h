#pragma once

#include "../shared/telemetry_protocol.h"

#include <cstddef>
#include <cstdint>
#include <vector>

namespace tasklet
{
namespace telemetry
{

struct EventBatch
{
    uint32_t dropped_records = 0;
    uint64_t next_sequence = 0;
    std::vector<TASKLET_EVENT_RECORD> records;
};

bool decode_event_batch(
    const void* buffer,
    size_t buffer_size,
    EventBatch& result);

} // namespace telemetry
} // namespace tasklet
