#pragma once

#include <stdint.h>

/// Metadata
enum monad_fiber_object_type : unsigned
{
    MONAD_FIBER_TRACE_NONE,
    MONAD_FIBER_TRACE_PRIORITY_POOL,
    MONAD_FIBER_TRACE_DB_WAIT,
    MONAD_FIBER_TRACE_TXN_RECOVERY_SYNC,
    MONAD_FIBER_TRACE_TXN_CAN_MERGE_SYNC,
};

struct monad_fiber_trace_info
{
    void *object;
    enum monad_fiber_object_type type;
    uint64_t extra;
};
