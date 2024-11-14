#pragma once

#include <monad/config.hpp>
#include <monad/trace/trace.h>

#include <bit>
#include <charconv>
#include <concepts>
#include <cstddef>
#include <cstdint>
#include <type_traits>
#include <utility>

#include <monad/event/event.h>
#include <monad/event/event_recorder.h>

MONAD_NAMESPACE_BEGIN

enum class trace_flow_id : uint64_t {};

template <monad_event_type EventType>
class TraceScopeRAII
{
public:
    explicit TraceScopeRAII()
    {
        MONAD_EVENT(EventType, 0);
    }

    explicit TraceScopeRAII(trace_flow_id flow_id)
    {
        MONAD_EVENT_EXPR(EventType, 0, flow_id);
    }

    ~TraceScopeRAII()
    {
        MONAD_EVENT(EventType, MONAD_EVENT_POP_SCOPE);
    }
};

MONAD_NAMESPACE_END
