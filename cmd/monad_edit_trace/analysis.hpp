#pragma once

#include <cstddef>
#include <cstdint>
#include <functional>
#include <type_traits>
#include <utility>

enum monad_event_type : uint16_t;
enum monad_trace_flow_type : uint8_t;
struct monad_trace_event;

enum class stack_key : uint64_t
{
};

constexpr stack_key make_stack_key(uint64_t thread_id, uint32_t fiber_id)
{
    if (fiber_id == 0) {
        return static_cast<stack_key>(1UL << 63 | thread_id);
    }
    return static_cast<stack_key>(fiber_id);
}

template <>
struct std::hash<stack_key>
{
    size_t operator()(stack_key k) const noexcept
    {
        return std::hash<std::underlying_type_t<stack_key>>{}(
            std::to_underlying(k));
    }
};

monad_trace_flow_type annotate_flow_type(monad_trace_event const &);

bool event_closes_scope(monad_trace_event const &open_scope, monad_trace_event const &close_scope);
