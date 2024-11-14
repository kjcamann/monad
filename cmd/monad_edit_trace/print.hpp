#pragma once

#include <chrono>
#include <cstddef>
#include <cstdint>
#include <cstdio>

class MonadTraceFileReader;
struct monad_trace_event;
struct monad_event_thread_info;
enum monad_trace_flow_type : uint8_t;

struct PrintEventOptions
{
    struct Context
    {
        size_t event_index;
        monad_event_thread_info const *thread_info;
        uint64_t flow_id;
        monad_trace_flow_type flow_type;
        uint32_t fiber_id;
        std::chrono::sys_time<std::chrono::nanoseconds> prev_event_time;
        MonadTraceFileReader const *trace_file;
    } context;

    std::chrono::time_zone const *time_zone;
    bool leading_new_line;
    bool print_event_index;
    bool print_thread_info;
    bool print_fiber_switch_details;
    unsigned leading_indent;
};

extern void print_trace_event(
    PrintEventOptions const &, monad_trace_event const &, std::FILE *);
