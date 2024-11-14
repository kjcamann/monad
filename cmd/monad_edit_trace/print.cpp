#include <bit>
#include <chrono>
#include <cstddef>
#include <cstdint>
#include <cstdio>
#include <cstring>
#include <format>
#include <memory>
#include <span>
#include <utility>

#include <sysexits.h>

#include "err_cxx.hpp"
#include "print.hpp"
#include "print_compat.hpp"
#include "trace_file_reader.hpp"

#include <monad/event/event.h>
#include <monad/event/event_metadata.h>
#include <monad/event/event_shmem.h>
#include <monad/trace/trace_file.h>

constexpr char const *monad_trace_flow_type_name(monad_trace_flow_type type)
{
    switch (type) {
    case MONAD_TRACE_FLOW_NONE:
        return "NONE";
    case MONAD_TRACE_FLOW_BLOCK:
        return "BLOCK";
    case MONAD_TRACE_FLOW_TXN:
        return "TXN";
    default:
        return "<invalid>";
    }
}

constexpr char const *
monad_trace_scope_action_name(monad_trace_scope_action action)
{
    switch (action) {
    case MONAD_TRACE_SCOPE_NONE:
        return "NONE";
    case MONAD_TRACE_SCOPE_PUSH:
        return "PUSH";
    case MONAD_TRACE_SCOPE_POP:
        return "POP";
    case MONAD_TRACE_SCOPE_UNKNOWN:
        return "UNKNOWN";
    default:
        return "<invalid>";
    }
}

extern void print_trace_event(
    PrintEventOptions const &print_opts, monad_trace_event const &event,
    std::FILE *out)
{
    PrintEventOptions::Context const &ctx = print_opts.context;
    std::chrono::sys_time const event_time{
        std::chrono::nanoseconds{event.epoch_nanos}};
    std::chrono::zoned_time const event_time_tz{
        print_opts.time_zone == nullptr ? std::chrono::current_zone()
                                        : print_opts.time_zone,
        event_time};

    // Print the top line:
    //   [<event-number>'.'] <event-time> ['+'<elapsed>]
    if (print_opts.leading_new_line) {
        std::println(out);
    }
    if (print_opts.leading_indent > 0) {
        std::print(out, "{:{}}", "", print_opts.leading_indent);
    }
    if (print_opts.print_event_index) {
        std::print(out, "{}. ", ctx.event_index);
    }
    std::print(out, "{:%H:%M:%S}", event_time_tz);
    if (ctx.prev_event_time != decltype(ctx.prev_event_time){}) {
        std::print(out, " [+{}]", event_time - ctx.prev_event_time);
    }
    std::println(out);

    auto const print_field =
        [out, leading_indent = print_opts.leading_indent]<typename... Args>(
            char const *field_name,
            std::format_string<Args...>
                fmt,
            Args &&...args) {
            size_t const field_name_len = std::strlen(field_name);
            std::print(
                out,
                "{:{}}{}:{:{}}",
                "",
                leading_indent + 2,
                field_name,
                "",
                field_name_len < 16 ? 16 - field_name_len : 0);
            std::println(out, fmt, std::forward<Args>(args)...);
        };

    auto const [domain_meta, event_meta, matches_static_data] =
        ctx.trace_file->get_event_metadata(event);
    if (domain_meta == nullptr || event_meta == nullptr) {
        errx_f(EX_DATAERR, "event metadata lookup for {} failed",
            std::to_underlying(event.type));
    }
    monad_trace_scope_action scope_action = event.pop_scope
        ? MONAD_TRACE_SCOPE_POP
        : MONAD_TRACE_SCOPE_UNKNOWN;
    if (matches_static_data && !event.pop_scope) {
        scope_action = event_meta->trace_flags & MONAD_EVENT_TRACE_PUSH_SCOPE
            ? MONAD_TRACE_SCOPE_PUSH
            : MONAD_TRACE_SCOPE_NONE;
    }
    print_field(
        "domain",
        "{} [{}]",
        domain_meta->name,
        std::to_underlying(MONAD_EVENT_DOMAIN(event.type)));
    print_field("type",
        "{0} [{1} {1:#x} {2}:{3}]",
        event_meta->c_name,
        std::to_underlying(event.type),
        std::to_underlying(MONAD_EVENT_DOMAIN(event.type)),
        MONAD_EVENT_DRCODE(event.type));
    print_field("seqno", "{}", event.seqno);
    print_field("scope_action", "{}", monad_trace_scope_action_name(scope_action));
    print_field("source_id", "{}", event.source_id);
    print_field("length", "{}", event.length);
    print_field(
        "flow_type",
        "{} [{}]",
        monad_trace_flow_type_name(ctx.flow_type),
        std::to_underlying(ctx.flow_type));
    switch (ctx.flow_type) {
    case MONAD_TRACE_FLOW_TXN:
        print_field(
            "flow_id",
            "B:{} T:{}",
            ctx.flow_id >> 24,
            ctx.flow_id & ((1UL << 24) - 1));
        break;

    case MONAD_TRACE_FLOW_BLOCK:
        print_field("flow_id", "B:{}", ctx.flow_id);
        break;

    default:
        print_field("flow_id", "{}", ctx.flow_id);
        break;
    }
    print_field("fiber_id", "{}", ctx.fiber_id);
    if (ctx.thread_info != nullptr && print_opts.print_thread_info) {
        print_field("thread", "{} [{}]", ctx.thread_info->thread_name,
            ctx.thread_info->thread_id);
    }
    // For the domain that causes the switch to happen, add an extra bit
    // of information
    if (matches_static_data && event.type == MONAD_EVENT_FIBER_SWITCH &&
        scope_action == MONAD_TRACE_SCOPE_PUSH && ctx.thread_info != nullptr &&
        print_opts.print_fiber_switch_details) {
        if (ctx.fiber_id != 0) {
            print_field(
                "fiber sw",
                "thread {} [{}] -> fiber {}",
                ctx.thread_info->thread_name,
                ctx.thread_info->thread_id,
                ctx.fiber_id);
        }
        else {
            print_field(
                "fiber sw",
                "return to thread {} [{}]",
                ctx.thread_info->thread_name,
                ctx.thread_info->thread_id);
        }
    }
    auto *const payload = std::bit_cast<std::byte const *>(&event + 1);
    auto *const payload_end = payload + event.length;
    if (payload != payload_end) {
        char line_buf[80], *p;
        char field_name[24] = "payload";
        for (std::byte const *line = payload; line < payload_end; line += 16) {
            p = line_buf;
            for (uint8_t b = 0; b < 16 && line + b < payload_end; ++b) {
                p = std::format_to(p, "{:02x}", std::to_underlying(line[b]));
                if (b == 7) {
                    *p++ = ' ';  // " " after 8 bytes
                }
            }
            *p++ = '\0';
            print_field(field_name, "{}", line_buf);
            *std::format_to(field_name, "{:#08x}", line + 16 - payload) = '\0';
        }
    }
}
