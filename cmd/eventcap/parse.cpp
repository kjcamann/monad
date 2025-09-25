#include "parse.hpp"
#include "eventcap.hpp"

#include <algorithm>
#include <cctype>
#include <charconv>
#include <cstddef>
#include <cstdint>
#include <cstring>
#include <expected>
#include <format>
#include <string>
#include <string_view>
#include <system_error>

#include <category/core/assert.h>
#include <category/execution/ethereum/event/exec_event_ctypes.h>

// Grammar:
//
//    ['B'] <begin> ['-' [<end>]]
std::expected<EventCaptureSpec, std::string>
parse_event_capture_spec(std::string_view capture_spec)
{
    EventCaptureSpec ecs{};
    char const *scan = capture_spec.data();
    char const *const end = scan + capture_spec.length();

    MONAD_ASSERT(scan != end, "caller should ensure this");
    if (*scan == 'B') {
        ecs.use_block_number = true;
        ++scan;
    }

    struct std::from_chars_result pr;
    pr = std::from_chars(scan, end, ecs.first_section);
    if (static_cast<int>(pr.ec)) {
        std::error_condition const econd{pr.ec};
        return std::unexpected(std::format(
            "capture spec <begin> token {} could not be parsed: {} [{}]",
            capture_spec,
            econd.message(),
            econd.value()));
    }
    if (pr.ptr == end) {
        // If the user does not explicitly indicate an infinite range with
        // `<start>-` then there is an implicit count of 1
        ecs.count = 1;
        return ecs;
    }
    if (*pr.ptr++ != '-') {
        return std::unexpected(std::format(
            "expected '-' after {} in ranged capture spec {}",
            ecs.first_section,
            capture_spec));
    }
    if (pr.ptr == end) {
        return ecs;
    }
    uint64_t end_value;
    pr = std::from_chars(pr.ptr, end, end_value);
    if (static_cast<int>(pr.ec)) {
        std::error_condition const econd{pr.ec};
        return std::unexpected(std::format(
            "capture spec <end> token {} could not be parsed: {} [{}]",
            pr.ptr,
            econd.message(),
            econd.value()));
    }
    if (pr.ptr != end) {
        return std::unexpected(
            std::format("capture spec <end> token {} is not a number", pr.ptr));
    }
    ecs.count = end_value - ecs.first_section;
    return ecs;
}

// parse_event_source_spec
//
// Grammar:
//
//    [<input-name> ':'] <event-source-file> ['#' <capture-spec>]
//
//  The only required component, <event-source-file>, can be one of four things:
//
//  1. a path to a regular file; this can either be an event ring file (live
//     or compressed snapshot) or an event capture file
//
//  2. a path to a finalized block archive directory
//
//  3. the name of an event ring type (e.g., `exec` or `test`)
//
//  4. the label of a "named input" created by the -i,--input option; this
//     allows multiple subcommands to easily reference the same file path, e.g.:
//
//        eventcap -i foo:/very/long/path dump -e foo info foo
//
// The optional [<name> ':'] component introduces a new named input at the same
// time is it defines a source specification; the named input refers only to
// the file, and not the trailing capture specification
//
// The optional ['#' <capture-spec>] is the "event capture specification"; it
// specifies part of an event capture file or an individual block in the block
// archive
std::expected<ParsedEventSourceSpec, std::string>
parse_event_source_spec(std::string_view event_source_spec)
{
    ParsedEventSourceSpec ess{};
    if (empty(event_source_spec)) {
        return ess;
    }

    // Parse the capture specification if it is present
    auto const hash_index = event_source_spec.find('#');
    if (hash_index != std::string_view::npos) {
        event_source_spec = event_source_spec.substr(0, hash_index);
        ess.capture_spec = event_source_spec.substr(hash_index + 1);
    }

    // <event-source-spec> can introduce a new named input
    auto const colon_index = event_source_spec.find(':');
    if (colon_index != std::string_view::npos) {
        ess.named_input = event_source_spec.substr(0, colon_index);
        ess.event_source_file = event_source_spec.substr(colon_index + 1);
    }
    else {
        ess.event_source_file = event_source_spec;
    }

    return ess;
}

std::expected<BlockLabel, std::string>
parse_block_label(std::string_view block_label)
{
    BlockLabel bl;
    if (block_label.starts_with("0x")) {
        uint8_t block_id[32];
        if (block_label.length() - 2 != sizeof(block_id) * 2) {
            return std::unexpected(std::format(
                "token {} starting with be '0x' must have full 32 byte "
                "block id",
                block_label));
        }
        char const *const start = block_label.data() + 2;
        for (size_t i = 0; i < 32; ++i) {
            if (std::sscanf(start + 2 * i, "%hhx", block_id + i) != 1) {
                return std::unexpected(std::format(
                    "token {} contains non-hex value", block_label));
            }
        }
        bl.type = BlockLabel::Type::BlockId;
        std::memcpy(bl.block_id.data(), block_id, sizeof block_id);
    }
    else {
        bl.type = BlockLabel::Type::BlockNumber;
        char const *const begin = data(block_label);
        char const *const end = begin + size(block_label);
        auto const [ptr, ec] = std::from_chars(begin, end, bl.block_number);
        if (static_cast<int>(ec) || ptr != end) {
            return std::unexpected(std::format(
                "token {} could not be parsable as a block number",
                block_label));
        }
    }
    return bl;
};

std::expected<SequenceNumberSpec, std::string>
parse_sequence_number_spec(std::string_view spec)
{
    SequenceNumberSpec sns = {
        .type = SequenceNumberSpec::Type::Number, .seqno = 0};
    char const *scan = spec.data();
    char const *const end = scan + spec.length();

    if (std::ranges::all_of(spec, [](char c) { return std::isdigit(c); })) {
        auto const [ptr, ec] = std::from_chars(scan, end, sns.seqno);
        if (static_cast<int>(ec)) {
            return std::unexpected(std::format("invalid token {}", spec));
        }
        MONAD_ASSERT(
            ptr == end,
            "all_of(spec, std::isidigit), but still stopped early?");
        return sns;
    }

    MONAD_ASSERT(scan != end, "caller should ensure this");
    sns.type = SequenceNumberSpec::Type::ConsensusEvent;
    switch (scan[0]) {
    case 'E':
        [[fallthrough]];
    case 'P':
        sns.consensus_event.consensus_type = MONAD_EXEC_BLOCK_START;
        break;

    case 'F':
        sns.consensus_event.consensus_type = MONAD_EXEC_BLOCK_FINALIZED;
        break;

    case 'Q':
        sns.consensus_event.consensus_type = MONAD_EXEC_BLOCK_QC;
        break;

    case 'V':
        sns.consensus_event.consensus_type = MONAD_EXEC_BLOCK_VERIFIED;
        break;

    case 'R':
        sns.consensus_event.consensus_type = MONAD_EXEC_NONE;
        break;

    default:
        return std::unexpected(std::format(
            "token character {:c} in {} is not recognized as a consensus event "
            "code",
            scan[0],
            spec));
    }
    ++scan;
    if (scan == end || (scan[1] == ':' && scan + 1 == end)) {
        // No specified block label; will stop at the first related consensus
        // event
        return sns;
    }
    if (*scan == ':') {
        ++scan;
    }
    MONAD_DEBUG_ASSERT(scan != end);
    auto ex_block_label = parse_block_label(
        std::string_view{scan, static_cast<size_t>(end - scan)});
    if (!ex_block_label) {
        return std::unexpected(ex_block_label.error());
    }
    sns.consensus_event.opt_block_label = *ex_block_label;
    return sns;
}
