#include <chrono>
#include <iterator>
#include <string>
#include <string_view>

#include <sys/socket.h>

#include "blockcapd.hpp"

namespace
{

enum class MetricType
{
    Counter,
    Gauge,
    Histogram,
    Summary,
    Untyped,
};

constexpr std::string_view describe(MetricType type)
{
    using enum MetricType;
    switch (type) {
    case Counter:
        return "counter";
    case Gauge:
        return "gauge";
    case Histogram:
        return "histogram";
    case Summary:
        return "summary";
    case Untyped:
        [[fallthrough]];
    default:
        return "untyped";
    }
}

struct MetricInfo
{
    std::string_view base_name;
    std::string_view description;
    MetricType type;
    uint64_t BlockCapMetrics::*value;
};

constexpr MetricInfo MetricInfoTable[] = {
    {
        .base_name = "sessions_total",
        .description =
            "Number of times blockcapd has reconnected to exec daemon",
        .type = MetricType::Counter,
        .value = &BlockCapMetrics::sessions_total,
    },
    {
        .base_name = "blocks_total",
        .description = "Number of blocks captured in daemon's lifetime",
        .type = MetricType::Counter,
        .value = &BlockCapMetrics::num_blocks_written,
    },
    {
        .base_name = "executed_proposals_total",
        .description = "Number of block proposals executed (not necessarily "
                       "finalized or successfully written to disk)",
        .type = MetricType::Counter,
        .value = &BlockCapMetrics::executed_proposals_total,
    },
    {
        .base_name = "last_block_number",
        .description = "Most recently written finalized block",
        .type = MetricType::Gauge,
        .value = &BlockCapMetrics::last_block_number,
    },
    {
        .base_name = "events_total",
        .description = "Number of execution events processed across all blocks",
        .type = MetricType::Counter,
        .value = &BlockCapMetrics::events_total,
    },
    {
        .base_name = "missing_ranges_total",
        .description = "Total number of missing ranges",
        .type = MetricType::Counter,
        .value = &BlockCapMetrics::missing_ranges_total,
    },
    {
        .base_name = "missing_range_size_total",
        .description = "Total number of blocks across all missing ranges",
        .type = MetricType::Gauge,
        .value = &BlockCapMetrics::missing_range_size_total,
    },
    {
        .base_name = "last_missing_range_start_block_number",
        .description = "First block in the most recent missing block range",
        .type = MetricType::Gauge,
        .value = &BlockCapMetrics::last_missing_range_start_block_number,
    },
    {
        .base_name = "last_missing_range_size",
        .description = "Size of the most recent missing block range",
        .type = MetricType::Gauge,
        .value = &BlockCapMetrics::last_missing_range_size,
    },
    {
        .base_name = "captured_bytes_uncompressed",
        .description =
            "Total number of bytes in the event and seqno index sections",
        .type = MetricType::Gauge,
        .value = &BlockCapMetrics::captured_bytes_uncompressed,
    },
    {
        .base_name = "captured_bytes_compressed",
        .description =
            "Same as captured_bytes_uncompressed, but after zstd compression",
        .type = MetricType::Gauge,
        .value = &BlockCapMetrics::captured_bytes_compressed,
    },
    {
        .base_name = "active_session_pid",
        .description = "pid of the execution daemon, zero if disconnected",
        .type = MetricType::Gauge,
        .value = &BlockCapMetrics::active_session_pid,
    },
};

std::string format_metrics(BlockCapMetrics const *metrics)
{
    using namespace std::chrono;
    std::string s;
    s.reserve(1UL << 12);
    std::back_insert_iterator const i = std::back_inserter(s);

    time_point const now = system_clock::now();
    milliseconds const epoch_millis =
        duration_cast<milliseconds>(now.time_since_epoch());
    for (MetricInfo const &mi : MetricInfoTable) {
        std::format_to(
            i, "# HELP monad_blockcapd_{} {}\n", mi.base_name, mi.description);
        std::format_to(
            i,
            "# TYPE monad_blockcapd_{} {}\n",
            mi.base_name,
            describe(mi.type));
        std::format_to(
            i,
            "monad_blockcapd_{} {} {}\n",
            mi.base_name,
            metrics->*mi.value,
            epoch_millis.count());
    }
    return s;
}

} // End of anonymous namespace

void scrape_metrics(int sock_fd, BlockCapMetrics const *metrics)
{
    std::string const s = format_metrics(metrics);
    if (send(sock_fd, s.data(), s.length(), 0) == -1) {
        BCD_ERR("metrics send failed with errno {}", errno);
    }
    g_scrape_signaled = 0;
}
