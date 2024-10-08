#include <algorithm>
#include <cerrno>
#include <charconv>
#include <chrono>
#include <cstddef>
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <filesystem>
#include <format>
#include <source_location>
#include <string>
#include <string_view>
#include <system_error>
#include <utility>

#include <err.h>
#include <getopt.h>
#include <sysexits.h>

#include <monad/core/c_result.h>
#include <monad/core/likely.h>
#include <monad/fiber/fiber.h>

namespace fs = std::filesystem;
using std::chrono::duration_cast, std::chrono::seconds,
    std::chrono::nanoseconds;

constexpr intptr_t KIBI_MASK = (1L << 10) - 1;

static size_t g_fiber_stack_size = 1UL << 17; // 128 KiB
static auto g_benchmark_seconds = seconds{10};

// clang-format off
static option longopts[] = {
    {.name = "list", .has_arg = 0, .flag = nullptr, .val = 'L'},
    {.name = "stack_shift", .has_arg = 1, .flag = nullptr, .val = 's'},
    {.name = "time", .has_arg = 1, .flag = nullptr, .val = 't'},
    {.name = "help", .has_arg = 1, .flag = nullptr, .val = 'h'},
    {}};
// clang-format on

extern char const *__progname;

static void usage(std::FILE *out)
{
    std::fprintf(out, "%s: [-Lh] [-t <sec>] [-s <shift>]\n", __progname);
}

template <typename... Args>
[[noreturn]] static void bench_die(
    std::source_location const &srcloc, std::format_string<Args...> fmt,
    Args &&...args)
{
    // TODO(ken): should use <print> but we don't have it yet
    std::string s = std::format(
                        "FATAL at {}@{}:{}:{}: ",
                        srcloc.function_name(),
                        fs::path{srcloc.file_name()}.filename().string(),
                        srcloc.line(),
                        srcloc.column()) +
                    std::format(fmt, std::forward<Args>(args)...);
    if (errno == 0) {
        std::error_condition const ec{std::errc(errno)};
        s += std::format(
            ": {} ({}:{})", ec.message(), ec.category().name(), ec.value());
    }
    err(EX_SOFTWARE, "%s", s.c_str());
}

#define CHECK_Z(X)                                                             \
    do {                                                                       \
        if (MONAD_UNLIKELY((X) != 0)) {                                        \
            errno = (X);                                                       \
            bench_die(                                                         \
                std::source_location::current(),                               \
                "expected a zero return value from {}, got {}",                \
                #X,                                                            \
                (X));                                                          \
        }                                                                      \
    }                                                                          \
    while (0)

#define ASSERT_EQ(X, Y)                                                        \
    do {                                                                       \
        if (MONAD_UNLIKELY((X) != (Y))) {                                      \
            errno = 0;                                                         \
            bench_die(                                                         \
                std::source_location::current(),                               \
                "assert failed: {}",                                           \
                #X " == " #Y);                                                 \
        }                                                                      \
    }                                                                          \
    while (0)

struct benchmark;

static void switch_benchmark(benchmark const &);

static struct benchmark
{
    std::string_view name;
    std::string_view description;
    void (*func)(benchmark const &);
} g_bench_table[] = {
    {.name = "switch",
     .description = "performance of fiber context switch",
     .func = switch_benchmark}};

static int parse_options(int argc, char **argv)
{
    int ch;
    std::from_chars_result fcr;
    unsigned opt_uint;

    while ((ch = getopt_long(argc, argv, "s:t:Lh", longopts, nullptr)) != -1) {
        char const *const end_optarg =
            optarg ? optarg + std::strlen(optarg) : nullptr;

        switch (ch) {
        case 'L':
            for (benchmark &b : g_bench_table) {
                std::fprintf(
                    stdout, "%s:\t%s\n", data(b.name), data(b.description));
            }
            std::exit(0);

        case 's':
            fcr = std::from_chars(optarg, end_optarg, g_fiber_stack_size);
            if (fcr.ptr != end_optarg || std::to_underlying(fcr.ec) ||
                g_fiber_stack_size < 10 || g_fiber_stack_size > 30) {
                errx(EX_CONFIG, "bad -s|--stack-shift value '%s'", optarg);
            }
            break;

        case 't':
            fcr = std::from_chars(optarg, end_optarg, opt_uint);
            if (fcr.ptr != end_optarg || std::to_underlying(fcr.ec) ||
                opt_uint == 0 || opt_uint > 3000) {
                errx(EX_CONFIG, "bad -t|--time value '%s'", optarg);
            }
            g_benchmark_seconds = seconds{opt_uint};
            break;

        case 'h':
            usage(stdout);
            exit(0);

        case '?':
            [[fallthrough]];
        default:
            usage(stderr);
            std::exit(EX_USAGE);
        }
    }

    return optind;
}

static monad_c_result yield_forever(monad_fiber_args_t mfa)
{
    auto *const done = (std::atomic<bool> *)mfa.arg[0];
    intptr_t y = 0;
    while (!done->load(std::memory_order::relaxed)) {
        monad_fiber_yield(monad_c_make_success(y++));
    }
    return monad_c_make_success(y);
}

static void switch_benchmark(benchmark const &self)
{
    monad_fiber_t *fiber;
    monad_fiber_suspend_info_t suspend_info;
    std::atomic<bool> done{false};
    monad_fiber_attr_t fiber_attr = {
        .stack_size = g_fiber_stack_size, .alloc = nullptr};

    CHECK_Z(monad_fiber_create(&fiber_attr, &fiber));
    CHECK_Z(monad_fiber_set_function(
        fiber,
        MONAD_FIBER_PRIO_HIGHEST,
        yield_forever,
        (monad_fiber_args_t){.arg = {(uintptr_t)&done}}));

    auto const start_time = std::chrono::system_clock::now();
    do {
        CHECK_Z(monad_fiber_run(fiber, &suspend_info));
        ASSERT_EQ(monad_result_has_value(suspend_info.eval), true);
        if ((suspend_info.eval.value & KIBI_MASK) == 0) {
            // Every 1024 yields, check if it's time to exit
            auto const now = std::chrono::system_clock::now();
            done.store(
                duration_cast<seconds>(now - start_time) >= g_benchmark_seconds,
                std::memory_order::release);
        }
    }
    while (!done);

    CHECK_Z(monad_fiber_run(fiber, &suspend_info));
    ASSERT_EQ(MF_SUSPEND_RETURN, suspend_info.suspend_type);
    monad_fiber_destroy(fiber);

    intptr_t const context_switch_count = suspend_info.eval.value + 1;
    double const nanos_per_switch =
        (double)(duration_cast<nanoseconds>(g_benchmark_seconds).count()) /
        (double)context_switch_count;
    std::fprintf(
        stdout,
        "%s:\tsingle core context switch rate: %lu sw/s, %.1f ns/sw\n",
        data(self.name),
        context_switch_count / g_benchmark_seconds.count(),
        nanos_per_switch);
}

int main(int argc, char **argv)
{
    char const *pos_arg;
    int next_pos_arg_idx = parse_options(argc, argv);

    if (next_pos_arg_idx == argc) {
        // Not specifying any benchmark runs all of them
        for (benchmark &b : g_bench_table) {
            b.func(b);
            std::fflush(stdout);
        }
    }
    while (next_pos_arg_idx != argc) {
        // If there are position arguments, run the benchmark named by the
        // argument; run with -L to see a list
        pos_arg = argv[next_pos_arg_idx++];
        auto const i_bench =
            std::ranges::find(g_bench_table, pos_arg, &benchmark::name);
        if (i_bench != std::end(g_bench_table)) {
            i_bench->func(*i_bench);
            std::fflush(stdout);
        }
        else {
            warnx("benchmark %s not found", pos_arg);
        }
    }

    return 0;
}
