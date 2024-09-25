#include <err.h>
#include <errno.h>
#include <getopt.h>
#include <libgen.h>
#include <stdatomic.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <time.h>

#include <sysexits.h>

#include <monad/core/likely.h>
#include <monad/fiber/fiber.h>

// TODO(ken): make constexpr
//   https://github.com/monad-crypto/monad-internal/issues/498
static uintptr_t const KIBI_MASK = (1UL << 10) - 1;
static uint64_t const NANOS_PER_SECOND = 1'000'000'000ULL;

static size_t g_fiber_stack_size = 1UL << 17; // 128 KiB
static time_t g_benchmark_seconds = 10;

// clang-format: off
// @formatter:off
static struct option longopts[] = {
    {.name = "list", .has_arg = 0, .flag = nullptr, .val = 'L'},
    {.name = "stack_shift", .has_arg = 1, .flag = nullptr, .val = 's'},
    {.name = "time", .has_arg = 1, .flag = nullptr, .val = 't'},
    {.name = "help", .has_arg = 1, .flag = nullptr, .val = 'h'},
    {}};
// @formatter:on
// clang-format: on

extern char const *__progname;

static void usage(FILE *out)
{
    fprintf(out, "%s: [-Lh] [-t <sec>] [-s <shift>]\n", __progname);
}

static int64_t to_nanos(struct timespec ts)
{
    return ts.tv_sec * NANOS_PER_SECOND + ts.tv_nsec;
}

static time_t elapsed_nanos(struct timespec start, struct timespec end)
{
    return to_nanos(end) - to_nanos(start);
}

static time_t elapsed_seconds(struct timespec start, struct timespec end)
{
    return elapsed_nanos(start, end) / NANOS_PER_SECOND;
}

#define BENCH_DIE(...)                                                         \
    fprintf(                                                                   \
        stderr,                                                                \
        "FATAL at %s@%s:%d\n",                                                 \
        __PRETTY_FUNCTION__,                                                   \
        basename(__FILE__),                                                    \
        __LINE__);                                                             \
    if (errno == 0) {                                                          \
        errx(1, __VA_ARGS__);                                                  \
    }                                                                          \
    else {                                                                     \
        err(1, __VA_ARGS__);                                                   \
    }

#define CHECK_Z(X)                                                             \
    do {                                                                       \
        if (MONAD_UNLIKELY((X) != 0)) {                                        \
            errno = (X);                                                       \
            BENCH_DIE(#X " != 0");                                             \
        }                                                                      \
    }                                                                          \
    while (0)

#define ASSERT_EQ(X, Y)                                                        \
    do {                                                                       \
        if (MONAD_UNLIKELY((X) != (Y))) {                                      \
            errno = 0;                                                         \
            BENCH_DIE("assert failed: " #X " == " #Y);                         \
        }                                                                      \
    }                                                                          \
    while (0)

struct benchmark;

static void switch_benchmark(struct benchmark const *);

static struct benchmark
{
    char const *name;
    char const *description;
    void (*func)(struct benchmark const *);
} g_bench_table[] = {
    {.name = "switch",
     .description = "performance of fiber context switch",
     .func = switch_benchmark}};

static const struct benchmark *const g_bench_table_end =
    g_bench_table + sizeof(g_bench_table) / sizeof(struct benchmark);

int parse_options(int argc, char **argv)
{
    int ch;
    monad_c_result mcr;

    while ((ch = getopt_long(argc, argv, "s:t:Lh", longopts, nullptr)) != -1) {
        switch (ch) {
        case 'L':
            for (struct benchmark *b = g_bench_table; b != g_bench_table_end;
                 ++b) {
                fprintf(stdout, "%s:\t%s\n", b->name, b->description);
            }
            exit(0);

        case 's':
            mcr = monad_strtonum(optarg, 10, 30);
            if (MONAD_FAILED(mcr)) {
                monad_errc(
                    1, mcr.error, "bad -s|--stack-shift value '%s'", optarg);
            }
            g_fiber_stack_size = 1UL << (unsigned)mcr.value;
            break;

        case 't':
            mcr = monad_strtonum(optarg, 1, 300);
            if (MONAD_FAILED(mcr)) {
                monad_errc(1, mcr.error, "bad -t|--time value '%s'", optarg);
            }
            g_benchmark_seconds = mcr.value;
            break;

        case 'h':
            usage(stdout);
            exit(0);

        case '?':
            [[fallthrough]];
        default:
            usage(stderr);
            exit(EX_USAGE);
        }
    }

    return optind;
}

static monad_c_result yield_forever(monad_fiber_args_t mfa)
{
    atomic_bool *const done = (atomic_bool *)mfa.arg[0];
    uintptr_t y = 0;
    while (!atomic_load_explicit(done, memory_order_relaxed)) {
        monad_fiber_yield(monad_c_make_success(y++));
    }
    return monad_c_make_success(y);
}

static void switch_benchmark(struct benchmark const *self)
{
    monad_fiber_t *fiber;
    monad_fiber_suspend_info_t suspend_info;
    atomic_bool done;
    struct timespec start_time;
    struct timespec now;
    monad_fiber_attr_t fiber_attr = {
        .stack_size = g_fiber_stack_size, .alloc = nullptr};

    CHECK_Z(monad_fiber_create(&fiber_attr, &fiber));
    CHECK_Z(monad_fiber_set_function(
        fiber,
        MONAD_FIBER_PRIO_HIGHEST,
        yield_forever,
        (monad_fiber_args_t){.arg = {(uintptr_t)&done}}));

    atomic_init(&done, false);
    (void)clock_gettime(CLOCK_REALTIME, &start_time);
    do {
        CHECK_Z(monad_fiber_run(fiber, &suspend_info));
        ASSERT_EQ(monad_result_has_value(suspend_info.eval), true);
        if ((suspend_info.eval.value & KIBI_MASK) == 0) {
            // Every 1024 yields, check if it's time to exit
            (void)clock_gettime(CLOCK_REALTIME, &now);
            atomic_store_explicit(
                &done,
                elapsed_seconds(start_time, now) >= g_benchmark_seconds,
                memory_order_release);
        }
    }
    while (!done);

    CHECK_Z(monad_fiber_run(fiber, &suspend_info));
    ASSERT_EQ(MF_SUSPEND_RETURN, suspend_info.suspend_type);
    monad_fiber_destroy(fiber);

    uintptr_t const context_switch_count = suspend_info.eval.value + 1;
    double const nanos_per_switch =
        (double)(g_benchmark_seconds * NANOS_PER_SECOND) /
        (double)context_switch_count;
    fprintf(
        stdout,
        "%s:\tsingle core context switch rate: %lu sw/s, %.1f ns/sw\n",
        self->name,
        context_switch_count / g_benchmark_seconds,
        nanos_per_switch);
}

int main(int argc, char **argv)
{
    char const *pos_arg;
    struct benchmark *bench;
    int next_pos_arg_idx = parse_options(argc, argv);

    if (next_pos_arg_idx == argc) {
        // Not specifying any benchmark runs all of them
        for (bench = g_bench_table; bench != g_bench_table_end; ++bench) {
            bench->func(bench);
            fflush(stdout);
        }
    }
    while (next_pos_arg_idx != argc) {
        // If there are position arguments, run the benchmark named by the
        // argument; run with -L to see a list
        pos_arg = argv[next_pos_arg_idx++];
        for (bench = g_bench_table; bench != g_bench_table_end; ++bench) {
            if (strcmp(pos_arg, bench->name) == 0) {
                bench->func(bench);
                fflush(stdout);
                break;
            }
        }
        if (bench == g_bench_table_end) {
            warnx("benchmark %s not found", pos_arg);
        }
    }

    return 0;
}
