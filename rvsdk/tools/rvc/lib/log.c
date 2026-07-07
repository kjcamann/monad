#include <stdcountof.h>
#include <stdio.h>

#define SYSLOG_NAMES
#include <syslog.h>

#include <rvc/log.h>

static char const *get_priority_name(unsigned level)
{
    for (size_t i = 0; i < countof(prioritynames); ++i) {
        if (prioritynames[i].c_val == level) {
            return prioritynames[i].c_name;
        }
    }
    return "<unknown>";
}

constexpr uintptr_t SYSLOG_LEVEL_MASK = 0x7;

static inline FILE *get_file_from_context(void const *const log_ctx)
{
    return (FILE *)((uintptr_t)log_ctx & ~SYSLOG_LEVEL_MASK);
}

static inline uint8_t get_syslog_level_from_context(void const *const log_ctx)
{
    return (uint8_t)((uintptr_t)log_ctx & SYSLOG_LEVEL_MASK);
}

static void
file_logger_publish(void *const log_ctx, struct rvc_log_msg const *const msg)
{
    FILE *const file = get_file_from_context(log_ctx);
    uint8_t const level = get_syslog_level_from_context(log_ctx);
    (void)fprintf(file, "[%6s] %s\n", get_priority_name(level), msg->message);
}

static uint8_t file_logger_max_level(void *const log_ctx)
{
    return get_syslog_level_from_context(log_ctx);
}

static void file_logger_flush(void *const log_ctx)
{
    (void)fflush(get_file_from_context(log_ctx));
}

struct rvc_log_interface const g_rvc_file_logger = {
    .publish = file_logger_publish,
    .max_level = file_logger_max_level,
    .flush = file_logger_flush,
};
