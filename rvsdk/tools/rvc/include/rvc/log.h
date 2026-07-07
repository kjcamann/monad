#pragma once

#include <stddef.h>
#include <stdint.h>
#include <stdio.h>

struct rvc_log_msg
{
    uint8_t syslog_level;
    char const *message;
};

typedef void(rvc_log_publish_fn)(void *, struct rvc_log_msg const *);

typedef uint8_t(rvc_log_get_max_level_fn)(void *);

typedef void(rvc_log_flush_fn)(void *);

struct rvc_log_interface
{
    rvc_log_publish_fn *publish;
    rvc_log_get_max_level_fn *max_level;
    rvc_log_flush_fn *flush;
};

__attribute__((visibility(
    "default"))) extern struct rvc_log_interface const g_rvc_file_logger;

/// A simple logger that works without adding a new log consumer type; the
/// `log_ctx` parameter is assumed to be a standard C I/O stream (i.e., a
/// `FILE *`) with the bottom three unused bits of the pointer storing the
/// maximum syslog severity level to publish
static inline void *rvc_create_file_logger_ctx(FILE *f, uint8_t syslog_level)
{
    return (void *)((uintptr_t)f | syslog_level);
}
