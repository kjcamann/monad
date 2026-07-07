#include <stdcountof.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>

#define SYSLOG_NAMES
#include <syslog.h>

#include <category/rv/rv_log_observer.h>

static char const *get_priority_name(uint8_t level)
{
    for (size_t i = 0; i < countof(prioritynames); ++i) {
        if (prioritynames[i].c_val == level) {
            return prioritynames[i].c_name;
        }
    }
    return "<unknown>";
}

static char const *final_path_component(char const *const path)
{
    char const *last = strrchr(path, '/');
    return last == nullptr ? path : last + 1;
}

static int file_publish(
    struct monad_rv_log_observer *const self,
    struct monad_rv_log_entry const *const log)
{
    int rc;
    struct monad_rv_log_file_writer *const writer =
        (struct monad_rv_log_file_writer *)self;

    rc = fprintf(
        writer->file, "[%6s] %s", get_priority_name(log->level), log->msg);
    if (rc != 0) {
        return rc;
    }
    if (log->error != 0) {
        rc = fprintf(
            writer->file, "; errno: %s (%d)", strerror(log->error), log->error);
        if (rc != 0) {
            return rc;
        }
    }
    if (log->srcloc != nullptr) {
        rc = fprintf(
            writer->file,
            "; source location: %s@%s:%u",
            log->srcloc->function_name,
            final_path_component(log->srcloc->file_name),
            log->srcloc->line);
        if (rc != 0) {
            return rc;
        }
    }
    return fputc('\n', writer->file);
}

static uint8_t file_max_level(struct monad_rv_log_observer const *const self)
{
    struct monad_rv_log_file_writer *const writer =
        (struct monad_rv_log_file_writer *)self;
    return writer->max_level;
}

static void file_flush(struct monad_rv_log_observer *const self)
{
    struct monad_rv_log_file_writer *const writer =
        (struct monad_rv_log_file_writer *)self;
    (void)fflush(writer->file);
}

struct monad_rv_log_observer_ops const g_monad_rv_log_file_writer_vtable = {
    .publish = file_publish,
    .max_level = file_max_level,
    .flush = file_flush,
};

extern void monad_rv_log_file_writer_init(
    struct monad_rv_log_file_writer *, FILE *, uint8_t);
