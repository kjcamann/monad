#pragma once

#include <stddef.h>
#include <stdint.h>
#include <stdio.h>

#include <category/core/srcloc.h>

struct monad_rv_log_observer;

#ifdef __cplusplus
extern "C"
{
#endif

// clang-format off

struct monad_rv_log_entry
{
    uint8_t level;         ///< syslog(3) severity level
    int error;             ///< errno(3) domain code, or zero
    char const *msg;       ///< Formatted log message (null terminated)
    size_t msglen;         ///< Length of formatted message
    monad_source_location_t
        const *srcloc;     ///< Code location where log generated (or null)
};

// clang-format on

typedef int(monad_rv_log_publish_fn)(
    struct monad_rv_log_observer *, struct monad_rv_log_entry const *);

typedef uint8_t(monad_rv_log_max_level_fn)(
    struct monad_rv_log_observer const *);

typedef void(monad_rv_log_flush_fn)(struct monad_rv_log_observer *);

struct monad_rv_log_observer_ops
{
    monad_rv_log_publish_fn *const publish;
    monad_rv_log_max_level_fn *const max_level;
    monad_rv_log_flush_fn *const flush;
};

struct monad_rv_log_observer
{
    struct monad_rv_log_observer_ops const *vtable;
};

[[gnu::always_inline]] static inline int monad_rv_log_publish(
    struct monad_rv_log_observer *const o,
    struct monad_rv_log_entry const *const log)
{
    return o->vtable->publish(o, log);
}

[[gnu::always_inline]] static inline uint8_t
monad_rv_log_max_level(struct monad_rv_log_observer const *const o)
{
    return o->vtable->max_level(o);
}

[[gnu::always_inline]] static inline void
monad_rv_log_flush(struct monad_rv_log_observer *const o)
{
    return o->vtable->flush(o);
}

struct monad_rv_log_file_writer
{
    struct monad_rv_log_observer self;
    FILE *file;
    uint8_t max_level;
};

extern struct monad_rv_log_observer_ops const g_monad_rv_log_file_writer_vtable;

inline void monad_rv_log_file_writer_init(
    struct monad_rv_log_file_writer *o, FILE *file, uint8_t max_level)
{
    o->self.vtable = &g_monad_rv_log_file_writer_vtable;
    o->file = file;
    o->max_level = max_level;
}

#ifdef __cplusplus
} // extern "C"
#endif
