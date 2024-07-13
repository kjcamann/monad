#pragma once

#include <stdarg.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

struct monad_error {
    void *domain;
    intptr_t value;
};

enum monad_result_flag {
    MONAD_RF_ERROR = 0b1,
};

typedef struct monad_result {
    union
    {
        intptr_t value;
        struct monad_error error;
    };
    unsigned flags;
} monad_result;

[[noreturn]] void monad_diagnose_value_on_error(monad_result mr);

static inline bool monad_is_error(monad_result mr) {
    return mr.flags & MONAD_RF_ERROR;
}

static inline intptr_t monad_value(monad_result mr) {
    if (monad_is_error(mr))
        monad_diagnose_value_on_error(mr);
    return mr.value;
}

static inline monad_result monad_make_sys_error(int e) {
    const monad_result mr = {
        .error = {.domain = nullptr, .value = e},
        .flags = MONAD_RF_ERROR
    };
    return mr;
}

static inline monad_result monad_ok(intptr_t v) {
    const monad_result mr = {
        .value = v,
        .flags = 0,
    };
    return mr;
}

/// An analogue of the BSD errc(3) utility function, but accepting a
/// monad_result (containing an error) rather than an errno code.
[[noreturn]] void mcl_errc(int eval, monad_result mr, const char *fmt, ...);

[[noreturn]] void mcl_verrc(int eval, monad_result mr, const char *fmt,
                            va_list ap);

#ifdef __cplusplus
} // extern "C"
#endif
