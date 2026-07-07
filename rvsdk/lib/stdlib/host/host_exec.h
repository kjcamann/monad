#pragma once

#include <evmc/evmc.h>
#include <stddef.h>
#include <stdint.h>

#include <category/core/byteview.h>
#include <category/rv/syscall.h>

#ifdef __cplusplus
extern "C"
{
#endif

// The parameters passed through evmc_execute_fn, plus anything else we need
struct mrv_host_exec_context
{
    struct evmc_vm *vm;
    struct evmc_host_interface const *host;
    struct evmc_host_context *context;
    int64_t gas;
    enum evmc_revision rev;
    struct evmc_message const *msg;
    struct evmc_result last_call_result;
    struct monad_bv code;
    void (*start_symbol)();
};

extern struct mrv_host_exec_context *mrv_get_host_exec_context();

[[noreturn]] extern void
mrv_host_exit(enum monad_rv_exit_type, void const *, size_t);

#ifdef __cplusplus
} // extern "C"
#endif
