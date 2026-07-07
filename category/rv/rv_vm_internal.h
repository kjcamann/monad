#pragma once

#include <pthread.h>
#include <sys/queue.h>
#include <syslog.h>

#include <category/rv/rv_link_map.h>
#include <category/rv/rv_vm.h>

#include "rvi_log_writer.h"
#include "rvi_zstd.h"

#define VM_ERR(ERR, ...)                                                       \
    (void)RVI_LOG_WRITE(vm->log_wr, LOG_ERR, (ERR), __VA_ARGS__), (ERR)
#define VM_ERRX(...) RVI_LOG_WRITE(vm->log_wr, LOG_ERR, 0, __VA_ARGS__)
#define VM_DEBUG(...) RVI_LOG_WRITE(vm->log_wr, LOG_DEBUG, 0, __VA_ARGS__)

struct monad_rv_zstd_decomp;
struct rvi_code_cache;
struct rvi_dynlink;

struct monad_rv_vm_ctx
{
    struct monad_rv_vm *vm;
    struct rvi_zstd_decomp decomp;
    SLIST_ENTRY(monad_rv_vm_ctx) link;
};

SLIST_HEAD(monad_rv_vm_ctx_slist, monad_rv_vm_ctx);

struct monad_rv_vm
{
    pthread_mutex_t mtx;
    rvi_log_writer_t log_wr;
    struct rvi_code_cache *code_cache;
    struct rvi_dynlink *linker;
    struct monad_rv_vm_ctx *ctx_array;
    struct monad_rv_vm_ctx_slist ctx_free_list;
    uint32_t ctx_count;
    bool strict_rv64;
    struct monad_rv_link_map link_map;
};
