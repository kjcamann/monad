#pragma once

#include <syslog.h>

#include <category/rv/rv_link_map.h>
#include <category/rv/rv_vm.h>

#include "rvi_log_writer.h"

#define VM_ERR(ERR, ...) (void)RVI_LOG_WRITE(vm->log_wr, LOG_ERR, (ERR), __VA_ARGS__), (ERR)
#define VM_ERRX(...) RVI_LOG_WRITE(vm->log_wr, LOG_ERR, 0, __VA_ARGS__)
#define VM_DEBUG(...) RVI_LOG_WRITE(vm->log_wr, LOG_DEBUG, 0, __VA_ARGS__)

struct rvi_code_cache;
struct rvi_dynlink;

struct monad_rv_vm
{
    rvi_log_writer_t log_wr;
    struct monad_rv_link_map link_map;
    struct rvi_dynlink *linker;
    struct rvi_code_cache *code_cache;
};
