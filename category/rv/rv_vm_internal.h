#pragma once

#include <stdint.h>

#include <category/core/srcloc.h>
#include <category/rv/rv_vm.h>

#include "rvi_log_writer.h"

#define VM_ERR(...) RVI_LOG_WRITE(vm->log_wr, LOG_ERR, __VA_ARGS__)
#define VM_ERRX(...) RVI_LOG_WRITE(vm->log_wr, LOG_ERR, 0, __VA_ARGS__)
#define VM_DEBUG(...) RVI_LOG_WRITE(vm->log_wr, LOG_DEBUG, 0, __VA_ARGS__)

struct rvi_dynlink;

struct monad_rv_vm
{
    rvi_log_writer_t log_wr;
    struct rvi_dynlink *linker;
};
