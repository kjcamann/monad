#include <errno.h>
#include <stdlib.h>
#include <string.h>

#include <category/rv/rv_vm.h>
#include <category/rv/rv_vm_config.h>
#include <category/rv/rvi_dynlink.h>

#include "rv_vm_internal.h"
#include "rvi_log_writer.h"

static int init_linker(
    struct monad_rv_vm *const vm,
    struct monad_rv_vm_config const *const vm_config)
{
    struct rvi_dynlink_config const linker_config = {
        .sys_archives = vm_config->sys_archives,
        .sys_archive_count = vm_config->sys_archive_count,
        .sys_lib_alloc = nullptr,
    };

    return rvi_dynlink_create(&vm->linker, vm, &linker_config);
}

int monad_rv_vm_create(
    struct monad_rv_vm **const vm_p,
    struct monad_rv_log_observer *const log_obs,
    struct monad_rv_vm_config const *const config)
{
    int rc;
    rvi_log_writer_t log_wr;
    struct monad_rv_vm *vm;

    log_wr = rvi_log_writer_init(log_obs, config->max_log_level);
    *vm_p = vm = malloc(sizeof *vm);
    if (vm == nullptr) {
        rc = errno;
        return RVI_LOG_WRITE(
                   log_wr, LOG_ERR, rc, "malloc(3) of monad_rv_failed"),
               rc;
    }
    memset(vm, 0, sizeof *vm);
    vm->log_wr = log_wr;

    return init_linker(vm, config);
}

void monad_rv_vm_destroy(struct monad_rv_vm *vm)
{
    if (vm != nullptr) {
        rvi_dynlink_destroy(vm->linker);
        free(vm);
    }
}
