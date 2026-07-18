#include <errno.h>
#include <stdlib.h>
#include <string.h>

#include <category/rv/rv_vm.h>
#include <category/rv/rv_vm_config.h>
#include <category/rv/rvi_dynlink.h>

#include "rv_vm_internal.h"
#include "rvi_dynlink.h"
#include "rvi_log_writer.h"

static int init_linker(
    struct monad_rv_vm *const vm,
    struct monad_rv_vm_config const *const vm_config)
{
    if (monad_bv_empty(vm_config->sys_archive) && !vm_config->no_system_libs) {
        VM_ERRX("dynamic linker needs a system archive to initialize");
    }
    // Create the dynamic linker, which will load all the system shared
    // libraries and resolve their relocations
    return rvi_dynlink_create(&vm->linker, vm, vm_config->sys_code_hugepages);
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
        return LW_ERR(errno, "malloc(3) of monad_rv_failed");
    }
    memset(vm, 0, sizeof *vm);
    vm->log_wr = log_wr;

    rc = init_linker(vm, config);
    if (rc != 0) {
        monad_rv_vm_destroy(vm);
        return rc;
    }

#if 0
    rc = init_code_cache(vm, config);
    if (rc != 0) {
        monad_rv_vm_destroy(vm);
        return rc;
    }
#endif

    return 0;
}

void monad_rv_vm_destroy(struct monad_rv_vm *vm)
{
    if (vm != nullptr) {
        // XXX: need to free the link map
        rvi_dynlink_destroy(vm->linker);
        // rvi_code_cache_destroy(vm->code_cache);
        free(vm);
    }
}
