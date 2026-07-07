#include <errno.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#include <sys/mman.h>
#include <sys/queue.h>

#include <category/core/assert.h>

#include "rv_vm_internal.h"
#include "rvi_code_cache.h"
#include "rvi_dynlink.h"

constexpr uint8_t SYSAR_HEADER[] = {'M', 'R', 'V', 'S', 'Y', 'S', '0', '1'};

// clang-format on

struct shared_object
{
    struct rvi_elf *elf; ///< ELF descriptor for shared object
    struct shared_object **deps; ///< Dependency list on other objects
    unsigned deps_count; ///< # of entries in `deps`
    STAILQ_ENTRY(shared_object) next_topo;
};

struct rvi_dynlink
{
    struct monad_rv_vm *vm;
    struct shared_object *shared_obj;
    unsigned shared_obj_count;
};

// clang-format off

int rvi_dynlink_create(
    struct rvi_dynlink **const dynlink_p, struct monad_rv_vm *const vm, struct rvi_dynlink_config const *const dl_config)
{
    int rc;
    struct rvi_dynlink *dynlink;

    *dynlink_p = dynlink = malloc(sizeof *dynlink);
    if (dynlink == nullptr) {
        rc = errno;
        return VM_ERR(rc, "malloc(3) of rvi_dynlink failed"), rc;
    }
    memset(dynlink, 0, sizeof *dynlink);
    dynlink->vm = vm;

    if (dl_config->bare_metal) {
        VM_DEBUG("bare metal; running without system archive");
        return 0;
    }

    return 0;
}

void rvi_dynlink_destroy(struct rvi_dynlink *dynlink)
{
    if (dynlink != nullptr) {
        free(dynlink->shared_obj);
        free(dynlink);
    }
}

int rvi_dynlink_relocate(struct rvi_dynlink *const, struct rvi_code_cache_entry *const entry)
{
    rvi_code_cache_state_t entry_state;

    entry_state = RVI_CCS_DYN_READY;
    if (!__atomic_compare_exchange_n(&entry->state, &entry_state, RVI_CCS_DYN_INIT, /*weak*/false, __ATOMIC_RELAXED, __ATOMIC_RELAXED)) {
        switch (entry_state) {
        case RVI_CCS_NOT_READY:
            // ELF image memory is still be copied over by another thread,
            // probably in zstd decompression; we treat this the same as if
            // dynamic linking were still in progress on another thread
            [[fallthrough]];
        case RVI_CCS_DYN_INIT:
            // Another thread is performing the dynamic linking; let the caller
            // know that this will succeed shortly, but it's not ready to run
            // immediately
            return EINPROGRESS;
        case RVI_CCS_READY:
            // Another thread has already linked this; return success
            return 0;
        default:
            MONAD_ABORT_PRINTF("unknown code cache state %u", entry_state);
        }
    }

    // XXX: we are supposed to do the linking, but do nothing for now
    return entry->elf_type != MONAD_RV_ELF_TYPE_RV64 ? ENOEXEC : 0;
}
