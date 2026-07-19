#include <errno.h>
#include <stdlib.h>
#include <string.h>

#include <sys/mman.h>
#include <sys/queue.h>

#include "rv_vm_internal.h"
#include "rvi_addr_space.h"
#include "rvi_dynlink.h"
#include "rvi_elf.h"

typedef enum object_type
{
    OT_SHARED,
    OT_CONTRACT,
} object_type_t;

// clang-format on

struct shared_object
{
    struct rvi_elf *elf;             ///< ELF descriptor for shared object
    struct shared_object **deps;     ///< Dependency list on other objects
    unsigned deps_count;             ///< # of entries in `deps`
    STAILQ_ENTRY(shared_object) next_topo;
};

struct rvi_dynlink
{
    struct monad_rv_vm *vm;
    struct shared_object *shared_obj;
    unsigned shared_obj_count;
};

// clang-format off

// For each linker input, create a `struct shared_object` representation of it;
static int create_shared_objects(struct rvi_dynlink *const dynlink, struct rvi_dynlink_input const *const dl_input, rvi_log_writer_t log_wr)
{
    int rc;
    struct shared_object *so;

    // Allocate an array to hold the shared objects
    dynlink->shared_obj_count = dl_input->ar_objs_count;
    dynlink->shared_obj = (struct shared_object *)calloc(dynlink->shared_obj_count, sizeof(struct shared_object));
    if (dynlink->shared_obj == nullptr) {
        rc = errno;
        return LW_ERR(rc, "calloc(3) for shared_objects failed"), rc;
    }

    return 0;
}

int rvi_dynlink_create(
    struct rvi_dynlink **const dynlink_p, struct monad_rv_vm *const vm, struct rvi_dynlink_config const *const dl_config)
{
    int rc;
    struct rvi_dynlink *dynlink;
    struct rvi_dynlink_input dl_input;

    *dynlink_p = dynlink = malloc(sizeof *dynlink);
    if (dynlink == nullptr) {
        rc = errno;
        return VM_ERR(rc, "malloc(3) of rvi_dynlink failed"), rc;
    }
    memset(dynlink, 0, sizeof *dynlink);
    dynlink->vm = vm;

    // First build a representation of the linker inputs from the raw input
    // we're given (the memory-mapped system archive file)
    rc = rvi_dynlink_build_input(&dl_input, dl_config->sys_archive, dl_config->bare_metal, vm->log_wr);
    if (rc != 0) {
        goto Error;
    }

    // XXX: pick up here later
    rc = create_shared_objects(dynlink, &dl_input, dl_config->use_hugepages);
    if (rc != 0) {
        goto Error;
    }
    return rc;

Error:
    rvi_dynlink_destroy(dynlink);
    return rc;
}

void rvi_dynlink_destroy(struct rvi_dynlink *dynlink)
{
    if (dynlink != nullptr) {
        free(dynlink->shared_obj);
        free(dynlink);
    }
}

int rvi_dynlink_relocate(struct rvi_dynlink *const dynlink, struct rvi_elf *const elf)
{
    return relocate_object(dynlink, elf, OT_CONTRACT);
}
