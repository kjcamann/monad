#include <errno.h>
#include <stdlib.h>
#include <string.h>

#include "rv_vm_internal.h"
#include "rvi_dynlink.h"

struct rvi_dynlink
{
    struct monad_rv_vm *vm;
};

int rvi_dynlink_create(
    struct rvi_dynlink **const dynlink_p, struct monad_rv_vm *const vm,
    struct rvi_dynlink_config const *const config)
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

    VM_DEBUG("hello from dynlink!");
    return 0;
}

void rvi_dynlink_destroy(struct rvi_dynlink *dynlink)
{
    if (dynlink != nullptr) {
        free(dynlink);
    }
}
