// This is intended to be a user-space implementation of the Solaris slab
// allocator, like libumem. It is entirely unimplemented and just calls
// malloc(3) instead. The name "mem_zone" comes from the FreeBSD kernel
// implementation of the same idea, i.e., "uma_zone_t".

#include <errno.h>
#include <stddef.h>
#include <stdlib.h>

#include <category/core/likely.h>
#include <category/core/mem/mem_zone.h>

struct mem_zone
{
    size_t size;
    size_t align;
};

int mem_zone_create(
    struct mem_zone_config const *const config, void *const instance,
    struct mem_zone **const mz_p)
{
    struct mem_zone *mz;

    *mz_p = mz = malloc(sizeof *mz);
    if (mz == nullptr) {
        return errno;
    }
    mz->size = config->size;
    mz->align = config->align;
    return 0;
}

void mem_zone_destroy(struct mem_zone *const mz)
{
    free(mz);
}

int mem_zone_alloc(struct mem_zone *const mz, void **ptr)
{
    *ptr = aligned_alloc(mz->align, mz->size);
    if (MONAD_UNLIKELY(*ptr == nullptr)) {
        return errno;
    }
    return 0;
}

void mem_zone_free(struct mem_zone *const mz, void *const p)
{
    free(p);
}
