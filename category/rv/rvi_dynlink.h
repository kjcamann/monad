#pragma once

#include <stddef.h>
#include <stdint.h>

#include <category/core/byteview.h>

#ifdef __cplusplus
extern "C"
{
#endif

struct monad_allocator;
struct monad_rv_vm;
struct rvi_dynlink;
struct rvi_elf;

struct rvi_dynlink_config
{
    struct monad_bv const *sys_archives;
    size_t sys_archive_count;
    struct monad_allocator *sys_lib_alloc;
};

// XXX: ability to return the linkmap
// XXX: ability to return the range in both address spaces of the system code
// map

int rvi_dynlink_create(
    struct rvi_dynlink **, struct monad_rv_vm *,
    struct rvi_dynlink_config const *);

void rvi_dynlink_destroy(struct rvi_dynlink *);

int rvi_dynlink_relocate(struct rvi_dynlink *, struct rvi_elf *);

#ifdef __cplusplus
} // extern "C"
#endif
