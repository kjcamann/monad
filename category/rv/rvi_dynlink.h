#pragma once

#include <category/core/byteview.h>

#ifdef __cplusplus
extern "C"
{
#endif

struct monad_rv_vm;
struct rvi_code_cache_entry;
struct rvi_dynlink;

struct rvi_dynlink_config
{
    struct monad_bv sys_archive;
    bool bare_metal;
};

int rvi_dynlink_create(
    struct rvi_dynlink **, struct monad_rv_vm *,
    struct rvi_dynlink_config const *);

void rvi_dynlink_destroy(struct rvi_dynlink *);

int rvi_dynlink_relocate(struct rvi_dynlink *, struct rvi_code_cache_entry *);

#ifdef __cplusplus
} // extern "C"
#endif
