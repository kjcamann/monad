#pragma once

#include <stddef.h>
#include <stdint.h>

#include <category/core/byteview.h>
#include <category/rv/rv_link_map.h>

#include "rvi_log_writer.h"

#ifdef __cplusplus
extern "C"
{
#endif

struct monad_rv_vm;
struct rvi_dynlink;
struct rvi_elf;

// Description of an object file in the system archive (an input to the dynamic
// linker)
struct rvi_dynlink_ar_object
{
    struct monad_rv_syslib_meta meta;
    struct monad_bv ar_bytes;
    STAILQ_ENTRY(rvi_dynlink_ar_object) next;
};

// Full dynamic linker input: a list of the system archive ET_REL object files
// and some metadata about them
struct rvi_dynlink_input
{
    STAILQ_HEAD(, rvi_dynlink_ar_object) ar_objs;
    uint32_t ar_objs_count;
    uint32_t symbol_count;
};

struct rvi_dynlink_config
{
    struct monad_bv sys_archive;
    bool bare_metal;
    bool use_hugepages;
};

int rvi_dynlink_create(struct rvi_dynlink **, struct monad_rv_vm *, struct rvi_dynlink_config const *);

void rvi_dynlink_destroy(struct rvi_dynlink *);

int rvi_dynlink_relocate(struct rvi_dynlink *, struct rvi_elf *);

int rvi_dynlink_build_input(struct rvi_dynlink_input *, struct monad_bv sys_archive, bool bare_metal, rvi_log_writer_t);

#ifdef __cplusplus
} // extern "C"
#endif
