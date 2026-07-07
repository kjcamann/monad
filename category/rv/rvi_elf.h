#pragma once

#include <stddef.h>

// XXX: want to forward declare this, but can't?
#include <elf.h>

#include <category/core/byteview.h>

#ifdef __cplusplus
extern "C"
{
#endif

struct rvi_elf;

// struct rvi_elf_import_iter;

#if 0
enum monad_rvc_validate_result
monad_rvc_elf_validate(void const *buf, size_t len, monad_rvc_elf_type_t *);
#endif

int rvi_elf_open(void *buf, size_t len, struct rvi_elf **);

void rvi_elf_close(struct rvi_elf *);

Elf64_Ehdr const *rvi_elf_get_header(struct rvi_elf const *);

struct monad_bv rvi_elf_get_bytes(struct rvi_elf const *);

// int rvi_elf_get_abi_name(struct rvi_elf const *, struct monad_bytes32 *);

// int rvi_elf_import_iter_begin(struct rvi_elf const *,
//     struct rvi_elf_import_iter *);

// int rvi_elf_import_iter_next(struct rvi_elf const *,
//     struct rvi_elf_import_iter **);

#ifdef __cplusplus
} // extern "C"
#endif
