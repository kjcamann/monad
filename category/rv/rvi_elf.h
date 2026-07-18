#pragma once

#include <stddef.h>

#include <elf.h>

#include <category/core/byteview.h>

#ifdef __cplusplus
extern "C"
{
#endif

enum rvi_elf_section_type
{
    RVI_ELF_ST_TEXT,
    RVI_ELF_ST_DATA,
    RVI_ELF_ST_RODATA,
};

struct rvi_elf
{
    struct monad_bv bytes;
    Elf64_Ehdr const *elf_header;
    Elf64_Shdr const *section_headers;
    Elf64_Nhdr const *abi_name_note;
    Elf64_Nhdr const **import_notes;
    size_t import_notes_count;
};

// struct rvi_elf_import_iter;

#if 0
enum monad_rvc_validate_result
monad_rvc_elf_validate(void const *buf, size_t len, monad_rvc_elf_type_t *);
#endif

int rvi_elf_open(struct rvi_elf *, void *buf, size_t len);

int rvi_elf_open_no_validate(struct rvi_elf *, void *buf, size_t len);

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
