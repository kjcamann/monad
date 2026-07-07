#pragma once

#include <stddef.h>

#include <elf.h>

#include <category/core/byteview.h>
#include <category/rv/rv_code.h>

#ifdef __cplusplus
extern "C"
{
#endif

#if 0
struct rvi_elf
{
    struct monad_bv bytes;
    Elf64_Ehdr const *elf_header;
    Elf64_Shdr const *section_headers;
};
#endif

monad_rv_validate_code_result_t
rvi_elf_validate(void const *buf, size_t len, monad_rv_elf_type_t *);

// XXX: maybe this should take an open rvi_elf descriptor, but we won't
// design that part of the API until the dynamic linker is finished; this
// is a stub used by the "prevalidated" part of the code now
monad_rv_elf_type_t rvi_elf_get_type(void const *buf);

#if 0
int rvi_elf_open(struct rvi_elf *, void *buf, size_t len);

int rvi_elf_open_no_validate(struct rvi_elf *, void *buf, size_t len);

void rvi_elf_close(struct rvi_elf *);

struct monad_bv rvi_elf_get_bytes(struct rvi_elf const *);
#endif

#ifdef __cplusplus
} // extern "C"
#endif
