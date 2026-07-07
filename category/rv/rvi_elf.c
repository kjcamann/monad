#include <stddef.h>

#include <elf.h>

#include <category/rv/rv_code.h>

#include "rvi_elf.h"

monad_rv_validate_code_result_t
rvi_elf_validate(void const *buf, size_t len, monad_rv_elf_type_t *elf_type)
{
    if (elf_type != nullptr) {
        *elf_type = MONAD_RV_ELF_TYPE_INVALID;
    }
    *elf_type = ((Elf64_Ehdr const *)buf)->e_machine == EM_RISCV
                    ? MONAD_RV_ELF_TYPE_RV64
                    : MONAD_RV_ELF_TYPE_HOST;
    return MONAD_RV_VCODE_OK;
}

monad_rv_elf_type_t rvi_elf_get_type(void const *buf)
{
    Elf64_Ehdr const *const hdr = (Elf64_Ehdr const *)buf;
    return hdr->e_ident[EI_CLASS] == ELFCLASS64 && hdr->e_machine == EM_RISCV
               ? MONAD_RV_ELF_TYPE_RV64
               : MONAD_RV_ELF_TYPE_HOST; // Assuming pre-validated
}
