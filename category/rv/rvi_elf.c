#include <stddef.h>

#include <category/rv/rvi_elf.h>

enum monad_rvc_validate_result monad_rvc_elf_validate(
    void const *buf, size_t len, monad_rvc_elf_type_t *elf_type)
{
    if (elf_type != nullptr) {
        *elf_type = MONAD_RVC_ELF_TYPE_INVALID;
    }

    return MONAD_RVC_VALIDATE_ELF_NOT_RV64;
}
