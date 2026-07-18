#pragma once

#include <stddef.h>
#include <stdint.h>

#include <sys/queue.h>

#include <category/core/byteview.h>

constexpr size_t MONAD_RV_ABI_NAME_MAX = 15;
constexpr size_t MONAD_RV_ABI_BUF_LEN = MONAD_RV_ABI_NAME_MAX + 1;

// clang-format off

/// Metadata for a shared library object; only certain objects (termed
/// "system libraries") can be shared
struct monad_rv_syslib_meta
{
    char abi_name[MONAD_RV_ABI_BUF_LEN]; ///< ABI name of library
    char lib_name[MONAD_RV_ABI_BUF_LEN]; ///< Name without .<version> suffix
    unsigned abi_version;                ///< ABI version integer
    unsigned symbol_count;               ///< # of external symbols exported
};

/// Description of a shared code object loaded into RV64 VM memory
struct monad_rv_link_map_entry
{
    struct monad_rv_syslib_meta meta;    ///< Metadata describing loaded library
    uint64_t rv_code_addr;               ///< Code location in RV64 addr space
    uint64_t rv_data_addr;               ///< Data location in RV64 addr space
    uint64_t rv_bss_start_addr;          ///< .bss start in RV64 addr space
    uint64_t rv_bss_end_end;             ///< .bss end in RV64 addr space
    struct monad_bv code_bytes;          ///< Relocated code in host memory
    struct monad_bv data_bytes;          ///< Initial data image
    STAILQ_ENTRY(monad_rv_link_map_entry) next; ///< Linkage for map list
};

// clang-format on

STAILQ_HEAD(monad_rv_link_map_list, monad_rv_link_map_entry);

/// Description of where system code is loaded into various parts of the address
/// space (RVI_AS_SYSTEM_CODE, RVI_AS_SYSTEM_DATA) for shared libraries
struct monad_rv_link_map
{
    struct monad_rv_link_map_list entries;
    uint32_t entries_count;
    uint32_t symbol_count;
    size_t code_segment_size;
    size_t data_segment_size;
};
