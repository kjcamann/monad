#pragma once

/**
 * @file
 *
 * This file defines data structures that describe the layout of the shared
 * library address space, similar to the SVR4 <link.h> interface. It is part
 * of the public API to aid in source-level debugging by other components in
 * the system (specifically decoding of addresses back to their ELF image
 * origin). The VM implementation maintains its own internal view of the
 * address space, in the dynamic linker.
 */

#include <stddef.h>
#include <stdint.h>

#include <sys/queue.h>

#include <elf.h>

constexpr size_t MONAD_RV_ABI_NAME_MAX = 31;
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

/// Description of a shared object loaded into RV64 VM memory
struct monad_rv_link_map_entry
{
    struct monad_rv_syslib_meta meta;  ///< Metadata describing loaded library
    uint64_t rv_load_address;          ///< Base load address (RV64 addr space)
    Elf64_Dyn *dyn_entries;            ///< Array of ELF dynamic entries
    STAILQ_ENTRY(monad_rv_link_map_entry) next; ///< Linkage for map list
};

STAILQ_HEAD(monad_rv_link_map_list, monad_rv_link_map_entry);

/// Description of where all shared libraries are loaded into the
/// RVI_AS_SHARED_LIBRARY address space
struct monad_rv_link_map
{
    struct monad_rv_link_map_list
        entries;             ///< Linked list of all map entries
    uint32_t entries_count;  ///< # of shared object mappings in `entries`
    uint32_t symbol_count;   ///< # of external symbols in all libraries
    uint64_t shared_start;   ///< Minimum RVI_AS_SHARED_LIBRARY address
    uint64_t shared_end;     ///< End of RVI_AS_SHARED_LIBRARY half-open range
};

// clang-format on
