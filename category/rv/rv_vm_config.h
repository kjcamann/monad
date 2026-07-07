#pragma once

#include <stddef.h>
#include <stdint.h>

#include <category/core/byteview.h>

// clang-format off

struct monad_rv_vm_config
{
    uint8_t max_log_level;         ///< Maximum syslog(3) level filter
    uint8_t code_cache_size_shift; ///< Code cache size == 2^(code_cache_shift)
    uint8_t ctx_pool_size_shift;   ///< # of VM ctx objects == 2^(vm_ctx_shift)
    bool no_system_libs;           ///< True -> don't load the system libraries
    struct monad_bv sys_archive;   ///< mmap'ed SDK sysar file for shared libs
};

// clang-format on
