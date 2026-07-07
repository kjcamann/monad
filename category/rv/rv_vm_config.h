#pragma once

#include <stddef.h>
#include <stdint.h>

#include <category/core/byteview.h>

// clang-format off

struct monad_rv_vm_config
{
    uint8_t max_log_level;               ///< Maximum syslog(3) level filter
    struct monad_bv const *sys_archives; ///< mmap'ed SDK bootstrap archives
    size_t sys_archive_count;            ///< Size of `sys_archives` array
};

// clang-format on
