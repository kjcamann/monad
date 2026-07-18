#pragma once

#include <stddef.h>
#include <stdint.h>

#include <category/core/byteview.h>

// clang-format off

struct monad_rv_vm_config
{
    uint8_t max_log_level;       ///< Maximum syslog(3) level filter
    bool sys_code_hugepages;     ///< True -> system code segment huge pages
    bool no_system_libs;         ///< True -> don't load the system libraries
    struct monad_bv sys_archive; ///< mmap'ed SDK ar(5) file with system code
};

// clang-format on
