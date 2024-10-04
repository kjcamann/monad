#pragma once

#ifdef __cplusplus
extern "C"
{
#endif

/**
 * @file
 *
 * This file contains a few thread routines which are not standardized
 * in pthread(3) at this time.
 */

#include <errno.h>
#include <stdint.h>

#include <monad/core/likely.h>

typedef long monad_tid_t;

// This constinit is needed on macOS, where the TLS codegen strategy differs
// between C and C++. The thread id object lives in `thread-{platform}.c`, so
// it follows the C language rules. These inline functions are usually also
// included in C++ translation units. Without constinit, this would emit
// references to an undefined C++ thread_local wrapper function on Darwin. See
// the comments in clang's `CodeGenModule::EmitGlobalVarDefinition` in
// CodeGenModule.cpp for more information
#ifdef __cplusplus
constinit
#endif
extern thread_local monad_tid_t _monad_tl_tid;

void _monad_tl_tid_init();

/// Get the system ID of the calling thread
static inline monad_tid_t monad_thread_get_id()
{
    if (MONAD_UNLIKELY(!_monad_tl_tid)) {
        _monad_tl_tid_init();
    }
    return _monad_tl_tid;
}

/// Set the name of the calling thread
int monad_thread_set_name(char const *name);

#ifdef __cplusplus
}
#endif
