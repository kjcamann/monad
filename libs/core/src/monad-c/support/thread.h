/**
 * @file
 *
 * This file contains a few thread routines which are not standardized
 * in pthread(3) at this time.
 */

#include <stdint.h>
#include <monad-c/support/result.h>

/// Get the system ID of the calling thread
monad_result mcl_thread_get_id();

/// Set the name of the calling thread
monad_result mcl_thread_set_name(const char *name);