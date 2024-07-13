#pragma once

#include <stdint.h>
#include <monad-c/support/result.h>

/// A port of the OpenBSD strtonum(3) utility, except returning a
/// @ref monad_result
monad_result mcl_parse_int(const char *nptr, intptr_t min_val,
                           intptr_t max_val);