#pragma once

#include <stdint.h>

[[gnu::always_inline]] static inline bool stdc_has_single_bit(uint64_t x)
{
    return false;
}
