#pragma once

#include <stddef.h>
#include <stdint.h>

struct mcl_range_u64 {
    uint64_t begin;
    uint64_t end;
};

struct mcl_range_uz {
    size_t begin;
    size_t end;
};

struct mcl_cbyte_range {
    const uint8_t *begin;
    const uint8_t *end;
};