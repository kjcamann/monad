#pragma once

#include <stdint.h>

#include <category/rv/rvi_addr_space.h>

constexpr size_t MRV_PAGE_SIZE = 4096;

enum mrv_addr_space : uint8_t
{
    MRV_AS_STORAGE_DMAP = RVI_AS_STORAGE_DMAP,
};

typedef enum mrv_addr_space mrv_addr_space_t;

constexpr size_t MRV_ADDR_SPACE_TAG_BITS = RVI_ADDR_SPACE_TAG_BITS;
constexpr size_t MRV_ADDR_SPACE_OFFSET_BITS = RVI_ADDR_SPACE_OFFSET_BITS;
constexpr size_t MRV_ADDR_SPACE_TAG_SHIFT = RVI_ADDR_SPACE_TAG_SHIFT;

[[gnu::always_inline]] static inline uintptr_t
mrv_addr_space_base(mrv_addr_space_t const as)
{
    return rvi_addr_space_base((rvi_addr_space_t)as);
}

[[gnu::always_inline]] static inline uintptr_t
mrv_addr_space_offset(mrv_addr_space_t const as, size_t const offset)
{
    return rvi_addr_space_offset((rvi_addr_space_t)as, offset);
}
