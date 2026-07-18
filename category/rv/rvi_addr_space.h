#pragma once

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C"
{
#endif

typedef uint64_t rvi_addr_t;

enum rvi_addr_space : uint8_t
{
    RVI_AS_PSABI,
    RVI_AS_CONTRACT_CODE,
    RVI_AS_CONTRACT_DATA,
    RVI_AS_SYSTEM_CODE,
    RVI_AS_SYSTEM_DATA,
};

typedef enum rvi_addr_space rvi_addr_space_t;

constexpr size_t RVI_ADDR_SPACE_TAG_BITS = 8;
constexpr size_t RVI_ADDR_SPACE_OFFSET_BITS = 64 - RVI_ADDR_SPACE_TAG_BITS;
constexpr size_t RVI_ADDR_SPACE_TAG_SHIFT = RVI_ADDR_SPACE_OFFSET_BITS;

constexpr rvi_addr_t RVI_ADDR_SPACE_OFFSET_MASK =
    ((rvi_addr_t)1U << RVI_ADDR_SPACE_OFFSET_BITS) - 1;

constexpr rvi_addr_t RVI_ADDR_SPACE_TAG_MASK = ~RVI_ADDR_SPACE_OFFSET_MASK;

[[gnu::always_inline]] static inline rvi_addr_t
rvi_addr_space_base(rvi_addr_space_t const as)
{
    return (uintptr_t)as << RVI_ADDR_SPACE_TAG_SHIFT;
}

[[gnu::always_inline]] static inline rvi_addr_t
rvi_addr_space_offset(rvi_addr_space_t const as, size_t const offset)
{
    return rvi_addr_space_base(as) + (rvi_addr_t)offset;
}

#ifdef __cplusplus
} // extern "C"
#endif
