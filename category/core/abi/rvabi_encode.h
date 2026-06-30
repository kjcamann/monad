#pragma once

#include <stdbit.h>
#include <stddef.h>
#include <stdint.h>
#include <string.h>

#include <category/core/abi/error.h>
#include <category/core/address.h>
#include <category/core/byteview.h>
#include <category/core/likely.h>
#include <category/core/strview.h>

#ifdef __cplusplus
extern "C"
{
#endif

[[gnu::always_inline]] static inline monad_abi_err_t monad_rvabi_encode_address(
    struct monad_address const *addr, void *buf, size_t *buflen)
{
    if (MONAD_UNLIKELY(*buflen < sizeof *addr)) {
        *buflen = sizeof *addr;
        return MONAD_ABIERR_NO_BUFFER_SPACE;
    }
    *buflen = sizeof *addr;
    __builtin_memcpy(buf, addr, sizeof *addr);
    return 0;
}

[[gnu::always_inline]] static inline monad_abi_err_t
monad_rvabi_encode_sv(struct monad_sv sv, void *buf, size_t *buflen)
{
    size_t const svlen = monad_sv_len(sv);
    size_t const abilen = sizeof(uint32_t) + svlen + 1;
    if (MONAD_UNLIKELY(*buflen < abilen)) {
        *buflen = abilen;
        return MONAD_ABIERR_NO_BUFFER_SPACE;
    }
    *buflen = abilen;
    *(uint32_t *)buf = (uint32_t)abilen;
    *(char *)mempcpy(buf + sizeof(uint32_t), sv.begin, svlen) = '\0';
    return 0;
}

[[gnu::always_inline]] static inline monad_abi_err_t
monad_rvabi_encode_uint(struct monad_bv bv, void *buf, size_t *buflen)
{
    size_t const bvlen = monad_bv_len(bv);
    if (MONAD_UNLIKELY(*buflen < bvlen)) {
        *buflen = bvlen;
        return MONAD_ABIERR_NO_BUFFER_SPACE;
    }
    *buflen = bvlen;
    if (MONAD_UNLIKELY(!stdc_has_single_bit(bvlen) || bvlen > 32)) {
        return MONAD_ABIERR_ILLEGAL_UINT;
    }
    __attribute__((assume(bvlen <= 32)));
    __builtin_memcpy(buf, bv.begin, bvlen);
    return 0;
}
