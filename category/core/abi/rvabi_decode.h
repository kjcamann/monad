#pragma once

#include <stdarg.h>
#include <stdbit.h>
#include <stddef.h>
#include <stdint.h>

#include <category/core/abi/abi.h>
#include <category/core/abi/error.h>
#include <category/core/address.h>
#include <category/core/byteview.h>
#include <category/core/likely.h>
#include <category/core/strview.h>

#ifdef __cplusplus
extern "C"
{
#endif

[[gnu::always_inline]] static inline monad_abi_err_t
monad_rvabi_decode_bytes(struct monad_bv buf, struct monad_bv *bv)
{
    uint32_t len;

    if (monad_bv_len(buf) < sizeof len) {
        return MONAD_ABIERR_RUNT_BUFFER;
    }
    len = *(uint32_t const *)buf.begin;
    *bv = monad_bv_sub(buf, sizeof(len), len);
    if (MONAD_UNLIKELY(bv->end > buf.end)) {
        return MONAD_ABIERR_OFFSET_POINTS_OUTSIDE;
    }
    return 0;
}

[[gnu::always_inline]] static inline monad_abi_err_t
monad_rvabi_decode_string(struct monad_bv buf, struct monad_sv *sv)
{
    uint32_t len;

    // This is almost the same as monad_rvabi_decode_bytes, but strings
    // include null termination
    if (monad_bv_len(buf) < sizeof len) {
        return MONAD_ABIERR_RUNT_BUFFER;
    }
    len = *(uint32_t const *)buf.begin;
    sv->begin = (char const *)buf.begin + sizeof(len);
    sv->end = sv->begin + len;
    if (MONAD_UNLIKELY((uint8_t const *)sv->end + 1 > buf.end)) {
        return MONAD_ABIERR_OFFSET_POINTS_OUTSIDE;
    }
    if (MONAD_UNLIKELY(*sv->end != '\0')) {
        return MONAD_ABIERR_ILLEGAL_STRING;
    }
    return 0;
}

[[gnu::always_inline]] static inline monad_abi_err_t monad_rvabi_decode_address(
    struct monad_bv buf, struct monad_address const **addr)
{
    if (monad_bv_len(buf) < sizeof **addr) {
        return MONAD_ABIERR_RUNT_BUFFER;
    }
    *addr = (struct monad_address const *)buf.begin;
    return 0;
}

[[gnu::always_inline]] static inline monad_abi_err_t
monad_rvabi_decode_uint(struct monad_bv buf, size_t uint_bytes, void const **u)
{
    if (monad_bv_len(buf) < uint_bytes) {
        return MONAD_ABIERR_RUNT_BUFFER;
    }
    if (!stdc_has_single_bit(uint_bytes)) {
        return MONAD_ABIERR_ILLEGAL_UINT;
    }
    *u = buf.begin;
    return 0;
}

static inline monad_abi_err_t monad_rvabi_unpack(
    struct monad_bv bytes, struct monad_abi_output *outputs, size_t count,
    struct monad_bv *resid)
{
    monad_abi_err_t err = 0;
    struct monad_bv remaining = bytes;

    for (size_t i = 0; i < count; ++i) {
        struct monad_bv bv_output;
        struct monad_sv sv_output;
        struct monad_abi_output *const outbuf = &outputs[i];

        switch (outbuf->type) {
        case MONAD_ABI_TYPE_ADDRESS:
            if (outbuf->ptr.view != nullptr) {
                err = monad_rvabi_decode_address(
                    remaining, (struct monad_address const **)outbuf->ptr.view);
            }
            remaining = monad_bv_sub(
                remaining, sizeof(struct monad_address), MONAD_BV_ALL);
            break;

        case MONAD_ABI_TYPE_UINT_BE:
            return MONAD_ABIERR_ILLEGAL_ABI_TYPE;

        case MONAD_ABI_TYPE_UINT_HE:
            if (outbuf->ptr.view != nullptr) {
                err = monad_rvabi_decode_uint(
                    remaining, outbuf->size, outbuf->ptr.view);
            }
            remaining = monad_bv_sub(remaining, outbuf->size, MONAD_BV_ALL);
            break;

        case MONAD_ABI_TYPE_BOOL:
            if (outbuf->ptr.buf != nullptr) {
                uint8_t const *uint_p;
                err = monad_rvabi_decode_uint(
                    remaining, 1, (void const **)&uint_p);
                if (MONAD_LIKELY(err == 0)) {
                    *(bool *)outbuf->ptr.buf = *uint_p;
                }
            }
            remaining = monad_bv_sub(remaining, 1, MONAD_BV_ALL);
            break;

        case MONAD_ABI_TYPE_BYTES:
            err = monad_rvabi_decode_bytes(remaining, &bv_output);
            if (MONAD_LIKELY(err == 0)) {
                remaining = monad_bv_sub(
                    remaining,
                    sizeof(uint32_t) + monad_bv_len(bv_output),
                    MONAD_BV_ALL);
                if (outbuf->ptr.buf != nullptr) {
                    *(struct monad_bv *)outbuf->ptr.buf = bv_output;
                }
            }
            break;

        case MONAD_ABI_TYPE_STRING:
            err = monad_rvabi_decode_string(remaining, &sv_output);
            if (MONAD_LIKELY(err == 0)) {
                remaining = monad_bv_sub(
                    remaining,
                    sizeof(uint32_t) + monad_sv_len(sv_output) + 1,
                    MONAD_BV_ALL);
                if (outbuf->ptr.buf != nullptr) {
                    *(struct monad_sv *)outbuf->ptr.buf = sv_output;
                }
            }
            break;

        case MONAD_ABI_TYPE_DYNAMIC_ARRAY:
            [[fallthrough]];
        case MONAD_ABI_TYPE_DYNAMIC_TUPLE:
            return MONAD_ABIERR_ILLEGAL_ABI_TYPE;

        default:
            return MONAD_ABIERR_UNKNOWN_ABI_TYPE;
        }

        if (err) {
            return err;
        }
    }

    if (resid != nullptr) {
        *resid = remaining;
    }
    return 0;
}

monad_abi_err_t monad_rvabi_unpack_valist(
    struct monad_bv bytes, size_t count, struct monad_bv *resid, va_list);

static inline monad_abi_err_t monad_rvabi_unpack_v(
    struct monad_bv bytes, size_t count, struct monad_bv *resid, ...)
{
    monad_abi_err_t err;
    va_list ap;

    va_start(ap, resid);
    err = monad_rvabi_unpack_valist(bytes, count, resid, ap);
    va_end(ap);
    return err;
}

#ifdef __cplusplus
} // extern "C"
#endif
