#pragma once

#include <stddef.h>
#include <stdint.h>

#include <category/core/abi/abi.h>
#include <category/core/abi/error.h>
#include <category/core/abi/rvabi_decode.h>
#include <category/core/abi/solabi_decode.h>
#include <category/core/byteview.h>
#include <category/core/likely.h>
#include <category/core/strview.h>

struct monad_address;

#ifdef __cplusplus
extern "C"
{
#endif

static monad_abi_err_t monad_xabi_decode_string(
    monad_abi_t abi, struct monad_bv buf, struct monad_sv *sv, bool *is_zstr);

static monad_abi_err_t monad_xabi_decode_address(
    monad_abi_t abi, struct monad_bv buf, struct monad_address const **);

static monad_abi_err_t monad_xabi_decode_uint(
    monad_abi_t abi, struct monad_bv buf, size_t uint_bytes, void *u);

static monad_abi_err_t
monad_xabi_decode_bool(monad_abi_t abi, struct monad_bv buf, bool *b);

inline monad_abi_err_t monad_xabi_decode_string(
    monad_abi_t abi, struct monad_bv buf, struct monad_sv *sv, bool *is_zstr)
{
    monad_abi_err_t err;

    switch (abi) {
    case MONAD_ABI_SOLIDITY:
        err = monad_solabi_decode_string(buf, sv);
        if (err) {
            return err;
        }
        if (is_zstr != nullptr) {
            *is_zstr = false;
        }
        return 0;

    case MONAD_ABI_RV64_V1:
        err = monad_rvabi_decode_string(buf, sv);
        if (err) {
            return err;
        }
        if (is_zstr != nullptr) {
            *is_zstr = true;
        }
        return 0;

    default:
        return MONAD_ABIERR_ABI_NOT_SUPPORTED;
    }
}

inline monad_abi_err_t monad_xabi_decode_address(
    monad_abi_t abi, struct monad_bv buf, struct monad_address const **addr)
{
    switch (abi) {
    case MONAD_ABI_SOLIDITY:
        return monad_solabi_decode_address(buf, addr);

    case MONAD_ABI_RV64_V1:
        return monad_rvabi_decode_address(buf, addr);

    default:
        return MONAD_ABIERR_ABI_NOT_SUPPORTED;
    }
}

inline monad_abi_err_t monad_xabi_decode_uint(
    monad_abi_t abi, struct monad_bv buf, size_t uint_bytes, void *u)
{
    void const *p;
    monad_abi_err_t err;

    switch (abi) {
    case MONAD_ABI_SOLIDITY:
        if (MONAD_UNLIKELY(monad_bv_len(buf) < 32)) {
            return MONAD_ABIERR_RUNT_BUFFER;
        }
        return monad_solabi_uint_he_from_bytes32(
            (struct monad_bytes32 const *)buf.begin, uint_bytes, u);

    case MONAD_ABI_RV64_V1:
        err = monad_rvabi_decode_uint(buf, uint_bytes, &p);
        if (err) {
            return err;
        }
        __attribute__((assume(uint_bytes <= 32)));
        __builtin_memcpy(u, p, uint_bytes);
        return 0;

    default:
        return MONAD_ABIERR_ABI_NOT_SUPPORTED;
    }
}

[[gnu::always_inline]] inline monad_abi_err_t
monad_xabi_decode_bool(monad_abi_t abi, struct monad_bv buf, bool *b)
{
    uint8_t u;
    monad_abi_err_t const err = monad_xabi_decode_uint(abi, buf, sizeof u, &u);
    if (err) {
        return err;
    }
    *b = u ? true : false;
    return 0;
}

#ifdef __cplusplus
} // extern "C"
#endif
