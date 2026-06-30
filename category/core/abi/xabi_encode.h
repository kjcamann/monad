#pragma once

#include <stdarg.h>
#include <stddef.h>
#include <stdint.h>

#include <category/core/abi/abi.h>
#include <category/core/abi/error.h>
#include <category/core/abi/rvabi_encode.h>
#include <category/core/abi/solabi_encode.h>
#include <category/core/address.h>
#include <category/core/assert.h>
#include <category/core/bytes32.h>
#include <category/core/byteview.h>
#include <category/core/mem/cma/cma_alloc.h>
#include <category/core/strview.h>

struct monad_address;

#ifdef __cplusplus
extern "C"
{
#endif

struct monad_xenc_ctx
{
    monad_abi_t abi;

    union
    {
        struct monad_solenc_ctx sol_ctx;
        // struct monad_rvenc_ctx rv_ctx;
    };
};

static monad_abi_err_t monad_xenc_ctx_init(
    struct monad_xenc_ctx *, monad_abi_t abi,
    struct monad_allocator *build_alloc, size_t element_count,
    struct monad_bv prefix_blob, bool strict);

static monad_abi_err_t monad_xenc_ctx_serialize(
    struct monad_xenc_ctx *, struct monad_allocator *serial_alloc,
    struct monad_bv postfix_blob, struct monad_memblk *, struct monad_bv *);

static void monad_xenc_ctx_free(struct monad_xenc_ctx *);

static monad_abi_err_t monad_xenc_ctx_write_address(
    struct monad_xenc_ctx *, size_t index, const struct monad_address *);

static monad_abi_err_t monad_xenc_ctx_write_uint_he(
    struct monad_xenc_ctx *, size_t index, size_t uint_bytes, void const *u);

static monad_abi_err_t monad_xabi_encode_address(
    monad_abi_t abi, struct monad_address const *addr, void *buf,
    size_t *buflen);

static monad_abi_err_t monad_xabi_encode_sv(
    monad_abi_t abi, struct monad_sv sv, void *buf, size_t *buflen);

static monad_abi_err_t monad_xabi_encode_uint(
    monad_abi_t abi, void const *u, size_t nbytes, void *buf, size_t *buflen);

static monad_abi_err_t
monad_xabi_encode_bool(monad_abi_t abi, bool b, void *buf, size_t *buflen);

static monad_abi_err_t monad_xabi_encode_tuple_inputs(
    monad_abi_t abi, struct monad_bv prefix_blob,
    const struct monad_abi_input *inputs, size_t count,
    struct monad_bv postfix_blob, void *buf, size_t *buflen);

static monad_abi_err_t monad_xabi_encode_tuple_v(
    monad_abi_t abi, struct monad_bv prefix_blob, size_t element_count,
    struct monad_bv postfix_blob, void *buf, size_t *buflen, ...);

static monad_abi_err_t monad_xabi_encode_tuple_valist(
    monad_abi_t abi, struct monad_bv prefix_blob, size_t element_count,
    struct monad_bv postfix_blob, void *buf, size_t *buflen, va_list ap);

/*
 * Inline definitions
 */

[[gnu::always_inline]] inline monad_abi_err_t monad_xenc_ctx_init(
    struct monad_xenc_ctx *ctx, monad_abi_t abi,
    struct monad_allocator *build_alloc, size_t element_count,
    struct monad_bv prefix_blob, bool strict)
{
    __builtin_memset(ctx, 0, sizeof *ctx);
    ctx->abi = abi;

    switch (ctx->abi) {
    case MONAD_ABI_SOLIDITY:
        return monad_solenc_ctx_init(
            &ctx->sol_ctx, build_alloc, element_count, prefix_blob, strict);

    case MONAD_ABI_RV64_V1:
        [[fallthrough]]; // XXX: implement

    default:
        return MONAD_ABIERR_ABI_NOT_SUPPORTED;
    }
}

[[gnu::always_inline]] inline monad_abi_err_t monad_xenc_ctx_serialize(
    struct monad_xenc_ctx *ctx, struct monad_allocator *serial_alloc,
    struct monad_bv postfix_blob, struct monad_memblk *memblk,
    struct monad_bv *bytes)
{
    switch (ctx->abi) {
    case MONAD_ABI_SOLIDITY:
        return monad_solenc_ctx_serialize(
            &ctx->sol_ctx, serial_alloc, postfix_blob, memblk, bytes);

    case MONAD_ABI_RV64_V1:
        [[fallthrough]]; // XXX: implement

    default:
        return MONAD_ABIERR_ABI_NOT_SUPPORTED;
    }
}

[[gnu::always_inline]] inline void
monad_xenc_ctx_free(struct monad_xenc_ctx *ctx)
{
    switch (ctx->abi) {
    case MONAD_ABI_SOLIDITY:
        return monad_solenc_ctx_free(&ctx->sol_ctx);

    case MONAD_ABI_RV64_V1:
        [[fallthrough]]; // XXX: implement

    default:
        MONAD_ABORT_PRINTF("unrecognized ABI code %hhu", ctx->abi);
    }
}

[[gnu::always_inline]] inline monad_abi_err_t monad_xenc_ctx_write_uint_he(
    struct monad_xenc_ctx *ctx, size_t index, size_t uint_bytes, void const *u)
{
    switch (ctx->abi) {
    case MONAD_ABI_SOLIDITY:
        return monad_solenc_tuple_set_uint_he(
            &ctx->sol_ctx.top_level, index, uint_bytes, u);

    case MONAD_ABI_RV64_V1:
        [[fallthrough]]; // XXX: implement

    default:
        return MONAD_ABIERR_ABI_NOT_SUPPORTED;
    }
}

[[gnu::always_inline]] inline monad_abi_err_t monad_xabi_encode_address(
    monad_abi_t abi, struct monad_address const *addr, void *buf,
    size_t *buflen)
{
    switch (abi) {
    case MONAD_ABI_SOLIDITY:
        return monad_solabi_encode_address(addr, buf, buflen);

    case MONAD_ABI_RV64_V1:
        return monad_rvabi_encode_address(addr, buf, buflen);

    default:
        return MONAD_ABIERR_ABI_NOT_SUPPORTED;
    }
}

[[gnu::always_inline]] inline monad_abi_err_t monad_xabi_encode_sv(
    monad_abi_t abi, struct monad_sv sv, void *buf, size_t *buflen)
{
    switch (abi) {
    case MONAD_ABI_SOLIDITY:
        return monad_solabi_encode_sv(sv, buf, buflen);

    case MONAD_ABI_RV64_V1:
        return monad_rvabi_encode_sv(sv, buf, buflen);

    default:
        return MONAD_ABIERR_ABI_NOT_SUPPORTED;
    }
}

[[gnu::always_inline]] inline monad_abi_err_t monad_xabi_encode_uint(
    monad_abi_t abi, void const *u, size_t nbytes, void *buf, size_t *buflen)
{
    switch (abi) {
    case MONAD_ABI_SOLIDITY:
        return monad_solabi_encode_uint(
            monad_bv_from_size(u, nbytes), buf, buflen);

    case MONAD_ABI_RV64_V1:
        return monad_rvabi_encode_uint(
            monad_bv_from_size(u, nbytes), buf, buflen);

    default:
        return MONAD_ABIERR_ABI_NOT_SUPPORTED;
    }
}

[[gnu::always_inline]] inline monad_abi_err_t
monad_xabi_encode_bool(monad_abi_t abi, bool b, void *buf, size_t *buflen)
{
    uint8_t const u = b ? 1 : 0;
    return monad_xabi_encode_uint(abi, &u, sizeof u, buf, buflen);
}

[[gnu::always_inline]] inline monad_abi_err_t monad_xabi_encode_tuple_inputs(
    monad_abi_t abi, struct monad_bv prefix_blob,
    const struct monad_abi_input *inputs, size_t count,
    struct monad_bv postfix_blob, void *buf, size_t *buflen)
{
    switch (abi) {
    case MONAD_ABI_SOLIDITY:
        return monad_solabi_encode_tuple_inputs(
            prefix_blob, inputs, count, postfix_blob, buf, buflen);

    case MONAD_ABI_RV64_V1:
        [[fallthrough]]; // XXX: implement this

    default:
        return MONAD_ABIERR_ABI_NOT_SUPPORTED;
    }
}

[[gnu::always_inline]] inline monad_abi_err_t monad_xabi_encode_tuple_valist(
    monad_abi_t abi, struct monad_bv prefix_blob, size_t element_count,
    struct monad_bv postfix_blob, void *buf, size_t *buflen, va_list ap)
{
    switch (abi) {
    case MONAD_ABI_SOLIDITY:
        return monad_solabi_encode_tuple_valist(
            prefix_blob, element_count, postfix_blob, buf, buflen, ap);

    case MONAD_ABI_RV64_V1:
        [[fallthrough]]; // XXX: implement this

    default:
        return MONAD_ABIERR_ABI_NOT_SUPPORTED;
    }
}

[[gnu::always_inline]] inline monad_abi_err_t monad_xabi_encode_tuple_v(
    monad_abi_t abi, struct monad_bv prefix_blob, size_t element_count,
    struct monad_bv postfix_blob, void *buf, size_t *buflen, ...)
{
    monad_abi_err_t err;
    va_list ap;

    va_start(ap, buflen);
    err = monad_xabi_encode_tuple_valist(
        abi, prefix_blob, element_count, postfix_blob, buf, buflen, ap);
    va_end(ap);
    return err;
}

#ifdef __cplusplus
} // extern "C"
#endif
