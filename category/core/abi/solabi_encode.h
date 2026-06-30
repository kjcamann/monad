#pragma once

/*
 * @file
 *
 * Implementation of a Solidity Contract ABI encoding library
 */

#include <stdarg.h>
#include <stdbit.h>
#include <stddef.h>
#include <stdint.h>

#include <category/core/abi/abi.h>
#include <category/core/abi/error.h>
#include <category/core/bytes32.h>
#include <category/core/byteview.h>
#include <category/core/mem/cma/cma_alloc.h>
#include <category/core/mem/cma/cma_bump.h>
#include <category/core/strview.h>

struct monad_address;

#ifdef __cplusplus
extern "C"
{
#endif

struct monad_solenc_ctx;
struct monad_solenc_tuple;

enum monad_solenc_type : uint8_t
{
    MONAD_SOLENC_UNINIT,
    MONAD_SOLENC_FIXED,
    MONAD_SOLENC_DYNAMIC_TUPLE,
    MONAD_SOLENC_DYNAMIC_ARRAY,
    MONAD_SOLENC_BYTES,
};

typedef enum monad_solenc_type monad_solenc_type_t;

union monad_solenc_value
{
    struct monad_bytes32 fixed;
    struct monad_solenc_tuple *dynamic;
};

// clang-format off

struct monad_solenc_tuple
{
    struct monad_solenc_ctx *ctx; ///< Encoding context we live in
    monad_solenc_type_t *types;   ///< `types[i]` tells what `values[i]` is
    union monad_solenc_value *values; ///< Tuple value array
    struct monad_memblk memblk;   ///< Memory block holding `types` & `values`
    size_t element_count;         ///< Number of elements in tuple or array
    bool no_dynamic;              ///< Set when `types[i] == FIXED` for all i
};

/// Solidity encoder context object; this manages dynamic memory during
/// encoding, and stores the top-level tuple descriptor
struct monad_solenc_ctx
{
    struct monad_allocator *alloc;       ///< Mem allocator for tuple data
    struct monad_solenc_tuple top_level; ///< Top-level tuple descriptor
    bool strict;                         ///< True -> aggressive error checking
};

// clang-format on

monad_abi_err_t monad_solenc_ctx_init(
    struct monad_solenc_ctx *, struct monad_allocator *alloc,
    size_t element_count, struct monad_bv prefix_blob, bool strict);

monad_abi_err_t monad_solenc_ctx_serialize(
    struct monad_solenc_ctx *, struct monad_allocator *serial_alloc,
    struct monad_bv postfix_blob, struct monad_memblk *, struct monad_bv *);

void monad_solenc_ctx_free(struct monad_solenc_ctx *);

monad_abi_err_t monad_solenc_tuple_set_fixed(
    struct monad_solenc_tuple *tuple, size_t index,
    struct monad_bytes32 const *value);

monad_abi_err_t monad_solenc_tuple_set_dynamic_array(
    struct monad_solenc_tuple *tuple, size_t index, size_t array_size,
    struct monad_solenc_tuple **array);

monad_abi_err_t monad_solenc_tuple_set_dynamic_tuple(
    struct monad_solenc_tuple *tuple, size_t index,
    size_t dyn_tuple_element_count, struct monad_solenc_tuple **dyn_tuple);

monad_abi_err_t monad_solenc_tuple_set_bytes(
    struct monad_solenc_tuple *tuple, size_t index, struct monad_bv bytes);

monad_abi_err_t monad_solenc_tuple_set_inputs(
    struct monad_solenc_tuple *tuple, size_t start_index,
    struct monad_abi_input const *inputs, size_t count);

[[gnu::always_inline]] static inline monad_abi_err_t
monad_solenc_tuple_set_address(
    struct monad_solenc_tuple *tuple, size_t index,
    struct monad_address const *addr)
{
    struct monad_bytes32 b32;
    __builtin_memset(&b32, 0, 12);
    __builtin_memcpy(&b32.bytes[12], addr, 20);
    return monad_solenc_tuple_set_fixed(tuple, index, &b32);
}

[[gnu::always_inline]] static inline monad_abi_err_t
monad_solenc_tuple_set_uint_be(
    struct monad_solenc_tuple *tuple, size_t index, size_t uint_bytes,
    void const *u)
{
    struct monad_bytes32 b32;

    if (MONAD_UNLIKELY(uint_bytes > 32)) {
        return MONAD_ABIERR_ILLEGAL_UINT;
    }
    __attribute__((assume(uint_bytes <= 32)));
    __builtin_memset(b32.bytes, 0, sizeof b32 - uint_bytes);
    __builtin_memcpy(b32.bytes + (sizeof b32 - uint_bytes), u, uint_bytes);
    return monad_solenc_tuple_set_fixed(tuple, index, &b32);
}

[[gnu::always_inline]] static inline monad_abi_err_t
monad_solenc_tuple_set_uint_he(
    struct monad_solenc_tuple *tuple, size_t index, size_t uint_bytes,
    void const *u)
{
#if __STDC_ENDIAN_NATIVE__ == __STDC_ENDIAN_BIG__
    return monad_solenc_tuple_set_uint_be(tuple, index, uint_bytes, u);
#else
    monad_abi_err_t err;
    struct monad_bytes32 b32;

    err = monad_uint256_be_from_he(&b32, uint_bytes, u);
    if (err) {
        return err;
    }
    return monad_solenc_tuple_set_fixed(tuple, index, &b32);
#endif
}

monad_abi_err_t monad_solabi_encode_address(
    struct monad_address const *addr, void *buf, size_t *buflen);

monad_abi_err_t
monad_solabi_encode_sv(struct monad_sv sv, void *buf, size_t *buflen);

monad_abi_err_t
monad_solabi_encode_uint(struct monad_bv bv, void *buf, size_t *buflen);

monad_abi_err_t monad_solabi_encode_tuple_inputs(
    struct monad_bv prefix_blob, const struct monad_abi_input *inputs,
    size_t count, struct monad_bv postfix_blob, void *buf, size_t *buflen);

static monad_abi_err_t monad_solabi_encode_tuple_v(
    struct monad_bv prefix_blob, size_t element_count,
    struct monad_bv postfix_blob, void *buf, size_t *buflen, ...);

monad_abi_err_t monad_solabi_encode_tuple_valist(
    struct monad_bv prefix_blob, size_t element_count,
    struct monad_bv postfix_blob, void *buf, size_t *buflen, va_list ap);

[[gnu::always_inline]] inline monad_abi_err_t monad_solabi_encode_tuple_v(
    struct monad_bv prefix_blob, size_t element_count,
    struct monad_bv postfix_blob, void *buf, size_t *buflen, ...)
{
    monad_abi_err_t err;
    va_list ap;

    va_start(ap, buflen);
    err = monad_solabi_encode_tuple_valist(
        prefix_blob, element_count, postfix_blob, buf, buflen, ap);
    va_end(ap);
    return err;
}

#ifdef __cplusplus
} // extern "C"
#endif
