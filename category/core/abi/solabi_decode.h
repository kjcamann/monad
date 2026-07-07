#pragma once

/**
 * @file
 *
 * Implementation of a Solidity Contract ABI decoding library
 */

#include <limits.h>
#include <stdarg.h>
#include <stdbit.h>
#include <stddef.h>
#include <stdint.h>

#include <category/core/abi/abi.h>
#include <category/core/abi/error.h>
#include <category/core/bytes32.h>
#include <category/core/byteview.h>
#include <category/core/likely.h>

struct monad_address;
struct monad_sv;

#ifdef __cplusplus
extern "C"
{
#endif

/*
 * Solidity Decoder (soldec) API
 *
 * The `monad_soldec_` routines are the lowest layer of the Solidity decoder
 * APIs. At this layer, it is not really a "decoder" but closer to a "parser".
 * A brief explanation of why this is:
 *
 * Encoding a host-order uint64_t to the Solidity Contact ABI might byteswap
 * the integer to big endian and then widen it to 256 bits. "Decoding" would
 * mean giving back the original uint64_t.
 *
 * There are some helper functions that do this, but the core "soldec" level of
 * the API does not do that kind of tranformation: it is a zero-copy API. The
 * only thing it does is "rediscover structure" of bytes32 storage slots, like
 * a parser.
 *
 * The "heart and soul" of the Solidity ABI format is that it turns all typed
 * values into tuples, and each tuple element is a bytes32 slot. The only tuple
 * values that have meaning in the _encoding itself_ (as opposed to having
 * meaning to the user, who knows the higher-level types) are the offset and
 * length values that are used to record variably-sized values, i.e., values
 * that have "dynamic type."
 *
 * Because the lowest-level API does not understand the meaning of any higher
 * level type system, the only thing it does is parse out the structure of
 * nested tuples, when they originated from dynamic types.
 *
 * The central object in the API is the tuple, `struct monad_soldec_tuple`. It
 * is a view-like type: a non-owning range of some of the bytes32 values whose
 * values live in the (const) decode buffer. To start decoding, you initialize
 * a "context" object with a byte view, and specify the number of elements in
 * the top-level tuple.
 *
 * From there, if any elements in the top-level tuple are dynamic, you can get
 * zero-copy views to those nested tuples. The `bytes` type is a special case:
 * it won't return another tuple, but instead the byte view type,
 * `struct monad_bv`.
 */

struct monad_soldec_ctx;

// clang-format off

/// A "view-like" type that is a non-owning reference to a range of bytes32
/// values in the context's decode buffer; this type is also used to describe
/// the values in dynamic arrays and dynamic tuples (these are "fixed-sized"
/// also, after their dynamic lengths have been parsed by the library)
struct monad_soldec_tuple
{
    struct monad_soldec_ctx const *ctx; ///< Decoder context we're in
    struct monad_bytes32 const *values; ///< Pointer to EVM words in tuple
    size_t element_count;               ///< Size of tuple/array (or bytes len)
};

// clang-format on

/// The decoder context object; this defines the span of all overall buffer
/// holding the encoded bytes, and the storage for the top-level tuple
struct monad_soldec_ctx
{
    struct monad_bytes32 const *begin;
    struct monad_bytes32 const *end;
    struct monad_soldec_tuple top_level;
};

/// Initialize a decoder context using the raw bytes of a byte view. This
/// also initializes the top-level fixed-sized tuple, `ctx->top_level`; the
/// caller must pass in the number of tuple elements as `element_count`
monad_abi_err_t monad_soldec_ctx_init(
    struct monad_soldec_ctx *ctx, struct monad_bv bytes, size_t element_count,
    bool strict);

/// Given a tuple where the `index` element is a fixed-sized object (a "static"
/// object in Soliduty ABI terms), return a pointer to that object's bytes32
/// slot. This is the same as `&tuple->values[index]`, but with bounds checking
monad_abi_err_t monad_soldec_tuple_get_fixed(
    struct monad_soldec_tuple const *tuple, size_t index,
    struct monad_bytes32 const **value_p);

/// Given a tuple where the `index` element encodes a dynamic array, initialize
/// a new tuple view object (`array`) that points to the elements of that array;
/// `array->element_count` will be set to the array length
monad_abi_err_t monad_soldec_tuple_get_dynamic_array(
    struct monad_soldec_tuple const *tuple, size_t index,
    struct monad_soldec_tuple *array);

/// Given a tuple where the `index` element encodes a dynamic tuple, initialize
/// a new tuple view object (`dyn_tuple`) that points to the elements of that
/// dynamic tuple; the user must pass the expected number of the elements in the
/// dynamic tuple, because the ABI format does not record it
monad_abi_err_t monad_soldec_tuple_get_dynamic_tuple(
    struct monad_soldec_tuple const *tuple, size_t index,
    size_t dyn_tuple_element_count, struct monad_soldec_tuple *dyn_tuple);

/// Given a tuple where the `index` element encodes a dynamic `bytes` array,
/// initialize a byte view that points to its data
monad_abi_err_t monad_soldec_tuple_get_bytes(
    struct monad_soldec_tuple const *tuple, size_t index,
    struct monad_bv *bytes);

/*
 * Solidity ABI decoding helper functions
 *
 * While the `soldec` family of APIs only works with zero-copy views of
 * `bytes32`, the helper functions below assume some kind of interpretation
 * for the a value in a `bytes32` slot. At a higher layer of the decoding
 * process (which presumably knows the typed schema), these can be called to
 * extract real values:
 *
 * - The `monad_solabi_X_from_bytes32` functions frame (and decode if necessary)
 *   the bits of a bytes32 slot that are assumed to hold a C value of type 'X',
 *   e.g., `monad_solabi_address_from_bytes32` returns the last 20 bytes of the
 *   bytes32 slot, with the pointer type-cast to `struct monad_address const *`
 *
 * - The `monad_solabi_decode_X` functions decode a single value of C type
 *   'X' directly from a byte buffer, i.e., there is no need to create the
 *   context or tuple temporary objects
 */

/// Given a bytes32 slot containing an unsigned integer that is `uint_bytes`
/// bytes long, set `*u_be` so that it points to the start of that integer; this
/// is a zero-copy API, so the integer remains in big-endian order; overflow
/// checking is performed
static monad_abi_err_t monad_solabi_uint_be_from_bytes32(
    struct monad_bytes32 const *b32, size_t uint_bytes, void const **u_be);

/// Given a bytes32 slot containing an unsigned integer that is `uint_bytes`
/// bytes long, set `*u` to the value of that integer in host order; this will
/// copy the value no matter the endianness of the host, and for little endian
/// systems it will byteswap the integer
static monad_abi_err_t monad_solabi_uint_he_from_bytes32(
    struct monad_bytes32 const *b32, size_t uint_bytes, void *u);

/// Given a bytes32 slot containing an address, set `*addr_p` so that it points
/// to that address; also ensures the leading 12 bytes are zero
static monad_abi_err_t monad_solabi_address_from_bytes32(
    struct monad_bytes32 const *b32, struct monad_address const **addr_p);

/// Given a byte view containing a single encoded byte array, initialize
/// the byte view parameter `array` to refer to the bytes of this array
static monad_abi_err_t
monad_solabi_decode_bytes(struct monad_bv bytes, struct monad_bv *array);

/// Given a byte view containing a single encoded UTF-8 string, initialize
/// the string view parameter `str` to refer to the bytes of this string
static monad_abi_err_t
monad_solabi_decode_string(struct monad_bv bytes, struct monad_sv *str);

/// Given a byte view containing a single encoded address, initialize
/// `addr` to point to this bytes of this address
static monad_abi_err_t monad_solabi_decode_address(
    struct monad_bv bytes, struct monad_address const **addr);

/// Given a byte view containing only fixed-sized types, return a zero-copy
/// view of the bytes32 slots
static monad_abi_err_t monad_solabi_decode_fixed(
    struct monad_bv bytes, struct monad_bytes32 const **outputs,
    size_t element_count);

// clang-format off

/*
 * Solidity ABI single tuple "unpack" functions
 *
 * These functions are used to decode multiple values from a tuple in a single
 * function call. All of the following functions perform that same task, but
 * with the inputs and outputs specified in different ways:
 *
 *   - The function can specify the schema and the output buffers using an
 *     array of typed buffer objects (the `_bufs` variant) or it can use
 *     variadic arguments; the latter come in two flavors, the `_v` variants
 *     are actually variadic (i.e., accepts `)...` and the `_valist` variants
 *     accept a `va_list`
 *
 *   - The tuple to be unpacked can be passed in directly, or as a convenience,
 *     a byte view can be used instead (raw bytes containing an encoded
 *     sequence, implying the top-level tuple); the former are called
 *     `unpack_tuple` and the latter, `unpack_byteview`
 *
 * Here is an example of the "byteview" form, using typed output buffers
 * to decode the schema `(address, uint256, <nested-array>)`:
 *
 *   ```c
 *   // decodes the tuple `(address, uint256, <nested-array>)` using typed
 *   // output buffers (type `struct monad_abi_output`)
 *   void decode_bufs_example(struct monad_bv encoded_bytes)
 *   {
 *     monad_abi_err_t err;
 *     struct monad_address const **addr;
 *     mrv_uint256_t value;
 *     struct monad_soldec_tuple nested_array;
 *
 *     // This array specifies the types of the tuple elements, and the output
 *     // buffers where the decoded value is written; if the decoding is zero
 *     // copy (as it is for `struct monad_address`), the output pointer has
 *     // type `void const **` and is initialize via the `view` field of the
 *     // `ptr` union: the pointer is updated to point at the data, but no copy
 *     // is made
 *     struct monad_abi_output outputs[] = {
 *       [0] = {.type = MONAD_ABI_TYPE_ADDRESS, .ptr = {.view = (void const **)addr}},
 *       [1] = {.type = MONAD_ABI_TYPE_UINT_HE, .ptr = {.buf = &value}, .size = sizeof *value},
 *       [2] = {.type = MONAD_ABI_TYPE_DYNAMIC_ARRAY, .ptr = {.buf = &nested_array}}
 *     };
 *
 *     err = monad_solabi_unpack_byteview_bufs(
 *         encoded_bytes, 0, outputs, countof(outputs));
 *     if (err) {
 *       return err;
 *     }
 *
 *     printf("the nested array has %u elements!", nested_array.element_count);
 *   }
 *   ```
 *
 * Here is the same example with the variadic form:
 *
 *   ```c
 *   // decodes the tuple `(address, uint256, <nested-array>)` using variadic
 *   // specification of output buffers
 *   void decode_variadic_example(struct monad_bv encoded_bytes)
 *   {
 *     monad_abi_err_t err;
 *     struct monad_address const **addr;
 *     mrv_uint256_t value;
 *     struct monad_soldec_tuple nested_array;
 *
 *     err = monad_solabi_unpack_byteview_v(encoded_bytes, 0, 3,
 *         MONAD_ABI_TYPE_ADDRESS, addr,
 *         MONAD_ABI_TYPE_UINT_HE, &value, sizeof value,
 *         MONAD_ABI_TYPE_DYNAMIC_ARRAY, &nested_array);
 *
 *     printf("the nested array has %u elements!", nested_array.element_count);
 *   }
 *   ```
 *
 * Given a tuple (or a byteview containing one) the caller specifies the start
 * element index, the number of elements to decode, and a variadic sequence
 * specifying how to decode the values and the output pointers to hold them.
 *
 * Note that the variadic form has to specify the number of elements in the
 * tuple to decode, whereas the typed output buffer variant knows this already:
 * it's also the number of output buffer entries.
 *
 * For each tuple element, a variadic argument describes what kind of value is
 * next in the tuple, followed by an argument specifying the output pointer that
 * accepts the decoded value. The integer types also require a third argument
 * specifying the number of bytes in the integer.
 *
 * Two things to note about the variadic form:
 *
 *   - The output pointer for some types is `const T **` instead of `T *`,
 *     e.g., for MONAD_ABI_TYPE_ADDRESS. This is because some values do not
 *     require any decoding so we can just point to the byte range in the
 *     original encoded buffer in a zero-copy fashion. The two types that
 *     behave this way are ADDRESS and UINT_BE (big endian integers)
 *
 *   - Most types are followed by one argument (the output pointer), but
 *     integers are followed by two. The first one gives the number of bytes
 *     in the integer, which can be any number between 1 and 32 to handle
 *     Solidity types like uint112 (14 bytes)
 */

static monad_abi_err_t monad_solabi_unpack_byteview_bufs(
    struct monad_bv bytes, size_t start_element,
    struct monad_abi_output *outputs, size_t count);

static monad_abi_err_t monad_solabi_unpack_tuple_bufs(
    struct monad_soldec_tuple const *, size_t start_element,
    struct monad_abi_output *outputs, size_t count);

static monad_abi_err_t monad_solabi_unpack_byteview_v(
    struct monad_bv bytes, size_t start_element, size_t element_count, ...);

static monad_abi_err_t monad_solabi_unpack_tuple_v(
    struct monad_soldec_tuple const *, size_t start_element,
    size_t element_count, ...);

static monad_abi_err_t monad_solabi_unpack_byteview_valist(
    struct monad_bv bytes, size_t start_element, size_t element_count,
    va_list ap);

monad_abi_err_t monad_solabi_unpack_tuple_valist(
    struct monad_soldec_tuple const *, size_t start_element,
    size_t element_count, va_list ap);

// clang-format on

/*
 * Inline implementations of helpers
 */

inline monad_abi_err_t monad_solabi_uint_be_from_bytes32(
    struct monad_bytes32 const *b32, size_t uint_bytes, void const **u)
{
    if (MONAD_UNLIKELY(uint_bytes > 32)) {
        return MONAD_ABIERR_ILLEGAL_UINT;
    }
    __attribute__((assume(uint_bytes <= 32)));
    if (MONAD_UNLIKELY(
            __builtin_memcmp(
                b32, &MONAD_BYTES32_ZERO, sizeof *b32 - uint_bytes) != 0)) {
        return MONAD_ABIERR_OVERFLOW;
    }
    *u = &b32->bytes[sizeof *b32 - uint_bytes];
    return 0;
}

inline monad_abi_err_t monad_solabi_uint_he_from_bytes32(
    struct monad_bytes32 const *b32, size_t uint_bytes, void *u)
{
    void const *be;
    monad_abi_err_t err;

    err = monad_solabi_uint_be_from_bytes32(b32, uint_bytes, &be);
    if (err) {
        return err;
    }
#if __STDC_ENDIAN_NATIVE__ == __STDC_ENDIAN_BIG__
    __attribute__((assume(uint_bytes <= 32)));
    __builtin_memcpy(u, be, uint_bytes);
    return 0;
#else
    return monad_uint256_be_to_he(be, uint_bytes, u);
#endif
}

[[gnu::always_inline]] inline monad_abi_err_t monad_solabi_address_from_bytes32(
    struct monad_bytes32 const *b32, struct monad_address const **addr_p)
{
    if (MONAD_UNLIKELY(__builtin_memcmp(b32, &MONAD_BYTES32_ZERO, 12) != 0)) {
        return MONAD_ABIERR_OVERFLOW;
    }
    *addr_p = (struct monad_address const *)((uint8_t const *)b32 + 12);
    return 0;
}

[[gnu::always_inline]] inline monad_abi_err_t
monad_solabi_decode_bytes(struct monad_bv bytes, struct monad_bv *array)
{
    monad_abi_err_t err;
    struct monad_soldec_ctx ctx;

    err = monad_soldec_ctx_init(&ctx, bytes, 1, /*strict*/ false);
    if (err) {
        return err;
    }
    return monad_soldec_tuple_get_bytes(&ctx.top_level, 0, array);
}

[[gnu::always_inline]] inline monad_abi_err_t
monad_solabi_decode_string(struct monad_bv bytes, struct monad_sv *str)
{
    return monad_solabi_decode_bytes(bytes, (struct monad_bv *)str);
}

[[gnu::always_inline]] inline monad_abi_err_t monad_solabi_decode_address(
    struct monad_bv bytes, struct monad_address const **addr)
{
    monad_abi_err_t err;
    struct monad_soldec_ctx ctx;

    *addr = nullptr;
    err = monad_soldec_ctx_init(&ctx, bytes, 1, /*strict*/ false);
    if (err) {
        return err;
    }
    return monad_solabi_address_from_bytes32(ctx.top_level.values, addr);
}

[[gnu::always_inline]] inline monad_abi_err_t monad_solabi_decode_fixed(
    struct monad_bv bytes, struct monad_bytes32 const **outputs,
    size_t element_count)
{
    monad_abi_err_t err;
    struct monad_soldec_ctx ctx;

    *outputs = nullptr;
    err = monad_soldec_ctx_init(&ctx, bytes, element_count, /*strict*/ false);
    if (err) {
        return err;
    }
    *outputs = ctx.top_level.values;
    return 0;
}

inline monad_abi_err_t monad_solabi_unpack_byteview_bufs(
    struct monad_bv bytes, size_t start_element,
    struct monad_abi_output *outputs, size_t count)
{
    monad_abi_err_t err;
    struct monad_soldec_ctx ctx;

    if (count > UINT32_MAX) {
        return MONAD_ABIERR_TUPLE_RANGE;
    }
    err = monad_soldec_ctx_init(&ctx, bytes, count, /*strict*/ false);
    if (err) {
        return err;
    }
    return monad_solabi_unpack_tuple_bufs(
        &ctx.top_level, start_element, outputs, count);
}

// This is a somewhat large function and an unusual candidate for inlining; the
// hope here is that if `count` is relatively small and `outputs` is known at
// the call site, this could be aggressively unrolled and turned into something
// nearly hand-written
inline monad_abi_err_t monad_solabi_unpack_tuple_bufs(
    struct monad_soldec_tuple const *tuple, size_t start_element,
    struct monad_abi_output *outputs, size_t count)
{
    monad_abi_err_t err;

    if (start_element + count >= (size_t)tuple->element_count) {
        return MONAD_ABIERR_TUPLE_RANGE;
    }

    for (size_t i = 0; i < count; ++i) {
        struct monad_bytes32 const *b32;
        uint8_t const *uint_be;
        struct monad_abi_output *outbuf;
        size_t const index = i + start_element;

        b32 = &tuple->values[index];
        outbuf = &outputs[i];
        err = 0;

        switch (outbuf->type) {
        case MONAD_ABI_TYPE_ADDRESS:
            if (outbuf->ptr.view != nullptr) {
                err = monad_solabi_address_from_bytes32(
                    b32, (struct monad_address const **)outbuf->ptr.view);
            }
            break;

        case MONAD_ABI_TYPE_UINT_BE:
            if (outbuf->ptr.view != nullptr) {
                err = monad_solabi_uint_be_from_bytes32(
                    b32, outbuf->size, outbuf->ptr.view);
            }
            break;

        case MONAD_ABI_TYPE_UINT_HE:
            if (outbuf->ptr.buf != nullptr) {
                err = monad_solabi_uint_he_from_bytes32(
                    b32, outbuf->size, outbuf->ptr.buf);
            }
            break;

        case MONAD_ABI_TYPE_BOOL:
            if (outbuf->ptr.buf != nullptr) {
                err = monad_solabi_uint_be_from_bytes32(
                    b32, 1, (void const **)&uint_be);
                if (err == 0) {
                    *(bool *)outbuf->ptr.buf = uint_be;
                }
            }
            break;

        case MONAD_ABI_TYPE_STRING:
            [[fallthrough]];
        case MONAD_ABI_TYPE_BYTES:
            if (outbuf->ptr.buf != nullptr) {
                err =
                    monad_soldec_tuple_get_bytes(tuple, index, outbuf->ptr.buf);
            }
            break;

        case MONAD_ABI_TYPE_DYNAMIC_ARRAY:
            if (outbuf->ptr.buf != nullptr) {
                err = monad_soldec_tuple_get_dynamic_array(
                    tuple, index, outbuf->ptr.buf);
            }
            break;

        case MONAD_ABI_TYPE_DYNAMIC_TUPLE:
            if (outbuf->ptr.buf != nullptr) {
                err = monad_soldec_tuple_get_dynamic_tuple(
                    tuple, index, outbuf->size, outbuf->ptr.buf);
            }
            break;

        default:
            return MONAD_ABIERR_UNKNOWN_ABI_TYPE;
        }

        if (err) {
            return err;
        }
    }

    return 0;
}

[[gnu::always_inline]] inline monad_abi_err_t monad_solabi_unpack_byteview_v(
    struct monad_bv bytes, size_t start_element, size_t element_count, ...)
{
    monad_abi_err_t err;
    va_list ap;

    va_start(ap, element_count);
    err = monad_solabi_unpack_byteview_valist(
        bytes, start_element, element_count, ap);
    va_end(ap);
    return err;
}

[[gnu::always_inline]] inline monad_abi_err_t monad_solabi_unpack_tuple_v(
    struct monad_soldec_tuple const *tuple, size_t start_element,
    size_t element_count, ...)
{
    monad_abi_err_t err;
    va_list ap;

    va_start(ap, element_count);
    err = monad_solabi_unpack_tuple_valist(
        tuple, start_element, element_count, ap);
    va_end(ap);
    return err;
}

[[gnu::always_inline]] inline monad_abi_err_t
monad_solabi_unpack_byteview_valist(
    struct monad_bv bytes, size_t start_element, size_t element_count,
    va_list ap)
{
    monad_abi_err_t err;
    struct monad_soldec_ctx ctx;

    err = monad_soldec_ctx_init(&ctx, bytes, element_count, /*strict*/ false);
    if (err) {
        return err;
    }
    return monad_solabi_unpack_tuple_valist(
        &ctx.top_level, start_element, element_count, ap);
}

#ifdef __cplusplus
} // extern "C"
#endif
