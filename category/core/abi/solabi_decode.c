#include <alloca.h>
#include <stdarg.h>
#include <stdbit.h>
#include <stddef.h>
#include <string.h>

#include <category/core/abi/abi.h>
#include <category/core/abi/error.h>
#include <category/core/abi/solabi_decode.h>
#include <category/core/bytes32.h>
#include <category/core/byteview.h>
#include <category/core/likely.h>

monad_abi_err_t monad_soldec_ctx_init(
    struct monad_soldec_ctx *ctx, struct monad_bv bytes, size_t element_count,
    bool strict)
{
    size_t const len = monad_bv_len(bytes);

    __builtin_memset(ctx, 0, sizeof *ctx);
    if (MONAD_UNLIKELY(strict && len % 32 != 0)) {
        return MONAD_ABIERR_UNALIGNED_EVM_WORD;
    }
    ctx->begin = (struct monad_bytes32 const *)bytes.begin;
    ctx->end = ctx->begin + len / 32;
    if (element_count > (size_t)(ctx->end - ctx->begin)) {
        return MONAD_ABIERR_TUPLE_RANGE;
    }
    ctx->top_level.ctx = ctx;
    ctx->top_level.values = ctx->begin;
    ctx->top_level.element_count = element_count;
    return 0;
}

monad_abi_err_t monad_soldec_tuple_get_fixed(
    struct monad_soldec_tuple const *tuple, size_t index,
    struct monad_bytes32 const **value_p)
{
    if (MONAD_UNLIKELY(index >= tuple->element_count)) {
        return MONAD_ABIERR_TUPLE_RANGE;
    }
    *value_p = &tuple->values[index];
    return 0;
}

monad_abi_err_t monad_soldec_tuple_get_dynamic_array(
    struct monad_soldec_tuple const *tuple, size_t index,
    struct monad_soldec_tuple *array)
{
    monad_abi_err_t err;
    struct monad_bytes32 const *offset_word;
    struct monad_bytes32 const *length_word;
    uint64_t offset;

    err = monad_soldec_tuple_get_fixed(tuple, index, &offset_word);
    if (err) {
        return err;
    }
    if (monad_uint256_be_to_u64(offset_word, &offset) != 0) {
        return MONAD_ABIERR_OFFSET_POINTS_OUTSIDE;
    }
    length_word =
        (struct monad_bytes32 const *)((uint8_t const *)tuple->values + offset);
    if (MONAD_UNLIKELY(length_word >= tuple->ctx->end)) {
        return MONAD_ABIERR_OFFSET_POINTS_OUTSIDE;
    }
    array->ctx = tuple->ctx;
    array->values = length_word + 1;
    if (monad_uint256_be_to_u64(
            length_word, (uint64_t *)&array->element_count) != 0) {
        return MONAD_ABIERR_OFFSET_POINTS_OUTSIDE;
    }
    if (MONAD_UNLIKELY(
            array->values + array->element_count > tuple->ctx->end)) {
        return MONAD_ABIERR_OFFSET_POINTS_OUTSIDE;
    }
    return 0;
}

monad_abi_err_t monad_soldec_tuple_get_dynamic_tuple(
    struct monad_soldec_tuple const *tuple, size_t index,
    size_t dyn_tuple_element_count, struct monad_soldec_tuple *dyn_tuple)
{
    monad_abi_err_t err;
    struct monad_bytes32 const *offset_word;
    uint64_t offset;

    err = monad_soldec_tuple_get_fixed(tuple, index, &offset_word);
    if (err) {
        return err;
    }
    if (monad_uint256_be_to_u64(offset_word, &offset) != 0) {
        return MONAD_ABIERR_OFFSET_POINTS_OUTSIDE;
    }
    dyn_tuple->ctx = tuple->ctx;
    dyn_tuple->values =
        (struct monad_bytes32 const *)((uint8_t const *)tuple->values + offset);
    dyn_tuple->element_count = dyn_tuple_element_count;
    if (MONAD_UNLIKELY(
            dyn_tuple->values + dyn_tuple->element_count > tuple->ctx->end)) {
        return MONAD_ABIERR_OFFSET_POINTS_OUTSIDE;
    }
    return 0;
}

monad_abi_err_t monad_soldec_tuple_get_bytes(
    struct monad_soldec_tuple const *tuple, size_t index,
    struct monad_bv *bytes)
{
    monad_abi_err_t err;
    struct monad_bytes32 const *offset_word;
    struct monad_bytes32 const *length_word;
    uint64_t offset;
    uint64_t length;

    err = monad_soldec_tuple_get_fixed(tuple, index, &offset_word);
    if (err) {
        return err;
    }
    if (monad_uint256_be_to_u64(offset_word, &offset) != 0) {
        return MONAD_ABIERR_OFFSET_POINTS_OUTSIDE;
    }
    length_word =
        (struct monad_bytes32 const *)((uint8_t const *)tuple->values + offset);
    if (MONAD_UNLIKELY(length_word >= tuple->ctx->end)) {
        return MONAD_ABIERR_OFFSET_POINTS_OUTSIDE;
    }
    if (monad_uint256_be_to_u64(length_word, &length) != 0) {
        return MONAD_ABIERR_OFFSET_POINTS_OUTSIDE;
    }
    bytes->begin = (uint8_t const *)(length_word + 1);
    bytes->end = bytes->begin + length;
    if (MONAD_UNLIKELY(
            (struct monad_bytes32 const *)bytes->end > tuple->ctx->end)) {
        return MONAD_ABIERR_OFFSET_POINTS_OUTSIDE;
    }
    return 0;
}

monad_abi_err_t monad_solabi_unpack_tuple_valist(
    struct monad_soldec_tuple const *tuple, size_t start_element,
    size_t element_count, va_list ap)
{
    struct monad_abi_output *outputs;

    if (start_element + element_count >= tuple->element_count) {
        return MONAD_ABIERR_TUPLE_RANGE;
    }

    outputs =
        (struct monad_abi_output *)alloca(element_count * sizeof *outputs);
    for (size_t i = 0; i < element_count; ++i) {
        struct monad_abi_output *const outbuf = &outputs[i];

        outbuf->type = va_arg(ap, monad_abi_type_t);
        switch (outbuf->type) {
        case MONAD_ABI_TYPE_ADDRESS:
            outbuf->ptr.view = va_arg(ap, void const **);
            break;

        case MONAD_ABI_TYPE_UINT_BE:
            outbuf->ptr.view = va_arg(ap, void const **);
            outbuf->size = va_arg(ap, size_t);
            break;

        case MONAD_ABI_TYPE_UINT_HE:
            [[fallthrough]];
        case MONAD_ABI_TYPE_DYNAMIC_TUPLE:
            outbuf->ptr.buf = va_arg(ap, void *);
            outbuf->size = va_arg(ap, size_t);
            break;

        case MONAD_ABI_TYPE_BOOL:
            [[fallthrough]];
        case MONAD_ABI_TYPE_STRING:
            [[fallthrough]];
        case MONAD_ABI_TYPE_BYTES:
            [[fallthrough]];
        case MONAD_ABI_TYPE_DYNAMIC_ARRAY:
            outbuf->ptr.buf = va_arg(ap, void *);
            break;

        default:
            return MONAD_ABIERR_UNKNOWN_ABI_TYPE;
        }
    }

    return monad_solabi_unpack_tuple_bufs(
        tuple, start_element, outputs, element_count);
}
