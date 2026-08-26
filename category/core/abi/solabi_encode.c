#include <alloca.h>
#include <errno.h>
#include <stdarg.h>
#include <stdbit.h>
#include <stddef.h>
#include <string.h>

#include <category/core/abi/abi.h>
#include <category/core/abi/error.h>
#include <category/core/abi/solabi_encode.h>
#include <category/core/address.h>
#include <category/core/assert.h>
#include <category/core/bytes32.h>
#include <category/core/mem/align.h>
#include <category/core/mem/cma/cma_alloc.h>
#include <category/core/mem/cma/cma_bump.h>
#include <category/core/strview.h>

static monad_abi_err_t set_dynamic_slot(
    struct monad_solenc_tuple *tuple, size_t index, monad_solenc_type_t type,
    size_t dynamic_element_count, struct monad_solenc_tuple **dynamic_p)
{
    int rc;
    size_t slots;
    size_t bytes_required;
    struct monad_solenc_tuple *dynamic;
    struct monad_memblk dynamic_memblk;

    *dynamic_p = nullptr;
    switch (type) {
    case MONAD_SOLENC_DYNAMIC_TUPLE:
        [[fallthrough]];
    case MONAD_SOLENC_DYNAMIC_ARRAY:
        slots = dynamic_element_count;
        break;

    case MONAD_SOLENC_BYTES:
        slots = monad_round_size_to_align(dynamic_element_count, 32);
        break;

    default:
        MONAD_ABORT_PRINTF("unexpected type code %hhu", type);
    }

    bytes_required = sizeof *dynamic + slots * (sizeof(struct monad_bytes32) +
                                                sizeof(monad_solenc_type_t));
    rc = monad_cma_alloc(
        tuple->ctx->alloc, bytes_required, /*align*/ 1, &dynamic_memblk);
    if (rc) {
        return rc;
    }
    *dynamic_p = dynamic = (struct monad_solenc_tuple *)dynamic_memblk.ptr;
    dynamic->ctx = tuple->ctx;
    dynamic->types = (monad_solenc_type_t *)(dynamic + 1);
    dynamic->values =
        (union monad_solenc_value *)(dynamic->types + dynamic_element_count);
    dynamic->memblk = dynamic_memblk;
    dynamic->element_count = dynamic_element_count;
    dynamic->no_dynamic = true;
    memset(dynamic->types, MONAD_SOLENC_UNINIT, dynamic->element_count);

    tuple->types[index] = type;
    tuple->values[index].dynamic = dynamic;
    tuple->no_dynamic = false;
    return 0;
}

static size_t count_storage_slots(const struct monad_solenc_tuple *tuple)
{
    size_t slots = tuple->element_count;

    if (tuple->no_dynamic) {
        return slots;
    }

    for (size_t i = 0; i < tuple->element_count; ++i) {
        switch (tuple->types[i]) {
        case MONAD_SOLENC_UNINIT:
            [[fallthrough]];
        case MONAD_SOLENC_FIXED:
            continue;
        case MONAD_SOLENC_DYNAMIC_TUPLE:
            slots += count_storage_slots(tuple->values[i].dynamic);
            break;
        case MONAD_SOLENC_DYNAMIC_ARRAY:
            slots += 1 + count_storage_slots(tuple->values[i].dynamic);
            break;
        case MONAD_SOLENC_BYTES:
            slots +=
                1 + monad_round_size_to_align(
                        (size_t)tuple->values[i].dynamic->element_count, 32) /
                        32;
            break;
        default:
            MONAD_ABORT_PRINTF("unexpected type code %hhu", tuple->types[i]);
        }
    }

    return slots;
}

static struct monad_bytes32 *serialize_tuple(
    struct monad_solenc_tuple const *tuple, struct monad_bytes32 *const begin,
    bool *has_uninit)
{
    size_t bytes_len;
    size_t bytes_resid;
    struct monad_bytes32 *next;
    struct monad_bytes32 *end;

    if (tuple->no_dynamic && !tuple->ctx->strict) {
        // This tuple has no dynamic elements, we can just memcpy it; we can
        // only do this when strict mode is disabled (as it is here), because
        // strict mode must visit each element to check if it was never set
        return mempcpy(
            begin,
            tuple->values,
            sizeof(struct monad_bytes32) * tuple->element_count);
    }

    next = begin;
    end = begin + tuple->element_count;
    for (size_t i = 0; i < tuple->element_count; ++i) {
        union monad_solenc_value const *const value = &tuple->values[i];

        switch (tuple->types[i]) {
        case MONAD_SOLENC_UNINIT:
            *has_uninit = true;
            __builtin_memset(next++, 0, sizeof *next);
            break;

        case MONAD_SOLENC_FIXED:
            __builtin_memcpy(next++, &value->fixed, sizeof *next);
            break;

        case MONAD_SOLENC_DYNAMIC_TUPLE:
            monad_uint256_be_from_u64(next++, (uint64_t)(end - begin));
            end = serialize_tuple(value->dynamic, end, has_uninit);
            break;

        case MONAD_SOLENC_DYNAMIC_ARRAY:
            monad_uint256_be_from_u64(next++, (uint64_t)(end - begin));
            monad_uint256_be_from_u64(end++, value->dynamic->element_count);
            end = serialize_tuple(value->dynamic, end, has_uninit);
            break;

        case MONAD_SOLENC_BYTES:
            bytes_len = value->dynamic->element_count;
            monad_uint256_be_from_u64(next++, (uint64_t)(end - begin));
            monad_uint256_be_from_u64(end++, bytes_len);
            end = mempcpy(end, value->dynamic->values, bytes_len);
            bytes_resid = monad_round_size_to_align(bytes_len, 32) - bytes_len;
            memset(end, 0, bytes_resid);
            end = (struct monad_bytes32 *)((uint8_t *)end + bytes_resid);
            break;

        default:
            MONAD_ABORT_PRINTF("unexpected type code %hhu", tuple->types[i]);
        }
    }

    return end;
}

// When a top-level tuple has no dynamic elements, we can often avoid a second
// memory allocation; this helper function handles this case
static monad_abi_err_t serialize_no_dynamic(
    struct monad_solenc_ctx *ctx, struct monad_allocator *serial_alloc,
    struct monad_bv postfix_blob, struct monad_memblk *memblk,
    struct monad_bv *bytes)
{
    int rc;
    bool has_uninit = false;
    struct monad_solenc_tuple *const tuple = &ctx->top_level;
    size_t const postfix_len = monad_bv_len(postfix_blob);
    size_t const bytes_required = tuple->memblk.size + postfix_len;

    if (serial_alloc != ctx->alloc) {
        // The destination allocator is different, we need a second allocation
        void *end;

        rc = monad_cma_alloc(serial_alloc, bytes_required, /*align*/ 1, memblk);
        if (rc) {
            return rc;
        }
        end = serialize_tuple(
            tuple, (struct monad_bytes32 *)memblk->ptr, &has_uninit);
        memcpy(end, postfix_blob.begin, postfix_len);
        bytes->begin = (uint8_t const *)memblk->ptr;
        bytes->end = bytes->begin + bytes_required;
        return has_uninit ? MONAD_ABIERR_ELEMENT_UNINIT : 0;
    }

    // We do not need a second allocation. We do not set `memblk` in this case
    // (and it is already zeroed out by the caller). Setting `memblk` would tell
    // the user that they have to free the allocation. Since we're reusing the
    // original tuple allocation, that is done by `monad_solenc_ctx_free`
    // instead.

    if (ctx->strict) {
        // Check for UNINIT
        for (size_t i = 0; i < tuple->element_count; ++i) {
            if (MONAD_UNLIKELY(tuple->types[i] == MONAD_SOLENC_UNINIT)) {
                __builtin_memset(
                    &tuple->values[i], 0, sizeof(struct monad_bytes32));
                has_uninit = true;
            }
        }
    }

    if (postfix_len > 0) {
        // We need to increase the original tuple allocation size to hold the
        // postfix blob and then copy it
        size_t const tuple_size = tuple->memblk.size;
        rc = monad_cma_realloc(
            serial_alloc, bytes_required, /*align*/ 1, &tuple->memblk);
        if (rc) {
            return rc;
        }
        memcpy(
            (uint8_t *)tuple->memblk.ptr + tuple_size,
            postfix_blob.begin,
            postfix_len);
    }

    bytes->begin = (uint8_t const *)tuple->memblk.ptr;
    bytes->end = bytes->begin + bytes_required;
    return has_uninit ? MONAD_ABIERR_ELEMENT_UNINIT : 0;
}

static void free_tuple_memory(struct monad_solenc_tuple *tuple)
{
    struct monad_allocator *const ma = tuple->ctx->alloc;

    for (size_t i = 0; i < tuple->element_count; ++i) {
        switch (tuple->types[i]) {
        case MONAD_SOLENC_UNINIT:
            [[fallthrough]];
        case MONAD_SOLENC_FIXED:
            continue;

        case MONAD_SOLENC_DYNAMIC_TUPLE:
            [[fallthrough]];
        case MONAD_SOLENC_DYNAMIC_ARRAY:
            [[fallthrough]];
        case MONAD_SOLENC_BYTES:
            free_tuple_memory(tuple->values[i].dynamic);
            monad_cma_dealloc(ma, tuple->values[i].dynamic->memblk);
            break;

        default:
            MONAD_ABORT_PRINTF("unexpected type code %hhu", tuple->types[i]);
        }
    }
    monad_cma_dealloc(ma, tuple->memblk);
}

static monad_abi_err_t set_tuple_inputs(
    struct monad_solenc_tuple *tuple, size_t start_index,
    struct monad_abi_input const *inputs, size_t count, bool allow_dynamic)
{
    monad_abi_err_t err;

    if (start_index + count > tuple->element_count) {
        return MONAD_ABIERR_TUPLE_RANGE;
    }

    for (size_t i = 0; i < count; ++i) {
        struct monad_abi_input const *const input = &inputs[i];
        size_t const index = i + start_index;

        err = 0;
        switch (input->type) {
        case MONAD_ABI_TYPE_ADDRESS:
            err = monad_solenc_tuple_set_address(
                tuple, index, (struct monad_address const *)input->ptr.fixed);
            break;

        case MONAD_ABI_TYPE_UINT_BE:
        case MONAD_ABI_TYPE_UINT_HE:
            err = monad_solenc_tuple_set_uint_be(
                tuple, index, input->size, input->ptr.fixed);
            break;

        case MONAD_ABI_TYPE_BOOL:
            err = monad_solenc_tuple_set_uint_be(
                tuple, index, 1, input->ptr.fixed);
            break;

        case MONAD_ABI_TYPE_STRING:
            [[fallthrough]];
        case MONAD_ABI_TYPE_BYTES:
            err = monad_solenc_tuple_set_bytes(
                tuple,
                index,
                (struct monad_bv){.begin = (uint8_t const *)input->ptr.fixed,
                                  .end = (uint8_t const *)input->ptr.fixed +
                                         input->size});
            break;

        case MONAD_ABI_TYPE_DYNAMIC_ARRAY:
            err = allow_dynamic
                      ? monad_solenc_tuple_set_dynamic_array(
                            tuple,
                            index,
                            input->size,
                            (struct monad_solenc_tuple **)input->ptr.dyn)
                      : MONAD_ABIERR_NO_DYNAMIC;
            break;

        case MONAD_ABI_TYPE_DYNAMIC_TUPLE:
            err = allow_dynamic
                      ? monad_solenc_tuple_set_dynamic_tuple(
                            tuple,
                            index,
                            input->size,
                            (struct monad_solenc_tuple **)input->ptr.dyn)
                      : MONAD_ABIERR_NO_DYNAMIC;
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

monad_abi_err_t monad_solenc_ctx_init(
    struct monad_solenc_ctx *ctx, struct monad_allocator *alloc,
    size_t element_count, struct monad_bv prefix_blob, bool strict)
{
    int rc;
    void *p;
    size_t bytes_required;
    size_t prefix_len;
    struct monad_solenc_tuple *const tuple = &ctx->top_level;

    __builtin_memset(ctx, 0, sizeof *ctx);
    ctx->alloc = alloc ? alloc : monad_cma_get_default_allocator();
    ctx->strict = strict;

    prefix_len = monad_bv_len(prefix_blob);
    bytes_required = (size_t)element_count * (sizeof(monad_solenc_type_t) +
                                              sizeof(struct monad_bytes32)) +
                     prefix_len;
    rc = monad_cma_alloc(
        ctx->alloc, bytes_required, /*align*/ 1, &tuple->memblk);
    if (rc) {
        return rc;
    }

    tuple->ctx = ctx;
    tuple->types = (monad_solenc_type_t *)tuple->memblk.ptr;
    p = prefix_blob.begin
            ? mempcpy(
                  tuple->types + element_count, prefix_blob.begin, prefix_len)
            : (uint8_t *)tuple->types + element_count;
    tuple->values = (union monad_solenc_value *)p;
    tuple->element_count = element_count;
    tuple->no_dynamic = true;
    memset(tuple->types, MONAD_SOLENC_UNINIT, tuple->element_count);
    return 0;
}

monad_abi_err_t monad_solenc_ctx_serialize(
    struct monad_solenc_ctx *ctx, struct monad_allocator *serial_alloc,
    struct monad_bv postfix_blob, struct monad_memblk *memblk,
    struct monad_bv *bytes)
{
    int rc;
    void *p;
    size_t slot_count;
    struct monad_bytes32 *end;
    size_t bytes_required;
    uint8_t const *prefix_start;
    bool has_uninit = false;
    struct monad_solenc_tuple *const tuple = &ctx->top_level;

    __builtin_memset(memblk, 0, sizeof *memblk);
    if (serial_alloc == nullptr) {
        serial_alloc = ctx->alloc;
    }

    if (tuple->no_dynamic) {
        return serialize_no_dynamic(
            ctx, serial_alloc, postfix_blob, memblk, bytes);
    }

    slot_count = count_storage_slots(tuple);
    bytes_required =
        slot_count * sizeof(struct monad_bytes32) + monad_bv_len(postfix_blob);
    rc = monad_cma_alloc(serial_alloc, bytes_required, /*align*/ 1, memblk);
    if (rc) {
        return rc;
    }

    // Copy the prefix byte sequence
    prefix_start = (uint8_t const *)(tuple->types + tuple->element_count);
    p = mempcpy(
        memblk->ptr,
        prefix_start,
        (uint8_t const *)tuple->values - prefix_start);
    bytes->begin = (uint8_t const *)p;

    // Serialize the top-level tuple
    end = serialize_tuple(tuple, (struct monad_bytes32 *)p, &has_uninit);

    // Copy the postfix byte sequence
    bytes->end = postfix_blob.begin
                     ? (uint8_t const *)mempcpy(
                           end, postfix_blob.begin, monad_bv_len(postfix_blob))
                     : (uint8_t const *)end;

    return has_uninit ? MONAD_ABIERR_ELEMENT_UNINIT : 0;
}

void monad_solenc_ctx_free(struct monad_solenc_ctx *ctx)
{
    free_tuple_memory(&ctx->top_level);
}

monad_abi_err_t monad_solenc_tuple_set_fixed(
    struct monad_solenc_tuple *tuple, size_t index,
    struct monad_bytes32 const *value)
{
    if (index > tuple->element_count) {
        return MONAD_ABIERR_TUPLE_RANGE;
    }

    // XXX: check if already marked as a nested tuple first, below allowing
    // this? or just clear the nested bit?
    tuple->types[index] = MONAD_SOLENC_FIXED;
    __builtin_memcpy(&tuple->values[index], value, sizeof *value);
    return 0;
}

monad_abi_err_t monad_solenc_tuple_set_dynamic_array(
    struct monad_solenc_tuple *tuple, size_t index, size_t array_size,
    struct monad_solenc_tuple **array)
{
    return set_dynamic_slot(
        tuple, index, MONAD_SOLENC_DYNAMIC_ARRAY, array_size, array);
}

monad_abi_err_t monad_solenc_tuple_set_dynamic_tuple(
    struct monad_solenc_tuple *tuple, size_t index,
    size_t dyn_tuple_element_count, struct monad_solenc_tuple **dyn_tuple)
{
    return set_dynamic_slot(
        tuple,
        index,
        MONAD_SOLENC_DYNAMIC_TUPLE,
        dyn_tuple_element_count,
        dyn_tuple);
}

monad_abi_err_t monad_solenc_tuple_set_bytes(
    struct monad_solenc_tuple *tuple, size_t index, struct monad_bv bytes)
{
    monad_abi_err_t err;
    struct monad_solenc_tuple *nested;
    size_t bytes_len;

    bytes_len = monad_bv_len(bytes);
    err = set_dynamic_slot(
        tuple, index, MONAD_SOLENC_DYNAMIC_TUPLE, bytes_len, &nested);
    if (err) {
        return err;
    }
    memcpy(nested->values, bytes.begin, bytes_len);
    return 0;
}

monad_abi_err_t monad_solenc_tuple_set_inputs(
    struct monad_solenc_tuple *tuple, size_t start_index,
    struct monad_abi_input const *inputs, size_t count)
{
    return set_tuple_inputs(
        tuple, start_index, inputs, count, /*allow_dynamic*/ true);
}

monad_abi_err_t monad_solabi_encode_address(
    struct monad_address const *addr, void *buf, size_t *buflen)
{
    if (*buflen < sizeof(struct monad_bytes32)) {
        *buflen = sizeof(struct monad_bytes32);
        return MONAD_ABIERR_NO_BUFFER_SPACE;
    }
    *buflen = sizeof(struct monad_bytes32);
    __builtin_memset(buf, 0, 12);
    __builtin_memcpy((uint8_t *)buf + 12, addr->bytes, sizeof *addr);
    return 0;
}

monad_abi_err_t
monad_solabi_encode_bytes(struct monad_bv bytes, void *buf, size_t *buflen)
{
    void *end;
    size_t const len = monad_bv_len(bytes);
    size_t const required = 64 + monad_round_size_to_align(len, 32);
    struct monad_bytes32 *head = (struct monad_bytes32 *)buf;

    if (*buflen < required) {
        *buflen = required;
        return MONAD_ABIERR_NO_BUFFER_SPACE;
    }
    monad_uint256_be_from_u64(head++, 32);
    monad_uint256_be_from_u64(head++, len);
    end = mempcpy(head, bytes.begin, len);
    memset(end, 0, required - ((uint8_t const *)end - (uint8_t const *)buf));
    *buflen = required;
    return 0;
}

monad_abi_err_t
monad_solabi_encode_sv(struct monad_sv sv, void *buf, size_t *buflen)
{
    void *end;
    size_t const len = monad_sv_len(sv);
    size_t const required = 64 + monad_round_size_to_align(len, 32);
    struct monad_bytes32 *head = (struct monad_bytes32 *)buf;

    if (*buflen < required) {
        *buflen = required;
        return MONAD_ABIERR_NO_BUFFER_SPACE;
    }
    monad_uint256_be_from_u64(head++, 32);
    monad_uint256_be_from_u64(head++, len);
    end = mempcpy(head, sv.begin, len);
    memset(end, 0, required - ((uint8_t const *)end - (uint8_t const *)buf));
    *buflen = required;
    return 0;
}

monad_abi_err_t
monad_solabi_encode_uint(struct monad_bv bv, void *buf, size_t *buflen)
{
    int rc;
    struct monad_bytes32 *const b32 = (struct monad_bytes32 *)buf;
    size_t const uint_bytes = monad_bv_len(bv);

    if (*buflen < sizeof(struct monad_bytes32)) {
        *buflen = sizeof(struct monad_bytes32);
        return MONAD_ABIERR_NO_BUFFER_SPACE;
    }
    switch (monad_uint256_be_from_he(b32, uint_bytes, bv.begin)) {
    case EINVAL:
        return MONAD_ABIERR_ILLEGAL_UINT;
    default:
        break;
    }
    __attribute__((assume(*buflen <= 32)));
    __builtin_memset(buf, 0, sizeof *b32 - uint_bytes);
    *buflen = sizeof *b32;
    return 0;
}

monad_abi_err_t monad_solabi_encode_tuple_inputs(
    struct monad_bv prefix_blob, const struct monad_abi_input *inputs,
    size_t count, struct monad_bv postfix_blob, void *buf, size_t *buflen)
{
    int rc;
    monad_abi_err_t err;
    struct monad_solenc_ctx ctx;
    struct monad_cma_bump bump;
    struct monad_memblk bump_blk;
    struct monad_bv bytes;

    rc = monad_cma_bump_init(&bump, buf, *buflen, nullptr);
    if (rc) {
        return rc;
    }

    err = monad_solenc_ctx_init(
        &ctx, &bump.self, count, prefix_blob, /*strict*/ false);
    if (err) {
        return err == ENOMEM ? MONAD_ABIERR_NO_BUFFER_SPACE : err;
    }

    err = set_tuple_inputs(
        &ctx.top_level, 0, inputs, count, /*allow_dynamic*/ false);
    if (err) {
        return err;
    }

    err = monad_solenc_ctx_serialize(
        &ctx, &bump.self, postfix_blob, &bump_blk, &bytes);
    if (err) {
        return err == ENOMEM ? MONAD_ABIERR_NO_BUFFER_SPACE : err;
    }

    *buflen = monad_bv_len(bytes);
    return 0;
}

monad_abi_err_t monad_solabi_encode_tuple_valist(
    struct monad_bv prefix_blob, size_t element_count,
    struct monad_bv postfix_blob, void *buf, size_t *buflen, va_list ap)
{
    monad_abi_err_t err;
    struct monad_abi_input *inputs;

    inputs = (struct monad_abi_input *)alloca(
        sizeof(struct monad_abi_input) * element_count);
    for (size_t i = 0; i < element_count; ++i) {
        struct monad_abi_input *const input = &inputs[i];

        input->type = va_arg(ap, monad_abi_type_t);
        switch (input->type) {
        case MONAD_ABI_TYPE_ADDRESS:
            [[fallthrough]];
        case MONAD_ABI_TYPE_BOOL:
            input->ptr.fixed = va_arg(ap, void const *);
            break;

        case MONAD_ABI_TYPE_UINT_BE:
            [[fallthrough]];
        case MONAD_ABI_TYPE_UINT_HE:
            [[fallthrough]];
        case MONAD_ABI_TYPE_STRING:
            [[fallthrough]];
        case MONAD_ABI_TYPE_BYTES:
            input->ptr.fixed = va_arg(ap, void const *);
            input->size = va_arg(ap, size_t);
            break;

        case MONAD_ABI_TYPE_DYNAMIC_ARRAY:
            [[fallthrough]];
        case MONAD_ABI_TYPE_DYNAMIC_TUPLE:
            return MONAD_ABIERR_NO_DYNAMIC;

        default:
            return MONAD_ABIERR_UNKNOWN_ABI_TYPE;
        }
    }

    return monad_solabi_encode_tuple_inputs(
        prefix_blob, inputs, element_count, postfix_blob, buf, buflen);
}
