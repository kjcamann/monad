#include <errno.h>
#include <stdint.h>
#include <string.h>

#include <monad-c/rlp/rlp_decode.h>
#include <monad-c/support/bit.h>
#include <monad-c/support/result.h>

monad_result rlp_make_decode_error(enum rlp_decode_error err) {
    // TODO(ken): don't know how the category stuff is going to work yet
    switch (err) {
    case RLP_DECODE_NOT_RLP:
        return monad_make_sys_error(EPROTO);
    case RLP_DECODE_WRONG_TYPE:
        return monad_make_sys_error(EPROTOTYPE);
    case RLP_DECODE_NO_SPACE:
        return monad_make_sys_error(ENOBUFS);
    default:
        return monad_make_sys_error(EINVAL);
    }
}

monad_result rlp_value_decode(rlp_buf_t b, struct rlp_value *value) {
    uint8_t length_bytes;
    uint64_t length, *plength;

    if (b.begin == nullptr || b.end == nullptr) {
        *value = RLP_INVALID_VALUE;
        return monad_make_sys_error(EFAULT);
    } else if (b.begin == b.end) {
        // RLP encoding cannot be empty
        *value = RLP_INVALID_VALUE;
        return rlp_make_decode_error(RLP_DECODE_NOT_RLP);
    }

    const uint8_t first_byte = b.begin[0];
    value->encoded_range.begin = b.begin;
    if (first_byte < 128) {
        value->type = RLP_TYPE_BYTE_ARRAY;
        value->payload_offset = 0;
        length = 1;
    } else if (first_byte >= 128 && first_byte < 184) {
        value->type = RLP_TYPE_BYTE_ARRAY;
        value->payload_offset = 1;
        length = first_byte - 128;
    } else if (first_byte >= 184 && first_byte < 192) {
        value->type = RLP_TYPE_BYTE_ARRAY;
        length_bytes = first_byte - 183;
        if (b.end - b.begin < 1 + length_bytes) {
            *value = RLP_INVALID_VALUE;
            return rlp_make_decode_error(RLP_DECODE_NOT_RLP);
        }
        value->payload_offset = 1 + length_bytes;
        plength = mcl_copy_uint_be(&length, sizeof length,
                                   value->encoded_range.begin + 1, length_bytes);
        if (plength == nullptr) {
            *value = RLP_INVALID_VALUE;
            return rlp_make_decode_error(RLP_DECODE_NOT_RLP);
        }
        length = be64toh(*plength);
    } else if (first_byte >= 192 && first_byte < 248) {
        value->type = RLP_TYPE_SEQUENCE;
        value->payload_offset = 1;
        length = first_byte - 192;
    } else {
        value->type = RLP_TYPE_SEQUENCE;
        length_bytes = first_byte - 247;
        if (b.end - b.begin < 1 + length_bytes) {
            *value = RLP_INVALID_VALUE;
            return rlp_make_decode_error(RLP_DECODE_NOT_RLP);
        }
        value->payload_offset = 1 + length_bytes;
        plength = mcl_copy_uint_be(&length, sizeof length,
                                   value->encoded_range.begin + 1, length_bytes);
        if (plength == nullptr) {
            *value = RLP_INVALID_VALUE;
            return rlp_make_decode_error(RLP_DECODE_NOT_RLP);
        }
        length = be64toh(*plength);
    }

    value->encoded_range.end = value->encoded_range.begin +
                               value->payload_offset + length;
    if (value->encoded_range.end > b.end) {
        return monad_make_sys_error(RLP_DECODE_NOT_RLP);
    }
    return monad_ok(value->type);
}

monad_result rlp_byte_array_copy(const struct rlp_value *value, void *buf,
                                 size_t buf_size) {
    size_t byte_array_size;
    if (buf == nullptr || value == nullptr)
        return monad_make_sys_error(EFAULT);
    if (value->type != RLP_TYPE_BYTE_ARRAY)
        return rlp_make_decode_error(RLP_DECODE_WRONG_TYPE);
    byte_array_size = rlp_value_length(value);
    if (byte_array_size > buf_size)
        return rlp_make_decode_error(RLP_DECODE_NO_SPACE);
    // TODO(ken): is this incorrect? couldn't unambiguously round-trip if
    //  we do this?
    memcpy(buf, rlp_value_data_begin(value), byte_array_size);
    memset((uint8_t*)buf + byte_array_size, 0, buf_size - byte_array_size);
    return monad_ok(byte_array_size);
}

monad_result rlp_byte_array_unpack_uint_be(const struct rlp_value *value,
                                           void *buf, size_t buf_size) {
    size_t byte_array_size;
    if (buf == nullptr || value == nullptr)
        return monad_make_sys_error(EFAULT);
    if (value->type != RLP_TYPE_BYTE_ARRAY)
        return rlp_make_decode_error(RLP_DECODE_WRONG_TYPE);
    byte_array_size = rlp_value_length(value);
    if (byte_array_size > buf_size)
        return rlp_make_decode_error(RLP_DECODE_NO_SPACE);
    (void)mcl_copy_uint_be(buf, buf_size, rlp_value_data_begin(value),
                           byte_array_size);
    return monad_ok(0);
}

monad_result rlp_byte_array_get_range(const struct rlp_value *value,
                                      struct mcl_cbyte_range *range) {
    if (value == nullptr || range == nullptr)
        return monad_make_sys_error(EFAULT);
    if (value->type != RLP_TYPE_BYTE_ARRAY)
        return rlp_make_decode_error(RLP_DECODE_WRONG_TYPE);
    range->begin = rlp_value_data_begin(value);
    range->end = rlp_value_data_end(value);
    return monad_ok(range->end - range->begin);
}

monad_result rlp_sequence_open_iter(const struct rlp_value *sequence,
                                    struct rlp_iterator *i) {
    rlp_buf_t next_val_buf;
    if (sequence == nullptr || i == nullptr)
        return monad_make_sys_error(EFAULT);
    else if (sequence->type != RLP_TYPE_SEQUENCE)
        return rlp_make_decode_error(RLP_DECODE_WRONG_TYPE);
    i->parent_sequence = *sequence;
    next_val_buf.begin = sequence->encoded_range.begin + sequence->payload_offset;
    next_val_buf.end = sequence->encoded_range.end;
    if (next_val_buf.begin == next_val_buf.end) {
        i->next_item.type = RLP_TYPE_END_OF_SEQUENCE;
        i->next_item.payload_offset = 0;
        i->next_item.encoded_range = next_val_buf;
        return monad_ok(0);
    }
    return rlp_value_decode(next_val_buf, &i->next_item);
}

monad_result rlp_sequence_next(struct rlp_iterator *i,
                               struct rlp_value *value) {
    rlp_buf_t next_val_buf;
    monad_result mr;

    if (i == nullptr)
        return monad_make_sys_error(EFAULT);
    if (value != nullptr)
        *value = i->next_item;
    if (i->next_item.encoded_range.end == i->parent_sequence.encoded_range.end) {
        i->next_item.type = RLP_TYPE_END_OF_SEQUENCE;
        i->next_item.payload_offset = 0;
        i->next_item.encoded_range.begin = i->next_item.encoded_range.end;
    } else {
        next_val_buf.begin = i->next_item.encoded_range.end;
        next_val_buf.end = i->parent_sequence.encoded_range.end;
        mr = rlp_value_decode(next_val_buf, &i->next_item);
        if (monad_is_error(mr))
            return mr;
    }
    return monad_ok(0);
}