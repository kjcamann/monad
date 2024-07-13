#pragma once

#include <stddef.h>
#include <stdint.h>

#include <monad-c/support/range.h>
#include <monad-c/support/result.h>

typedef struct mcl_cbyte_range rlp_buf_t;

/**
 * Describes what kind of RLP object an @ref rlp_value instance represents.
 *
 * Conceptually an RLP encoding represents objects of the form:
 *
 *   value ::= byte-array | sequence
 *   sequence ::= value*
 *
 * A top-level RLP value is either a byte array or a sequence. Older Ethereum
 * documents call a sequence a "list".
 *
 * If an RLP value is a sequence, each item in the sequence is either a byte
 * array or a nested sequence. For ease of error reporting and iteration we
 * introduce two other types of RLP objects: invalid objects and a sentinel
 * value that indicates the sequence is finished.
 */
enum rlp_value_type : uint8_t {
    RLP_TYPE_INVALID,
    RLP_TYPE_END_OF_SEQUENCE,
    RLP_TYPE_BYTE_ARRAY,
    RLP_TYPE_SEQUENCE
};

struct rlp_value {
    enum rlp_value_type type;  ///< Type: byte array, sequence, invalid, EOS
    uint8_t payload_offset;    ///< Offset in encoded range where payload starts
    rlp_buf_t encoded_range;   ///< Raw bytes encoding the RLP value (w/ prefix)
};

struct rlp_iterator {
    struct rlp_value parent_sequence; ///< Sequence item we're iterating through
    struct rlp_value next_item;       ///< Item returned by rlp_sequence_next
};

constexpr struct rlp_value RLP_INVALID_VALUE = {
    .type = RLP_TYPE_INVALID,
    .payload_offset = 0,
    .encoded_range = {
        .begin = nullptr,
        .end = nullptr
    }
};

enum rlp_decode_error : int {
    RLP_DECODE_SUCCESS,    ///< Zero-initialization -> no error
    RLP_DECODE_NOT_RLP,    ///< Buffer does not contain valid RLP
    RLP_DECODE_WRONG_TYPE, ///< rlp_value_type did not match what API expected
    RLP_DECODE_NO_SPACE,   ///< Buffer provided for copy-out of value too small
};

monad_result rlp_make_decode_error(enum rlp_decode_error);

monad_result rlp_value_decode(rlp_buf_t b, struct rlp_value *value);

monad_result rlp_byte_array_copy(const struct rlp_value *value,
                                 void *buf, size_t buf_size);

monad_result rlp_byte_array_unpack_uint_be(const struct rlp_value *value,
                                           void *buf, size_t buf_size);

monad_result rlp_byte_array_get_range(const struct rlp_value *value,
                                      struct mcl_cbyte_range *range);

monad_result rlp_sequence_open_iter(const struct rlp_value *sequence,
                                    struct rlp_iterator *i);

monad_result rlp_sequence_next(struct rlp_iterator *i, struct rlp_value *value);

static inline const uint8_t *
rlp_value_data_begin(const struct rlp_value *value) {
    return value->encoded_range.begin + value->payload_offset;
}

static inline const uint8_t *
rlp_value_data_end(const struct rlp_value *value) {
    return value->encoded_range.end;
}

static inline uint64_t rlp_value_length(const struct rlp_value *value) {
    return rlp_value_data_end(value) - rlp_value_data_begin(value);
}

static inline bool rlp_value_is_empty_byte_array(const struct rlp_value *v) {
    return v->encoded_range.begin != nullptr && *v->encoded_range.begin == 128;
}

static inline bool rlp_value_is_empty_list(const struct rlp_value *v) {
    return v->encoded_range.begin != nullptr && *v->encoded_range.begin == 192;
}

static inline bool rlp_sequence_has_next(struct rlp_iterator *i) {
    return i != nullptr && i->next_item.type != RLP_TYPE_END_OF_SEQUENCE &&
           i->next_item.type != RLP_TYPE_INVALID;
}

static inline struct rlp_iterator rlp_sequence_make_null_iterator() {
    struct rlp_iterator i = {
        .parent_sequence = RLP_INVALID_VALUE,
        .next_item = RLP_INVALID_VALUE
    };
    return i;
}

#define RLP_DEFINE_DECODE_UINT_INTO_FN(SUFFIX, TYPE) \
static inline monad_result                                                   \
rlp_decode_uint_into_ ## SUFFIX(const struct rlp_value *value, TYPE *decoded) { \
    return rlp_byte_array_unpack_uint_be(value, decoded, sizeof *decoded); \
}

#define RLP_DEFINE_DECODE_VAR_BYTE_ARRAY_FN(SUFFIX, TYPE) \
static inline monad_result            \
rlp_decode_var_ ## SUFFIX(const struct rlp_value *value, TYPE *decoded) { \
    return rlp_byte_array_copy(value, decoded, sizeof *decoded); \
}
