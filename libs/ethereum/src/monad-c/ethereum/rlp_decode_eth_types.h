#pragma

#include <string.h>
#include <monad-c/ethereum/types.h>
#include <monad-c/rlp/rlp_decode.h>
#include <monad-c/support/result.h>

#define RLP_DEFINE_DECODE_FIXED_BYTE_ARRAY_FN(SUFFIX, TYPE) \
static inline monad_result            \
rlp_decode_fixed_ ## SUFFIX(const struct rlp_value *value, TYPE *decoded) { \
    size_t byte_array_size; \
    if (value == nullptr || decoded == nullptr) \
        return monad_make_sys_error(1); \
    if (value->type != RLP_TYPE_BYTE_ARRAY) \
        return monad_make_sys_error(2); \
    byte_array_size = rlp_value_length(value); \
    if (byte_array_size != sizeof *decoded) \
        return monad_make_sys_error(3); \
    (void)memcpy(decoded, rlp_value_data_begin(value), sizeof *decoded); \
    return monad_ok(0); \
}


RLP_DEFINE_DECODE_FIXED_BYTE_ARRAY_FN(bytes32, struct mel_bytes32)
RLP_DEFINE_DECODE_FIXED_BYTE_ARRAY_FN(address, struct mel_address)
RLP_DEFINE_DECODE_FIXED_BYTE_ARRAY_FN(bytes256, struct mel_bytes256)
RLP_DEFINE_DECODE_FIXED_BYTE_ARRAY_FN(uint64be, union mel_uint64be)
RLP_DEFINE_DECODE_FIXED_BYTE_ARRAY_FN(uint128be, union mel_uint128be)

RLP_DEFINE_DECODE_VAR_BYTE_ARRAY_FN(bytes32, struct mel_bytes32)

RLP_DEFINE_DECODE_UINT_INTO_FN(uint64be, union mel_uint64be)
RLP_DEFINE_DECODE_UINT_INTO_FN(uint128be, union mel_uint128be)
RLP_DEFINE_DECODE_UINT_INTO_FN(uint256be, struct mel_bytes32)