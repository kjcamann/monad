#include <monad-c/ethereum/block.h>
#include <monad-c/ethereum/rlp_decode_eth_types.h>
#include <monad-c/rlp/rlp_decode.h>
#include <monad-c/support/result.h>

monad_result mel_decode_block_header(const struct rlp_value *header_sequence,
                                     struct mel_block_header *header) {
    monad_result mr;
    struct rlp_iterator header_iter;
    struct rlp_value header_field;

    mr = rlp_sequence_open_iter(header_sequence, &header_iter);
    if (monad_is_error(mr))
        return mr;

#define BLOCK_TRY_DECODE(DECODE_FN, STORAGE) \
    mr = rlp_sequence_next(&header_iter, &header_field); \
    if (monad_is_error(mr)) \
        return mr;                                      \
    mr = DECODE_FN(&header_field, STORAGE); \
    if (monad_is_error(mr)) \
        return mr;

    BLOCK_TRY_DECODE(rlp_decode_fixed_bytes32, &header->parent_hash)
    BLOCK_TRY_DECODE(rlp_decode_fixed_bytes32, &header->ommers_hash)
    BLOCK_TRY_DECODE(rlp_decode_fixed_address, &header->coinbase)
    BLOCK_TRY_DECODE(rlp_decode_fixed_bytes32, &header->state_root)
    BLOCK_TRY_DECODE(rlp_decode_fixed_bytes32, &header->transactions_root)
    BLOCK_TRY_DECODE(rlp_decode_fixed_bytes32, &header->receipt_root)
    BLOCK_TRY_DECODE(rlp_decode_fixed_bytes256, &header->bloom)
    BLOCK_TRY_DECODE(rlp_decode_uint_into_uint128be, &header->difficulty)
    BLOCK_TRY_DECODE(rlp_decode_uint_into_uint64be, &header->number)
    BLOCK_TRY_DECODE(rlp_decode_uint_into_uint64be, &header->gas_limit)
    BLOCK_TRY_DECODE(rlp_decode_uint_into_uint64be, &header->gas_used)
    BLOCK_TRY_DECODE(rlp_decode_uint_into_uint64be, &header->timestamp)
    BLOCK_TRY_DECODE(rlp_decode_var_bytes32, &header->extra_data)
    BLOCK_TRY_DECODE(rlp_decode_fixed_bytes32, &header->prev_randao)
    BLOCK_TRY_DECODE(rlp_decode_uint_into_uint64be, &header->nonce)

    // Decode EIP-1559 field
    if (!rlp_sequence_has_next(&header_iter))
        return monad_ok(0);
    BLOCK_TRY_DECODE(rlp_decode_fixed_bytes32, &header->base_fee_per_gas)

    // Decode EIP-4895
    if (!rlp_sequence_has_next(&header_iter))
        return monad_ok(0);
    BLOCK_TRY_DECODE(rlp_decode_fixed_bytes32, &header->withdrawals_root);

#undef BLOCK_TRY_DECODE

    if (rlp_sequence_has_next(&header_iter))
        return monad_make_sys_error(3); // XXX: expected end!
    return monad_ok(0);
}