#include <string.h>

#include <monad-c/ethereum/rlp_decode_eth_types.h>
#include <monad-c/ethereum/transaction.h>
#include <monad-c/rlp/rlp_decode.h>
#include <monad-c/support/result.h>

static monad_result decode_legacy_txn(const struct rlp_value *txn_sequence,
                                      struct mel_transaction *txn) {
    monad_result mr;
    struct rlp_iterator txn_iter;
    struct rlp_value txn_field;

    txn->type = MEL_TXN_TYPE_LEGACY;
    mr = rlp_sequence_open_iter(txn_sequence, &txn_iter);
    if (monad_is_error(mr))
        return mr;

#define TXN_TRY_DECODE(DECODE_FN, STORAGE) \
    mr = rlp_sequence_next(&txn_iter, &txn_field); \
    if (monad_is_error(mr)) \
        return mr;                                      \
    mr = DECODE_FN(&txn_field, STORAGE); \
    if (monad_is_error(mr)) \
        return mr;

    // Clear fields not used in legacy transactions
    memset(&txn->max_priority_fee_per_gas, 0, sizeof txn->max_priority_fee_per_gas);
    txn->access_list_iter = rlp_sequence_make_null_iterator();

    TXN_TRY_DECODE(rlp_decode_uint_into_uint256be, &txn->nonce)
    TXN_TRY_DECODE(rlp_decode_uint_into_uint64be, &txn->max_fee_per_gas)
    TXN_TRY_DECODE(rlp_decode_uint_into_uint64be, &txn->gas)

    // The address is encoded as 20 bytes, unless it is the empty contract
    // address, in which case it is empty.
    mr = rlp_sequence_next(&txn_iter, &txn_field);
    if (monad_is_error(mr))
        return mr;
    if (rlp_value_is_empty_byte_array(&txn_field))
        memset(&txn->to, 0, sizeof txn->to);
    else {
        mr = rlp_decode_fixed_address(&txn_field, &txn->to);
        if (monad_is_error(mr))
            return mr;
    }

    TXN_TRY_DECODE(rlp_decode_uint_into_uint256be, &txn->value)

    mr = rlp_sequence_next(&txn_iter, &txn_field);
    if (monad_is_error(mr))
        return mr;
    mr = rlp_byte_array_get_range(&txn_field, &txn->data);
    if (monad_is_error(mr))
        return mr;

    TXN_TRY_DECODE(rlp_decode_uint_into_uint256be, &txn->v);
    TXN_TRY_DECODE(rlp_decode_uint_into_uint256be, &txn->r);
    TXN_TRY_DECODE(rlp_decode_uint_into_uint256be, &txn->s);

#undef TXN_TRY_DECODE

    if (rlp_sequence_has_next(&txn_iter))
        return monad_make_sys_error(3); // XXX: expected end!
    return monad_ok(0);
}

monad_result mel_decode_transaction(const struct rlp_value *txn_value,
                                    struct mel_transaction *txn) {
    if (txn_value->type == RLP_TYPE_SEQUENCE)
        return decode_legacy_txn(txn_value, txn);
    return monad_make_sys_error(7); // XXX: ENOSYS
}