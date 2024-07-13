#pragma once

#include <stdint.h>
#include <monad-c/ethereum/types.h>
#include <monad-c/rlp/rlp_decode.h>
#include <monad-c/support/result.h>

/// Type of the transaction; different transaction formats were introduced by
/// EIP-2718.
enum mel_transaction_type : uint8_t {
    MEL_TXN_TYPE_INVALID,
    MEL_TXN_TYPE_LEGACY,      ///< Original Ethereum txn type
    MEL_TXN_TYPE_ACCESS_LIST, ///< EIP-2930
    MEL_TXN_TYPE_FEE_MARKET   ///< EIP-1559 and called "Dynamic Fee" in geth
};

/**
 * Data in an Ethereum transaction
 *
 * The core fields are described in [YP 4.2: The Transaction]. The current
 * specification is taken from the Ethereum Execution Layer Specification,
 * Shanghai Fork [EELS: src/ethereum/shanghai/transactions.py].
 */
struct mel_transaction {
    enum mel_transaction_type type;
    mel_uint64be_t chain_id;
    mel_uint256be_t nonce;
    mel_uint64be_t max_priority_fee_per_gas; ///< Stores zero in old txn types
    mel_uint64be_t max_fee_per_gas; ///< Stores `gas_price` in old txn types
    mel_uint64be_t gas;
    mel_address_t to;
    mel_amount_t value;
    rlp_buf_t data;
    struct rlp_iterator access_list_iter; ///< Iterates over access list seq.
    mel_uint256be_t v;
    mel_uint256be_t r;
    mel_uint256be_t s;
};

monad_result mel_decode_transaction(const struct rlp_value *txn_value,
                                    struct mel_transaction *txn);