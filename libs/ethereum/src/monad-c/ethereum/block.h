#pragma once

#include <stdint.h>
#include <monad-c/ethereum/types.h>
#include <monad-c/rlp/rlp_decode.h>
#include <monad-c/support/range.h>
#include <monad-c/support/result.h>

typedef uint64_t mel_block_num;
typedef struct mcl_range_u64 mel_block_range;

/**
 * Data in an Ethereum block header
 *
 * The core fields are described in [YP 4.3: The Block]. The current
 * specification is taken from the Ethereum Execution Layer Specification,
 * Shanghai Fork [EELS: src/ethereum/shanghai/blocks.py]. For some fields the
 * EELS uses different names than the historical ones, e.g., `coinbase` was
 * originally called `beneficiary`. We use the EELS names.
 *
 * The block header is not a fixed size structure: some of the fields are
 * specified as arbitrary-sized unsigned integers. For any particular value,
 * these fields will have fixed representations once their value is RLP
 * encoded. In this structure, we use a reasonable fixed size following the
 * most popular Ethereum implementation, see `go-ethereum/core/types/block.go`
 */
struct mel_block_header {
    mel_keccak256_t parent_hash;
    mel_keccak256_t ommers_hash;
    mel_address_t coinbase;
    mel_keccak256_t state_root;
    mel_keccak256_t transactions_root;
    mel_keccak256_t receipt_root;
    mel_bytes256_t bloom;
    mel_uint128be_t difficulty; ///< 128b for historical value; zero since Paris
    mel_uint64be_t number;
    mel_uint64be_t gas_limit;
    mel_uint64be_t gas_used;
    mel_uint64be_t timestamp;
    mel_bytes32_t extra_data;
    mel_bytes32_t prev_randao;
    mel_uint64be_t nonce;
    mel_amount_t base_fee_per_gas;  ///< EIP-1559
    mel_keccak256_t withdrawals_root; ///< EIP-4895
};

monad_result mel_decode_block_header(const struct rlp_value *header_sequence,
                                     struct mel_block_header *header);
