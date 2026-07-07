#pragma once

#include <stddef.h>

#include <category/core/address.h>
#include <category/core/bytes32.h>
#include <category/core/byteview.h>
#include <category/execution/ethereum/core/eth_ctypes.h>

// clang-format off

struct txn_access_list
{
  struct monad_address address;     ///< E_a: addr of account whose storage to warm
  struct monad_bytes32 const *keys; ///< E_s: key array
  size_t key_count;                 ///< Size of key array
};

struct txn_input
{
  struct monad_eth_txn_header header;    ///< Fixed-size fields of transaction
  monad_address sender;                  ///< Optional recovered sender address
  struct monad_bv data;                  ///< Transaction input
  struct monad_bv blob_versioned_hashes; ///< Array of EIP-4844 hashes
  struct txn_access_list const *
      access_lists;                      ///< Array of EIP-2930 access entries
  size_t access_list_count;              ///< Size of access_lists
  struct monad_auth_list_entry const *   ///< Array of EIP-7702 authorizations
      auth_entries;
  size_t auth_entry_count;               ///< Size of auth_entries
};

struct block_input
{
  monad_uint256_be chain_id;        ///< Blockchain we're associated with
  struct monad_eth_block_input
      eth_block_input;              ///< Header fields known at start
  struct monad_bytes32 parent_hash; ///< Hash of parent, if known
  struct txn_input const *txns;     ///< Array of transactions
  size_t txn_count;                 ///< Size of transaction array
};

// clang-format on

void txn_input_free(struct txn_input *);

void block_input_free(struct block_input *);
