project(monad_ethereum LANGUAGES C)

add_library(monad_ethereum_c STATIC
  # ethereum - basic types
  "src/monad-c/ethereum/block.h"
  "src/monad-c/ethereum/block.c"
  "src/monad-c/ethereum/rlp_decode_eth_types.h"
  "src/monad-c/ethereum/transaction.h"
  "src/monad-c/ethereum/transaction.c"
  "src/monad-c/ethereum/types.h"

  # db - block_db support
  "src/monad-c/db/block_db.h"
  "src/monad-c/db/block_db.c")

target_compile_features(monad_ethereum_c PUBLIC c_std_23)

target_include_directories(monad_ethereum_c
  PUBLIC ${PROJECT_SOURCE_DIR}/src)

target_link_libraries(monad_ethereum_c PUBLIC monad_core_c)
target_link_libraries(monad_ethereum_c PRIVATE PkgConfig::brotli) # for block_db