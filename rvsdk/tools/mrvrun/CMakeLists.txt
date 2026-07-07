add_executable(mrvrun
  block_input.c
  exec.c
  exec_block.c
  exec_msg.c
  exec_txn.c
  hexdump.c # move this somewhere else?
  input.c
  input_eth_test.c
  main.c
  mem_state_db.c
  state_db.c
  state_tracker.c)

# stubs for now
target_sources(mrvrun PUBLIC
  ../../../category/core/assert.c
  ../../lib/stdlib/host/backtrace.c)

if(APPLE)
  find_package(OpenSSL REQUIRED)
  target_sources(mrvrun PUBLIC compat/macos/keccak.c)
  target_link_libraries(mrvrun PRIVATE OpenSSL::Crypto)
else()
  target_sources(mrvrun PUBLIC
    ../../../category/core/keccak.c
    ../../../third_party/openssl/crypto/sha/asm/keccak1600-avx2.S)
endif()

# FIXME: this should come from INTERFACE linking mrv_stdlib, but it
# doesn't work?
target_include_directories(mrvrun PRIVATE ${CMAKE_CURRENT_SOURCE_DIR}/../../include)

target_compile_definitions(mrvrun PUBLIC _GNU_SOURCE)
target_compile_features(mrvrun PUBLIC c_std_23)
target_link_libraries(mrvrun PRIVATE monad_core_limited_static
  evmc::evmc evmc::loader rvc_loader yyjson)
