cmake_minimum_required(VERSION 3.30)

project(mrvsdk LANGUAGES C ASM)

if("${CMAKE_C_COMPILER_ARCHITECTURE_ID}" STREQUAL "riscv64")
  set(CACHE{MRV_EVM_PLATFORM} TYPE INTERNAL VALUE "rv64")
  add_library(mrv_libc
    lib/libc/errno.c
    lib/libc/stdio.c
    lib/libc/stdlib.c
    lib/libc/string.c)
  target_compile_features(mrv_libc PUBLIC c_std_23)
  target_include_directories(mrv_libc
      PUBLIC ${CMAKE_CURRENT_SOURCE_DIR}/include/libc)
else()
  set(CACHE{MRV_EVM_PLATFORM} TYPE INTERNAL VALUE "host")
  add_subdirectory(third_party/evmc)
  add_subdirectory(third_party/yyjson)
endif()

add_library(monad_core_limited STATIC
  ../category/core/address.c
  ../category/core/format_err.c
  ../category/core/strview.c
  ../category/core/abi/error.c
  ../category/core/abi/rvabi_decode.c
  ../category/core/abi/solabi_decode.c
  ../category/core/abi/solabi_encode.c
  ../category/core/mem/cma/cma_alloc.c
  ../category/core/mem/cma/cma_bump.c
  ../category/core/mem/cma/cma_fallback.c)

set_target_properties(monad_core_limited PROPERTIES
  POSITION_INDEPENDENT_CODE ON
  C_VISIBILITY_PRESET hidden)

target_compile_definitions(monad_core_limited PUBLIC _GNU_SOURCE)
target_compile_features(monad_core_limited PUBLIC c_std_23)
target_include_directories(monad_core_limited PUBLIC ${CMAKE_CURRENT_SOURCE_DIR}/..)

if(MRV_EVM_PLATFORM STREQUAL "rv64")
  # The CMA allocator does not need (and cannot use) atomics on RV64
  target_compile_definitions(monad_core_limited PUBLIC MONAD_CMA_NO_ATOMICS)
  target_link_libraries(monad_core_limited PUBLIC mrv_libc)
else()
  # XXX: these should either be supported or move out of this target
  target_sources(monad_core_limited PUBLIC
    ../category/core/bytes32_map.c
    ../category/core/mem/mem_zone.c)
endif()

add_library(mrv_stdlib
  lib/stdlib/error.c
  lib/stdlib/exit.c
  lib/stdlib/panic.c
  lib/stdlib/rvabi.c
  lib/stdlib/start.c)

target_compile_definitions(mrv_stdlib PUBLIC _GNU_SOURCE)
target_compile_features(mrv_stdlib PUBLIC c_std_23)
target_compile_options(mrv_stdlib PUBLIC -Werror)
target_include_directories(mrv_stdlib PUBLIC ${CMAKE_CURRENT_SOURCE_DIR}/include)
target_link_libraries(mrv_stdlib PUBLIC monad_core_limited)

set_target_properties(mrv_stdlib PROPERTIES
  POSITION_INDEPENDENT_CODE ON
  INTERFACE_POSITION_INDEPENDENT_CODE ON
  C_VISIBILITY_PRESET hidden)

if(MRV_EVM_PLATFORM STREQUAL "host")
  target_compile_definitions(mrv_stdlib PUBLIC MRV_EVM_HOST_PLATFORM)
  target_sources(mrv_stdlib PUBLIC
    ../category/core/assert.c
    lib/stdlib/host/backtrace.c
    lib/stdlib/host/evm.c)
  target_link_libraries(mrv_stdlib PUBLIC evmc::evmc)
elseif(MRV_EVM_PLATFORM STREQUAL "rv64")
  target_compile_definitions(mrv_stdlib PUBLIC MRV_EVM_RV64_PLATFORM)
  target_sources(mrv_stdlib PUBLIC
    lib/stdlib/rv64/assert.c
    lib/stdlib/rv64/evm.c
    lib/stdlib/rv64/uint256.c)
else()
  message(FATAL_ERROR "Unknown MRV_EVM_PLATFORM value ${MRV_EVM_PLATFORM}")
endif()

add_library(mrv_erc20
  lib/erc20/call.c
  lib/erc20/native.c
  lib/erc20/native_abi.c)
target_link_libraries(mrv_erc20 PUBLIC mrv_stdlib)
set_target_properties(mrv_erc20 PROPERTIES C_VISIBILITY_PRESET hidden)

add_subdirectory(examples)

if(MRV_EVM_PLATFORM STREQUAL "host")
  add_library(monad_rv_limited STATIC
    ../category/rv/rv_code.c
    ../category/rv/rv_code_cache.c)
  set_target_properties(monad_rv_limited PROPERTIES
    POSITION_INDEPENDENT_CODE ON
    C_VISIBILITY_PRESET hidden)

  find_library(libzstd_file zstd REQUIRED)

  target_link_libraries(monad_rv_limited PUBLIC monad_core_limited)
  target_link_libraries(monad_rv_limited PRIVATE ${libzstd_file})

  find_package(PkgConfig REQUIRED)
  pkg_check_modules(LIBELF IMPORTED_TARGET libelf)

  if(LIBELF_FOUND)
    target_link_libraries(monad_rv_limited PUBLIC PkgConfig::LIBELF)
  else()
    target_link_libraries(monad_rv_limited PUBLIC -lelf)
  endif()

  add_subdirectory(tools)
endif()
