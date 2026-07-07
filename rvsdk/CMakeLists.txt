cmake_minimum_required(VERSION 4.2)

project(mrvsdk VERSION 1.0 LANGUAGES C ASM)

set(CACHE{MRV_LIBC_ABI_VERSION} TYPE INTERNAL VALUE 1)
set(CACHE{MRV_MONAD_CORE_ABI_VERSION} TYPE INTERNAL VALUE 1)
set(CACHE{MRV_STDLIB_ABI_VERSION} TYPE INTERNAL VALUE 1)
set(CACHE{MRV_ERC20_ABI_VERSION} TYPE INTERNAL VALUE 1)

# mrvc_link(<primary-static-library-target> [<output-name>]
#           [SYSTEM] [AUTO_IMPORT]
#           [NAMED_IMPORTS <import>...]
#           [SYMBOL_MAP_SEARCH_DIRS <dir>...]
#           [EXTRA_LIBRARIES] <extra-library-target>...)
function(mrvc_link target)
  cmake_parse_arguments(PARSE_ARGV 1 ARG "SYSTEM;AUTO_IMPORT" ""
      "NAMED_IMPORTS;SYMBOL_MAP_SEARCH_DIRS;EXTRA_LIBRARIES")

  # Optional second positional arg: the output file name.
  set(OUTPUT_NAME "")
  if(ARG_UNPARSED_ARGUMENTS)
    list(GET ARG_UNPARSED_ARGUMENTS 0 OUTPUT_NAME)
  endif()

  # If not passed as an argument, try a custom property on the static lib
  if(NOT OUTPUT_NAME)
    get_target_property(OUTPUT_NAME ${target} MRV_CONTRACT_NAME)
  endif()

  # Fall back to a name derived from the target
  if(NOT OUTPUT_NAME)
      set(OUTPUT_NAME "${target}")
  endif()

  set(OBJECT_FILE ${CMAKE_CURRENT_BINARY_DIR}/${OUTPUT_NAME}.o)
  set(MRVC_FILE ${CMAKE_CURRENT_BINARY_DIR}/${OUTPUT_NAME}.mrvc)

  if(ARG_SYSTEM)
    # This .mrvc is a "system" file, meaning it will be placed in the platform
    # bootstrap code tar file
    set_property(GLOBAL APPEND PROPERTY MRVC_SYSTEM_FILES "${MRVC_FILE}")
  endif()

  set(named_import_args "")
  set(symbol_map_search_dirs "")

  if(ARG_AUTO_IMPORT)
    # AUTO_IMPORT will add NAMED_IMPORTS entries automatically for any
    # target dependency that carries an `MRV_ABI_NAME` property

    get_target_property(_target_deps ${target} LINK_LIBRARIES)

    foreach(_extra_lib IN LISTS ARG_EXTRA_LIBRARIES)
      get_target_property(_extra_deps ${_extra_lib} LINK_LIBRARIES)
      list(APPEND _target_deps ${_extra_deps})
    endforeach()
    list(REMOVE_DUPLICATES _target_deps)

    foreach(_dep IN LISTS _target_deps)
      get_target_property(import ${_dep} MRV_ABI_NAME)
      if(import)
        list(APPEND named_import_args --named-import "${import}")
        get_target_property(import_binary_dir ${_dep} BINARY_DIR)
        list(APPEND symbol_map_search_dirs "${import_binary_dir}")
      endif()
    endforeach()
  endif()

  list(REMOVE_DUPLICATES symbol_map_search_dirs)
  set(symbol_map_args "")
  foreach(_dir IN LISTS symbol_map_search_dirs)
    list(APPEND symbol_map_args -m ${_dir})
  endforeach()

  # Turn the NAMED_IMPORTS list into a list of command line argument string
  # pairs `--named-import ${import}`
  foreach(import IN LISTS ARG_NAMED_IMPORTS)
    list(APPEND named_import_args --named-import "${import}")
  endforeach()

  # Turn the SYMBOL_MAP_SEARCH_DIRS list into a list of command line
  # argument string pairs `-m ${dir}`
  foreach(dir IN LISTS ARG_SYMBOL_MAP_SEARCH_DIRS)
    list(APPEND symbol_map_args -m "${dir}")
  endforeach()

  get_target_property(abi_name ${target} MRV_ABI_NAME)
  if(abi_name)
    set(abi_name_args --abi-name ${abi_name})
  else()
    set(abi_name_args "")
  endif()

  set(_link_targets ${target} ${ARG_EXTRA_LIBRARIES})
  set(link_input_args "")
  foreach(_lt IN LISTS _link_targets)
    list(APPEND link_input_args "$<TARGET_FILE:${_lt}>")
  endforeach()

  add_custom_command(
    OUTPUT ${OBJECT_FILE} ${MRVC_FILE}
    COMMAND ${Python3_EXECUTABLE} ${PROJECT_SOURCE_DIR}/utils/mrvc-link.py
            -o "${OBJECT_FILE}" --bin
            --objcopy "${MRV_OBJCOPY_PROGRAM}"
            ${abi_name_args}
            ${named_import_args}
            ${symbol_map_args}
            ${link_input_args}
    DEPENDS ${target} "${PROJECT_SOURCE_DIR}/utils/mrvc-link.py"
    COMMENT "mrvc-link ${target} -> ${OUTPUT_NAME}.mrvc"
    VERBATIM)

  add_custom_target(${target}_contract ALL DEPENDS ${MRVC_FILE})
endfunction()

if("${CMAKE_C_COMPILER_ARCHITECTURE_ID}" STREQUAL "riscv64")
  set(CACHE{MRV_EVM_PLATFORM} TYPE INTERNAL VALUE "rv64")
  set(CACHE{MRV_LIBRARY_TYPE} TYPE INTERNAL VALUE "STATIC")

  # Disable RISC-V linker relaxation, our dynamic linker does not support it
  add_compile_options(-mno-relax)

  # Linking on rv64 uses a Python wrapper script, and it requires at least
  # Python 3.14 (the first version to ship with a standard module that can
  # perform zstd compression)
  find_package(Python3 3.14 REQUIRED COMPONENTS Interpreter)

  # The linker script needs to call an objcopy which supports RV64 ELF files;
  # platforms like macOS this probably won't be there by default, and will
  # likely come from a user-installed LLVM (ld.lld)
  find_program(MRV_OBJCOPY_PROGRAM objcopy REQUIRED)

  # On our RISC-V platform, we provide the libc implementation, which is mostly
  # system call wrappers to efficient implementations in the VM runtime
  add_library(mrv_libc STATIC
    lib/libc/errno.c
    lib/libc/rv64_ecall.c
    lib/libc/stdio.c
    lib/libc/stdlib.c
    lib/libc/string.c)
  target_compile_features(mrv_libc PUBLIC c_std_23)
  target_compile_options(mrv_libc PUBLIC -Werror)
  target_include_directories(mrv_libc
      PUBLIC ${CMAKE_CURRENT_SOURCE_DIR}/include/libc)
  set_target_properties(mrv_libc PROPERTIES
      MRV_ABI_NAME "libc.${MRV_LIBC_ABI_VERSION}"
      MRV_CONTRACT_NAME "libc")
  mrvc_link(mrv_libc SYSTEM)
else()
  set(CACHE{MRV_EVM_PLATFORM} TYPE INTERNAL VALUE "host")
  set(CACHE{MRV_LIBRARY_TYPE} TYPE INTERNAL VALUE "SHARED")

  if(APPLE)
    add_link_options(-Wl,-undefined,dynamic_lookup)
  endif()

  add_subdirectory(third_party/evmc)
  block(SCOPE_FOR VARIABLES)
    set(ENABLE_UTILS ON)
    add_subdirectory(third_party/libucl)
  endblock()
  add_subdirectory(third_party/yyjson)
endif()

add_library(monad_core_limited ${MRV_LIBRARY_TYPE}
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

target_compile_definitions(monad_core_limited PUBLIC _GNU_SOURCE)
target_compile_features(monad_core_limited PUBLIC c_std_23)
target_include_directories(monad_core_limited PUBLIC ${CMAKE_CURRENT_SOURCE_DIR}/..)

set_target_properties(monad_core_limited PROPERTIES
    MRV_ABI_NAME "monad_core.${MRV_MONAD_CORE_ABI_VERSION}"
    MRV_CONTRACT_NAME "monad_core")

if(MRV_EVM_PLATFORM STREQUAL "rv64")
  # The CMA allocator does not need (and cannot use) atomics on RV64
  target_compile_definitions(monad_core_limited PUBLIC MONAD_CMA_NO_ATOMICS)
  target_link_libraries(monad_core_limited PUBLIC mrv_libc)
  mrvc_link(monad_core_limited SYSTEM AUTO_IMPORT)
else()
  set_target_properties(monad_core_limited PROPERTIES SOVERSION
                        ${MRV_MONAD_CORE_ABI_VERSION})

  # TODO(ken): these should either be supported on RV64 or moved out of the
  # core target
  target_sources(monad_core_limited PRIVATE
    ../category/core/bytes32_map.c
    ../category/core/mem/mem_zone.c)
endif()

add_library(mrv_stdlib ${MRV_LIBRARY_TYPE}
  lib/stdlib/error.c
  lib/stdlib/exit.c
  lib/stdlib/panic.c
  lib/stdlib/rvabi.c)

target_compile_definitions(mrv_stdlib PUBLIC _GNU_SOURCE)
target_compile_features(mrv_stdlib PUBLIC c_std_23)
target_compile_options(mrv_stdlib PUBLIC -Werror)
target_include_directories(mrv_stdlib PUBLIC ${CMAKE_CURRENT_SOURCE_DIR}/include)
target_link_libraries(mrv_stdlib PUBLIC monad_core_limited)

set_target_properties(mrv_stdlib PROPERTIES
    MRV_ABI_NAME "mrv_stdlib.${MRV_STDLIB_ABI_VERSION}"
    MRV_CONTRACT_NAME "mrv_stdlib")

# We'll statically link certain symbols (e.g., the start symbols) into every
# contract
add_library(mrv_stdlib_rt OBJECT lib/stdlib/start.c)
target_link_libraries(mrv_stdlib_rt PUBLIC mrv_stdlib monad_core_limited)

if(MRV_EVM_PLATFORM STREQUAL "host")
  # The SDK standard library is being compiled to run on the host: the evm.h
  # interface is implemented by calling into the "host_exec.h" machinery which
  # is expected to come from whatever simulator program emulates the blockchain
  target_compile_definitions(mrv_stdlib PUBLIC MRV_EVM_HOST_PLATFORM)
  target_sources(mrv_stdlib PRIVATE
    ../category/core/assert.c
    lib/stdlib/host/backtrace.c
    lib/stdlib/host/evm.c)
  target_link_libraries(mrv_stdlib PUBLIC evmc::evmc)
  set_target_properties(mrv_stdlib PROPERTIES SOVERSION ${MRV_STDLIB_ABI_VERSION})
elseif(MRV_EVM_PLATFORM STREQUAL "rv64")
  # The SDK standard library is being compiled to real a RISC-V ELF target:
  # the evm.h interface (and other things in our dependent libraries, like
  # `monad_assertion_failed` from monad_core) are implemented as RISC-V system
  # calls
  target_compile_definitions(mrv_stdlib PUBLIC MRV_EVM_RV64_PLATFORM)
  target_sources(mrv_stdlib PRIVATE
    lib/stdlib/rv64/assert.c
    lib/stdlib/rv64/evm.c
    lib/stdlib/rv64/uint256.c)
  target_link_libraries(mrv_stdlib PUBLIC mrv_libc)
  mrvc_link(mrv_stdlib SYSTEM AUTO_IMPORT)
else()
  message(FATAL_ERROR "Unknown MRV_EVM_PLATFORM value ${MRV_EVM_PLATFORM}")
endif()

add_library(mrv_erc20 ${MRV_LIBRARY_TYPE}
  lib/erc20/call.c
  lib/erc20/native.c
  lib/erc20/native_abi.c)
target_link_libraries(mrv_erc20 PUBLIC mrv_stdlib monad_core_limited)

set_target_properties(mrv_erc20 PROPERTIES
    MRV_ABI_NAME "mrv_erc20.${MRV_ERC20_ABI_VERSION}"
    MRV_CONTRACT_NAME "mrv_erc20")

if(MRV_EVM_PLATFORM STREQUAL "rv64")
  target_link_libraries(mrv_erc20 PUBLIC mrv_libc)
  mrvc_link(mrv_erc20 SYSTEM AUTO_IMPORT)
else()
  set_target_properties(mrv_erc20 PROPERTIES SOVERSION ${MRV_ERC20_ABI_VERSION})
endif()

if(MRV_EVM_PLATFORM STREQUAL "rv64")
  set(MRVC_BOOTSTRAP_ARCHIVE ${CMAKE_CURRENT_BINARY_DIR}/sdk-bootstrap.${CMAKE_PROJECT_VERSION_MAJOR}.tar)
  get_property(_mrvc_tar_inputs GLOBAL PROPERTY MRVC_SYSTEM_FILES)
  add_custom_command(
    OUTPUT ${MRVC_BOOTSTRAP_ARCHIVE}
    COMMAND ${CMAKE_COMMAND} -E tar cf
            ${MRVC_BOOTSTRAP_ARCHIVE}
            ${_mrvc_tar_inputs}
    DEPENDS ${_mrvc_tar_inputs}
    WORKING_DIRECTORY ${CMAKE_CURRENT_BINARY_DIR}
    COMMENT "Bundling system .mrvc libraries into ${MRVC_BOOTSTRAP_ARCHIVE}"
    VERBATIM)

  add_custom_target(mrvc_bootstrap ALL DEPENDS ${MRVC_BOOTSTRAP_ARCHIVE})
endif()

# mrv_link_contract(<target> LIB_DEPENDS <lib>...)
function(mrv_link_contract target)
  cmake_parse_arguments(PARSE_ARGV 1 ARG "" "" "LIB_DEPENDS")

  if(ARG_UNPARSED_ARGUMENTS)
    message(FATAL_ERROR "mrv_link_contract: unexpected arguments: ${ARG_UNPARSED_ARGUMENTS}")
  endif()

  # All contracts link the platform standard library, which has
  # monad_core_limited as a dependency
  list(APPEND ARG_LIB_DEPENDS mrv_stdlib monad_core_limited)

  if(MRV_EVM_PLATFORM STREQUAL "rv64")
    # RV64 explicitly needs its own libc as a dependency
    list(APPEND ARG_LIB_DEPENDS mrv_libc)
  endif()

  foreach(lib IN LISTS ARG_LIB_DEPENDS)
    if(NOT TARGET ${lib})
      message(FATAL_ERROR "${mrv_link_contract}: LIB_DEPENDS entry `${lib}` is not a known target")
    endif()
    target_link_libraries(${target} PRIVATE ${lib})
  endforeach()

  # All contracts link in the standard library start symbols; we didn't
  # add this to the ARG_LIB_DEPENDS list because it doesn't import anything
  # (the symbols are copied over, not referenced)
  target_link_libraries(${target} PRIVATE mrv_stdlib_rt)

  if(MRV_EVM_PLATFORM STREQUAL "host")
    # On the host platform, contracts are dynamic shared object files
    if(APPLE)
      # Same as the below, but macOS uses the old UNIX "linker names" concept
      # so the symbols need a `_` prefix
      target_link_options(${target} PRIVATE -Wl,-u,_mrv_start -Wl,-u,_mrv_init)
    else()
      # Ensure `mrv_start` and `mrv_init` will be pulled in from the object
      # library mrv_stdlib_rt
      target_link_options(${target} PRIVATE -Wl,-u,mrv_start -Wl,-u,mrv_init)
    endif()

  elseif(MRV_EVM_PLATFORM STREQUAL "rv64")
    # On RV64, contracts are the result of running the `mrvc-link.py` link step
    mrvc_link(${target} AUTO_IMPORT)
  else()
    message(FATAL_ERROR "Unknown MRV_EVM_PLATFORM value ${MRV_EVM_PLATFORM}")
  endif()

  set_target_properties(${name} PROPERTIES C_VISIBILITY_PRESET hidden)
endfunction()

add_subdirectory(examples)

if(MRV_EVM_PLATFORM STREQUAL "host")
  add_library(monad_rv STATIC
    ../category/rv/rv_code.c
    ../category/rv/rv_code_cache.c
    ../category/rv/rv_log_observer.c
    ../category/rv/rv_vm.c
    ../category/rv/rvi_dynlink.c
    ../category/rv/rvi_log_writer.c)
  target_include_directories(monad_rv PRIVATE third_party/musl)

  find_library(libzstd_file zstd REQUIRED)
  target_link_libraries(monad_rv PUBLIC monad_core_limited)
  target_link_libraries(monad_rv PRIVATE ${libzstd_file})

  add_subdirectory(tools)
endif()
