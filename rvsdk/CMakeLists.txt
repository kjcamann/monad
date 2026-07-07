cmake_minimum_required(VERSION 4.2)

project(mrvsdk VERSION 1.0 LANGUAGES C)

set(CACHE{MRV_LIBC_ABI_VERSION} TYPE INTERNAL VALUE 1)
set(CACHE{MRV_MONAD_CORE_ABI_VERSION} TYPE INTERNAL VALUE 1)
set(CACHE{MRV_STDLIB_ABI_VERSION} TYPE INTERNAL VALUE 1)
set(CACHE{MRV_ERC20_ABI_VERSION} TYPE INTERNAL VALUE 1)

option(MRV_BUILD_EXAMPLES "Build the example contracts" ON)

# Step 1: platform detection decides "mrv" or "host"
#
# The first thing we do is check if we're crossing-compiling to the Monad
# RISC-V target, or if we're compiling for the host platform and emulating
# the RISC-V SDK programming environment on the host.
#
# This will set the internal cache variable `MRV_PLATFORM` to either "mrv"
# or "host". If we're targetting the "mrv" platform, we will also build the
# platform's libc.
#
# If we're compiling for the host's native architecture, we also build the
# Monad RISC-V virtual machine and the extra SDK utilities (e.g., the
# simulation libraries).
#
# The platform detection will also set the cache variable `MRV_CONTRACT_PIC`
# to ON or OFF, depending on whether the target requires code linked into
# contracts to be position independent or not. You don't need to worry about
# this if you create a contract with a call to `mrv_add_contract`, but if your
# project is made up of multiple object or static libraries, they'll need to
# be compiled with the right code model for the final binary. Native mrv
# executables do _not_ require PIC, but host emulation mode does.
#
# A final note: the prefixes `MRV_` and `mrv_` are used as a disambiguation /
# namespace mechanism in CMake variable and function names. The function
# `mrv_add_contract`, for example, can be used to create a contract even if
# we're compiling for the host architecture without a RISC-V toolchain. In
# that case, it creates the contract in native code which the simulator can
# run. Thus, the abbreviation "mrv" usually refers to all aspects of the SDK.
# In the context of MRV_PLATFORM, however, "mrv" means the compiler produces
# bare metal ELF binaries containing RISC-V machine code.

if("${CMAKE_C_COMPILER_ARCHITECTURE_ID}" STREQUAL "riscv64")
  # TODO(ken): ^ if the host platform is also RISC-V (e.g., a lightweight
  #   RISC-V development machine), we might do the wrong thing here. We should
  #   do something smarter here. "mrv" is a more specific thing than "the CPU
  #   is riscv64". It specifically means bare metal RV64IM, plus the required
  #   runtime support in our VM (the ECALL set expected to be there, and our
  #   VM's dynamic runtime linking model)

  set(CACHE{MRV_PLATFORM} TYPE INTERNAL VALUE "mrv")
  set(CACHE{MRV_CONTRACT_PIC} TYPE INTERNAL VALUE OFF)
  set(CACHE{MRV_LINKER_PREFIX} TYPE INTERNAL VALUE "")

  # We're cross-compiling to bare metal, so both CMake and clang's linker
  # driver logic believe that shared libraries are not supported. We manually
  # configured the toolchain to teach CMake how to build them, so let it know
  # that add_library(SHARED) is OK.
  set_property(GLOBAL PROPERTY TARGET_SUPPORTS_SHARED_LIBS TRUE)

  set(mrv_libc_sources
    lib/libc/errno.c
    lib/libc/rv64_ecall.c
    lib/libc/stdio.c
    lib/libc/stdlib.c
    lib/libc/string.c)

  add_library(mrv_libc_interface INTERFACE)
  add_library(mrv_libc_shared SHARED ${mrv_libc_sources})
  add_library(mrv_libc_static STATIC ${mrv_libc_sources})

  target_compile_features(mrv_libc_interface INTERFACE c_std_23)
  target_include_directories(mrv_libc_interface INTERFACE
      ${mrvsdk_SOURCE_DIR}/include/libc)

  foreach(_lib_type SHARED STATIC)
    string(TOLOWER "mrv_libc_${_lib_type}" _mrv_libc)
    target_compile_options(${_mrv_libc} PRIVATE -Werror)
    target_link_libraries(${_mrv_libc} PUBLIC mrv_libc_interface)
    set_target_properties(${_mrv_libc} PROPERTIES OUTPUT_NAME "mrv_libc")
  endforeach()

  set(_linker_script ${mrvsdk_SOURCE_DIR}/toolchain/syslib.ld)
  set_target_properties(mrv_libc_shared PROPERTIES
    SOVERSION ${MRV_LIBC_ABI_VERSION}
    LINK_DEPENDS ${_linker_script}
    INTERFACE_LINK_DEPENDS ${_linker_script})

  target_compile_options(mrv_libc_static
      PRIVATE -ffunction-sections -fdata-sections)
else()
  set(CACHE{MRV_PLATFORM} TYPE INTERNAL VALUE "host")
  set(CACHE{MRV_CONTRACT_PIC} TYPE INTERNAL VALUE ON)
  set(CACHE{MRV_LINKER_PREFIX} TYPE INTERNAL VALUE "LINKER:")

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

set(MRV_SYSTEM_LIBRARIES "")

# Step 2: build the MRV contract SDK libraries
#
# These are built in both SHARED and STATIC flavors. The only library every
# contract needs is the MRV standard library, mrv_stdlib, which contains the
# basic platform support and essential primitive vocabulary types like
# `monad_address`. An implementation detail is that parts of the standard
# library are in a separate physical library, called `monad_core_limited`.
# This target contains common C library code shared with the execution client
# and the execution events SDK.

# Contracts that use static libraries (i.e., that want to statically link
# parts of the SDK runtime) will probably want to ensure the linker garbage
# collects unused symbols; they can use the below variables in their
# target-level compile and link options
if(APPLE)
  set(CACHE{MRV_DEAD_STRIP_COMPILE_OPTIONS} TYPE INTERNAL VALUE "")
  set(CACHE{MRV_DEAD_STRIP_LINK_OPTIONS} TYPE INTERNAL VALUE
      ${MRV_LINKER_PREFIX}-dead_strip)
else()
  set(CACHE{MRV_DEAD_STRIP_COMPILE_OPTIONS} TYPE INTERNAL VALUE
      -ffunction-sections -fdata-sections)
  set(CACHE{MRV_DEAD_STRIP_LINK_OPTIONS} TYPE INTERNAL VALUE
      ${MRV_LINKER_PREFIX}--gc-sections)
endif()

#
# monad_core_limited
#

set(monad_core_limited_sources
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

add_library(monad_core_limited_interface INTERFACE)
add_library(monad_core_limited_shared SHARED ${monad_core_limited_sources})
add_library(monad_core_limited_static STATIC ${monad_core_limited_sources})

target_compile_definitions(monad_core_limited_interface INTERFACE _GNU_SOURCE)
target_compile_features(monad_core_limited_interface INTERFACE c_std_23)
target_include_directories(monad_core_limited_interface
  INTERFACE ${mrvsdk_SOURCE_DIR}/..)

if(MRV_PLATFORM STREQUAL "mrv")
  # The CMA allocator does not need (and cannot use) atomics on RV64
  target_compile_definitions(monad_core_limited_interface
      INTERFACE MONAD_CMA_NO_ATOMICS)

  # Link to our libc as a dependency; this is how it ends up getting linked
  # into everything else
  target_link_libraries(monad_core_limited_interface INTERFACE mrv_libc_interface)
endif()

foreach(_lib_type SHARED STATIC)
  string(TOLOWER "monad_core_limited_${_lib_type}" _monad_core_limited)
  target_compile_options(${_monad_core_limited} PRIVATE -Werror)
  target_link_libraries(${_monad_core_limited} PUBLIC monad_core_limited_interface)
  set_target_properties(${_monad_core_limited} PROPERTIES
      OUTPUT_NAME "monad_core_limited")

  if(MRV_PLATFORM STREQUAL "mrv")
    string(TOLOWER "mrv_libc_${_lib_type}" _mrv_libc)
    target_link_libraries(${_monad_core_limited} PUBLIC ${_mrv_libc})
  elseif(MRV_PLATFORM STREQUAL "host")
    # TODO(ken): these should either be supported on RV64 or moved out of the
    # core target and into `tools`
    target_sources(${_monad_core_limited} PRIVATE
      ../category/core/bytes32_map.c
      ../category/core/mem/mem_zone.c)
  endif()
endforeach()

set_target_properties(monad_core_limited_shared PROPERTIES
    SOVERSION ${MRV_MONAD_CORE_ABI_VERSION})

target_compile_options(monad_core_limited_static
    PRIVATE ${MRV_DEAD_STRIP_COMPILE_OPTIONS})

list(APPEND MRV_SYSTEM_LIBRARIES monad_core_limited)

#
# mrv_stdlib
#

set(mrv_stdlib_sources
  lib/stdlib/error.c
  lib/stdlib/exit.c
  lib/stdlib/panic.c
  lib/stdlib/rvabi.c)

add_library(mrv_stdlib_interface INTERFACE)
add_library(mrv_stdlib_shared SHARED ${mrv_stdlib_sources})
add_library(mrv_stdlib_static STATIC ${mrv_stdlib_sources})

target_compile_definitions(mrv_stdlib_interface INTERFACE _GNU_SOURCE)
target_compile_features(mrv_stdlib_interface INTERFACE c_std_23)
target_include_directories(mrv_stdlib_interface INTERFACE ${mrvsdk_SOURCE_DIR}/include)
target_link_libraries(mrv_stdlib_interface INTERFACE monad_core_limited_interface)

if(MRV_PLATFORM STREQUAL "mrv")
  target_compile_definitions(mrv_stdlib_interface INTERFACE MRV_EVM_RV64_PLATFORM)
elseif(MRV_PLATFORM STREQUAL "host")
  target_compile_definitions(mrv_stdlib_interface INTERFACE MRV_EVM_HOST_PLATFORM)
else()
  message(FATAL_ERROR "Unknown MRV_PLATFORM value ${MRV_PLATFORM}")
endif()

foreach(_lib_type SHARED STATIC)
  string(TOLOWER "mrv_stdlib_${_lib_type}" _mrv_stdlib)
  string(TOLOWER "monad_core_limited_${_lib_type}" _monad_core_limited)

  target_compile_options(${_mrv_stdlib} PRIVATE -Werror)
  target_link_libraries(${_mrv_stdlib} PUBLIC mrv_stdlib_interface ${_monad_core_limited})
  set_target_properties(${_mrv_stdlib} PROPERTIES OUTPUT_NAME "mrv_stdlib")

  if(MRV_PLATFORM STREQUAL "mrv")
    # The SDK standard library is being compiled to a real MRV target: the evm.h
    # interface (and other things in its dependent libraries, like
    # `monad_assertion_failed` from monad_core_limited) are implemented as
    # RISC-V system calls
    target_sources(${_mrv_stdlib} PRIVATE
      lib/stdlib/rv64/assert.c
      lib/stdlib/rv64/evm.c
      lib/stdlib/rv64/uint256.c)
  elseif(MRV_PLATFORM STREQUAL "host")
    # The SDK standard library is being compiled to run on the host: the evm.h
    # services are implemented by calling into the "host_exec.h" interface. The
    # implementation of "host_exec.h" is expected to come from the simulator
    # program that emulates the blockchain (the simulator will export the
    # dynamic symbols `mrv_get_host_exec_context` for us to find)
    target_sources(${_mrv_stdlib} PRIVATE
      ../category/core/assert.c
      lib/stdlib/host/backtrace.c
      lib/stdlib/host/evm.c)
    target_link_libraries(${_mrv_stdlib} PUBLIC evmc::evmc)
  else()
    message(FATAL_ERROR "Unknown MRV_PLATFORM value ${MRV_PLATFORM}")
  endif()
endforeach()

set_target_properties(mrv_stdlib_shared PROPERTIES SOVERSION ${MRV_STDLIB_ABI_VERSION})

target_compile_options(mrv_stdlib_static
    PRIVATE ${MRV_DEAD_STRIP_COMPILE_OPTIONS})

list(APPEND MRV_SYSTEM_LIBRARIES mrv_stdlib)

# `mrv_add_contract` will statically link certain runtime support symbols (e.g.,
# the start and init symbols) into every contract
add_library(mrv_stdlib_rt OBJECT lib/stdlib/start.c)
target_link_libraries(mrv_stdlib_rt PRIVATE mrv_stdlib_static monad_core_limited_static)

#
# mrv_erc20
#

set(mrv_erc20_sources
  lib/erc20/call.c
  lib/erc20/native.c
  lib/erc20/native_abi.c)

add_library(mrv_erc20_interface INTERFACE)
add_library(mrv_erc20_shared SHARED ${mrv_erc20_sources})
add_library(mrv_erc20_static STATIC ${mrv_erc20_sources})

target_link_libraries(mrv_erc20_interface INTERFACE mrv_stdlib_interface)

target_compile_options(mrv_erc20_static
    PRIVATE ${MRV_DEAD_STRIP_COMPILE_OPTIONS})

foreach(_lib_type SHARED STATIC)
  string(TOLOWER "mrv_erc20_${_lib_type}" _mrv_erc20)
  string(TOLOWER "mrv_stdlib_${_lib_type}" _mrv_stdlib)

  target_compile_options(${_mrv_erc20} PRIVATE -Werror)
  set_target_properties(${_mrv_erc20} PROPERTIES OUTPUT_NAME "mrv_erc20")
  target_link_libraries(${_mrv_erc20} PUBLIC mrv_erc20_interface ${_mrv_stdlib})
endforeach()

set_target_properties(mrv_erc20_shared PROPERTIES SOVERSION ${MRV_ERC20_ABI_VERSION})

list(APPEND MRV_SYSTEM_LIBRARIES mrv_erc20)

# Last step: make sure all STATIC platform libraries have PIC enabled on the
# host platform
if(MRV_PLATFORM STREQUAL "host")
  foreach(_target ${MRV_SYSTEM_LIBRARIES})
    set_target_properties(${_target}_static PROPERTIES POSITION_INDEPENDENT_CODE ON)
  endforeach()
  set_target_properties(mrv_stdlib_rt PROPERTIES POSITION_INDEPENDENT_CODE ON)
endif()

if(MRV_PLATFORM STREQUAL "mrv")
  set(_system_archive ${CMAKE_CURRENT_BINARY_DIR}/sdk.sysar.${CMAKE_PROJECT_VERSION_MAJOR})
  set(_sysar_inputs $<TARGET_FILE:mrv_libc_shared>)
  foreach(_syslib IN LISTS MRV_SYSTEM_LIBRARIES)
      list(APPEND _sysar_inputs "$<TARGET_FILE:${_syslib}_shared>")
  endforeach()
  add_custom_command(
    OUTPUT ${_system_archive}
    COMMAND ${Python3_EXECUTABLE} ${PROJECT_SOURCE_DIR}/utils/sysar
            -o ${_system_archive}
            ${_sysar_inputs}
    DEPENDS ${_sysar_inputs}
    WORKING_DIRECTORY ${CMAKE_CURRENT_BINARY_DIR}
    COMMENT "Bundling system objects into ${_system_archive}"
    COMMAND_EXPAND_LISTS
    VERBATIM)

  add_custom_target(sdk_bootstrap ALL DEPENDS ${_system_archive})
endif()

# function(mrv_add_contract <name> <sources>...)
#
# This function creates a build target for a Monad RISC-V smart contract. When
# actually cross-compiling to the RISC-V platform, it is a wrapper around
# CMake's `add_executable` command. When compiling using host emulation mode
# (where code is compiled for the host CPU and run in a simulator), it is a
# wrapper around CMake's `add_library(<name> SHARED)` command.
#
# In both cases, it passes through all arguments through to the underlying
# CMake command, and links in the RISC-V runtime start symbols (mrv_start and
# mrv_init).
function(mrv_add_contract target)
  if(MRV_PLATFORM STREQUAL "mrv")
    # For mrv, a contract is a fixed-address-layout ET_EXEC binary with
    # mrv_start as the start symbol and particular address space layout that
    # is meaningful to the VM
    add_executable(${target} $<TARGET_OBJECTS:mrv_stdlib_rt> ${ARGN})
    set_target_properties(${target} PROPERTIES
      LINK_DEPENDS ${mrvsdk_SOURCE_DIR}/toolchain/contract.ld)
  else()
    # In host mode, a contract is a dynamic shared object that is loaded
    # into the simulation program. The simulator locates mrv_start and
    # mrv_init using dlsym(3) and transfers control to them.
    add_library(${target} SHARED $<TARGET_OBJECTS:mrv_stdlib_rt> ${ARGN})
    set_target_properties(${target} PROPERTIES C_VISIBILITY_PRESET hidden)

    if(NOT APPLE)
      # Ensure `mrv_start` and `mrv_init` will be pulled in from the object
      # library mrv_stdlib_rt
      target_link_options(${target} PRIVATE LINKER:-u,mrv_start LINKER:-u,mrv_init)
    else()
      # Same as above, but macOS uses the old UNIX "linker names" concept so
      # the symbols need a `_` prefix
      target_link_options(${target} PRIVATE LINKER:-u,_mrv_start LINKER:-u,_mrv_init)
    endif()

  endif()
endfunction()

if(MRV_BUILD_EXAMPLES)
  add_subdirectory(examples)
endif()

if(MRV_PLATFORM STREQUAL "host")
  find_library(libzstd_file zstd REQUIRED)

  add_library(monad_rv STATIC
    ../category/rv/rv_code.c
    ../category/rv/rv_vm.c
    ../category/rv/rvi_code_cache.c
    ../category/rv/rvi_dynlink.c
    ../category/rv/rvi_elf.c
    ../category/rv/rvi_log_writer.c
    ../category/rv/rvi_zstd.c)
  target_include_directories(monad_rv PRIVATE third_party/musl)
  target_link_libraries(monad_rv PUBLIC monad_core_limited_static)
  target_link_libraries(monad_rv PRIVATE ${libzstd_file} evmc::evmc)

  add_subdirectory(tools)
endif()
