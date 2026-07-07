# This file configures a clang toolchain that will cross-compile to the Monad
# RISC-V blockchain target.
#
# The user needs to create a few symlinks somewhere on their $PATH, so that
# the following commands can be found:
#
#     monad-rv-clang    An installation of clang-21 or greater; it must have
#                       been compiled with support for the RISC-V backend, which
#                       is usually the case by default (you can check by running
#                       `clang --print-targets`; `riscv64` must be listed)
#
#     monad-rv-ld       A linker which can process riscv64 object files. This
#                       will usually be lld, the LLVM linker. In this toolchain,
#                       the linker is _not_ called through the clang compiler
#                       driver, but is invoked directly
#
#     monad-rv-ar       An ar which can process riscv64 object files. You should
#                       use llvm-ar if the system ar(1) does not support RISC-V
#                       ELF objects (e.g., on macOS)
#
#     monad-rv-ranlib   A ranlib which can process riscv64 object files. You
#                       should use llvm-ranlib if the system ranlib(1) does not
#                       support RISC-V ELF objects
#
# Also, a Python interpreter with version 3.14+ must be found on the path
# (3.14 is the first version to ship with a standard module that can perform
# zstd compression)

set(CMAKE_C_COMPILER monad-rv-clang)
set(CMAKE_LINKER monad-rv-ld)

set(CMAKE_AR monad-rv-ar)
set(CMAKE_RANLIB monad-rv-ranlib)

find_package(Python3 3.14 REQUIRED COMPONENTS Interpreter)

set(CMAKE_SHARED_LIBRARY_SONAME_C_FLAG "-soname ")

set(CMAKE_C_LINK_EXECUTABLE
  "${CMAKE_LINKER} <LINK_FLAGS> -o <TARGET> <OBJECTS> <LINK_LIBRARIES> -T ${CMAKE_CURRENT_LIST_DIR}/contract.ld"
  "${Python3_EXECUTABLE} ${CMAKE_CURRENT_LIST_DIR}/../utils/mrvcpack <TARGET>")

set(CMAKE_C_CREATE_SHARED_LIBRARY
  "${CMAKE_LINKER} <LINK_FLAGS> -Bsymbolic -z now -T ${CMAKE_CURRENT_LIST_DIR}/syslib.ld <SONAME_FLAG> <TARGET_SONAME> -o <TARGET> <OBJECTS> <LINK_LIBRARIES>")

set(CMAKE_C_FLAGS_INIT "--target=riscv64-unknown-elf -march=rv64im -ffreestanding -fno-builtin -nostdlib")

# Configure CMake for a bare metal target; this will stop CMake from injecting
# settings determined by the host platform into the toolchain parameters, e.g.,
# it stops `-arch arm64` from automatically being passed to the compiler on macOS
set(CMAKE_SYSTEM_NAME Generic)
