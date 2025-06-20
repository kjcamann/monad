# Copyright (C) 2025 Category Labs, Inc.
#
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program.  If not, see <http://www.gnu.org/licenses/>.

cmake_minimum_required(VERSION 3.31)

project(monad_eventcap)

if(PROJECT_IS_TOP_LEVEL)
  # eventcap can be built as a top-level project, as a test of the developer
  # experience for integrating with the SDK as a third-party library; in this
  # case we need the monad_event library, which a third-party would find via
  # find_package or FetchContent
  add_subdirectory(../../category/event monad-event-build)
endif()

# We need to link against libstdc++15 but it may not be available at runtime
# on Ubuntu 24.04; allow it to be statically linked to support that platform
option(MONAD_EVENTCAP_STATIC_CXX
       "Force eventcap to statically link the C++ standard library" OFF)

if(CMAKE_CXX_COMPILER_ID STREQUAL "GNU" AND
   CMAKE_CXX_COMPILER_VERSION VERSION_LESS "15.2")
  message(FATAL_ERROR "gcc 15.2 or greater is required")
endif()

if(CMAKE_CXX_COMPILER_ID STREQUAL "Clang" AND
   CMAKE_CXX_COMPILER_VERSION VERSION_LESS "19")
  message(FATAL_ERROR "clang 19 or greater is required")
endif()

find_package(CLI11 REQUIRED)
find_package(OpenSSL REQUIRED COMPONENTS Crypto)
find_package(zstd REQUIRED)

add_executable(eventcap
  blockstat.cpp
  digest.cpp
  dump.cpp
  err_cxx.hpp
  eventcap.hpp
  eventsource.cpp
  eventsource.hpp
  execstat.cpp
  header.cpp
  init.cpp
  main.cpp
  metadata.hpp
  options.hpp
  record.cpp
  recordexec.cpp
  snapshot.cpp
  stats.cpp
  stats.hpp
  stacktrace.cpp
  util.cpp
  util.hpp)

target_compile_definitions(eventcap PRIVATE _GNU_SOURCE)
target_compile_definitions(eventcap PRIVATE ZSTD_STATIC_LINKING_ONLY)
target_compile_features(eventcap PRIVATE cxx_std_23)
target_compile_options(eventcap PRIVATE -Wall -Wextra -Wconversion -Werror)

# Disable some warnings
target_compile_options(eventcap PRIVATE -Wno-c99-designator)
target_compile_options(eventcap PRIVATE -Wno-missing-field-initializers)

target_link_libraries(eventcap PRIVATE
    monad_event CLI11::CLI11 zstd::libzstd OpenSSL::Crypto)

target_link_libraries(eventcap PRIVATE -lstdc++exp)

if(MONAD_EVENTCAP_STATIC_CXX)
  target_link_options(eventcap PRIVATE -static-libstdc++)
endif()
