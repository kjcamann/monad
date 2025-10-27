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

add_library(monad-vm-event OBJECT)

target_sources(monad-vm-event PRIVATE
    "evmt_event_recorder.cpp"
    "evmt_event_recorder.hpp"
    "evmt_event_ctypes.h"
    "evmt_event_ctypes_metadata.c"
)

monad_compile_options(monad-vm-event)

target_include_directories(monad-vm-event PUBLIC ${CATEGORY_MAIN_DIR})
target_link_libraries(monad-vm-event PRIVATE monad_event evmc::evmc)

add_library(monad-vm::monad-vm-event ALIAS monad-vm-event)
