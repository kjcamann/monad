// Copyright (C) 2025 Category Labs, Inc.
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
//
// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU General Public License for more details.
//
// You should have received a copy of the GNU General Public License
// along with this program.  If not, see <http://www.gnu.org/licenses/>.

#pragma once

#include <cstddef>
#include <cstdint>
#include <string>

enum class TextUIMode : unsigned;
class EventCaptureFile;
struct OutputFile;

enum monad_event_content_type : uint16_t;
struct monad_evcap_writer;

constexpr size_t NotReadyCheckMask = (1UL << 25) - 1;

void copy_all_schema_sections(
    monad_evcap_writer *dst, EventCaptureFile const *src,
    monad_event_content_type skip);

bool event_ring_is_abandoned(int ring_fd);

bool use_tty_control_codes(TextUIMode, OutputFile const *);

constexpr std::string ANSI_MoveCursorTopLeft = "\x1b[H";
constexpr std::string ANSI_ClearFromCursorToEnd = "\x1b[J";
constexpr std::string ANSI_ClearScreen = "\x1b[2J";

constexpr std::string ANSI_HideCursor = "\x1b[?25l";
constexpr std::string ANSI_ShowCursor = "\x1b[?25h";

// If we don't hide the cursor first, resetting to (1,1) renders poorly on some
// terminals
constexpr std::string ANSI_ResetCursor =
    ANSI_HideCursor + ANSI_MoveCursorTopLeft;

// When we're done writing a table that updates, clear the rest of the screen
// and show the cursor again
constexpr std::string ANSI_FinishUpdate =
    ANSI_ClearFromCursorToEnd + ANSI_ShowCursor;
