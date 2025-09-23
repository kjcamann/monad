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

#include <expected>
#include <optional>
#include <string>
#include <string_view>

struct BlockLabel;
struct EventCaptureSpec;
struct SequenceNumberSpec;

// Represents the parsed form of an <event-source-spec>
struct ParsedEventSourceSpec
{
    std::string named_input;
    std::string event_source_file;
    std::string capture_spec;
};

std::expected<EventCaptureSpec, std::string>
parse_event_capture_spec(std::string_view capture_spec);

std::expected<ParsedEventSourceSpec, std::string>
parse_event_source_spec(std::string_view event_source_spec);

std::expected<BlockLabel, std::string>
parse_block_label(std::string_view block_label);

std::expected<SequenceNumberSpec, std::string>
parse_sequence_number_spec(std::string_view spec);
