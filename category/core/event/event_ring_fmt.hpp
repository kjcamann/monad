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

#include <category/core/event/event_ring.h>
#include <category/core/hex.hpp>

#include <format>
#include <iterator>
#include <span>
#include <string>
#include <utility>

template <>
struct std::formatter<monad_event_record_error> : std::formatter<std::string>
{
    template <typename FormatContext>
    auto format(monad_event_record_error const &value, FormatContext &ctx) const
    {
        using monad::as_hex;
        std::string s;
        std::back_insert_iterator i{s};
        i = std::format_to(i, "record_error {{");
        i = std::format_to(
            i, "error_type = {}", std::to_underlying(value.error_type));
        i = std::format_to(
            i, "dropped_event_type = {}", value.dropped_event_type);
        i = std::format_to(
            i, "truncated_payload_size = {}", value.truncated_payload_size);
        i = std::format_to(
            i, "requested_payload_size = {}", value.requested_payload_size);
        *i++ = '}';
        auto const *const p = reinterpret_cast<std::byte const *>(&value + 1);
        size_t const p_size = static_cast<size_t>(value.truncated_payload_size);
        i = std::format_to(
            i, ", truncated_payload = {}", as_hex(std::span{p, p_size}));
        return std::formatter<std::string>::format(s, ctx);
    }
};
