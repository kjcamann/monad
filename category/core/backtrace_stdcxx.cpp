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

#include <category/core/assert.h>
#include <category/core/backtrace.hpp>
#include <category/core/config.hpp>

#include <cstddef>
#include <memory_resource>
#include <span>
#include <stacktrace>

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

MONAD_NAMESPACE_BEGIN

struct stack_backtrace_impl final : public stack_backtrace
{
    std::pmr::monotonic_buffer_resource storage_buf;
    std::pmr::polymorphic_allocator<std::stacktrace_entry> stack_entry_alloc;
    std::pmr::stacktrace stacktrace;

    explicit stack_backtrace_impl(std::span<std::byte> storage)
        : storage_buf{storage.data(), storage.size()}
        , stack_entry_alloc{&storage_buf}
        , stacktrace{std::pmr::stacktrace::current(stack_entry_alloc)}
    {
    }

    size_t serialize(std::span<std::byte> serialised) const noexcept override
    {
        auto const willneed = stacktrace.size() *
                              sizeof(std::stacktrace_entry::native_handle_type);
        if (willneed > serialised.size()) {
            return willneed;
        }
        std::span const tofill(
            reinterpret_cast<std::stacktrace_entry::native_handle_type *>(
                serialised.data()),
            stacktrace.size());
        for (unsigned short n = 0; n < stacktrace.size(); n++) {
            tofill[n] = stacktrace[n].native_handle();
        }
        return willneed;
    }

    void print(int fd, unsigned indent, bool print_async_signal_unsafe_info)
        const noexcept override
    {
        char indent_buffer[64];
        memset(indent_buffer, ' ', 64);
        indent_buffer[indent] = 0;
        for (auto const &frame : stacktrace) {
            dprintf(fd, "\n%s   %08zx", indent_buffer, frame.native_handle());
        }
        if (print_async_signal_unsafe_info) {
            dprintf(
                fd,
                "\n\n%sAttempting async signal unsafe human readable "
                "stacktrace (this may hang):",
                indent_buffer);
            for (std::stacktrace_entry const &e : stacktrace) {
                dprintf(
                    fd,
                    "\n%s   %zu: %s",
                    indent_buffer,
                    e.native_handle(),
                    e.description().c_str());
                if (e.source_line() > 0) {
                    dprintf(
                        fd,
                        "\n%s                   [%s:%u]",
                        indent_buffer,
                        e.source_file().c_str(),
                        e.source_line());
                }
            }
        }
        dprintf(fd, "\n");
    }
};

stack_backtrace::ptr
stack_backtrace::capture(std::span<std::byte> storage) noexcept
{
    MONAD_ASSERT(storage.size() > sizeof(stack_backtrace_impl));
    return ptr(new (storage.data()) stack_backtrace_impl(
        storage.subspan(sizeof(stack_backtrace_impl))));
}

stack_backtrace::ptr stack_backtrace::deserialize(
    std::span<std::byte>, std::span<std::byte const>) noexcept
{
    dprintf(STDERR_FILENO, "C++23 <stacktrace> does not support deserialize");
    abort();
}

extern "C" void monad_stack_backtrace_capture_and_print(
    char *buffer, size_t size, int fd, unsigned indent,
    bool print_async_unsafe_info)
{
    stack_backtrace::capture({reinterpret_cast<std::byte *>(buffer), size})
        ->print(fd, indent, print_async_unsafe_info);
}

MONAD_NAMESPACE_END
