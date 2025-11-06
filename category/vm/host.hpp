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

#include <category/vm/runtime/types.hpp>

#include <evmc/evmc.hpp>

#include <exception>
#include <vector>

namespace monad::vm
{
    class VM;

    class Host : public evmc::Host
    {
        friend class VM;

    public:
        /// Capture `std::current_exception()`.
        /// IMPORTANT: Make sure to call this from inside a `catch` block.
        void capture_current_exception() const noexcept
        {
            active_exception_ = std::current_exception();
        }

        /// Propagate a previously captured exception through the most recent
        /// VM stack frame(s). The VM will re-throw the exception after
        /// unwinding the stack. IMPORTANT: Do not call this from a `catch`
        /// block, because it does not return. This can otherwise cause memory
        /// leaks due to missing deallocation of the current active exception.
        /// IMPORTANT: Since `stack_unwind` never returns, make sure there are
        /// no stack objects with uninvoked destructor.
        [[noreturn]] void stack_unwind() const noexcept
        {
            MONAD_VM_ASSERT(active_exception_);
            MONAD_VM_ASSERT(runtime_context_)
            runtime_context_->stack_unwind();
        }

        void msg_call_seqno_push(uint64_t s)
        {
            msg_call_seqno_stack_.push_back(s);
        }

        void msg_call_seqno_pop()
        {
            msg_call_seqno_stack_.pop_back();
        }

        vm::runtime::TraceFlowTag get_trace_flow_tag() const
        {
            return {
                txn_start_seqno_,
                msg_call_seqno_stack_.empty() ? 0
                                              : msg_call_seqno_stack_.back()};
        }

        uint64_t gas_remaining() const
        {
            return runtime_context_ != nullptr
                       ? static_cast<uint64_t>(runtime_context_->gas_remaining)
                       : 0;
        }

        void set_txn_start_seqno(uint64_t s)
        {
            txn_start_seqno_ = s;
        }

    private:
        [[gnu::always_inline]]
        void rethrow_on_active_exception()
        {
            if (MONAD_VM_UNLIKELY(active_exception_)) {
                auto e = active_exception_;
                active_exception_ = std::exception_ptr{};
                std::rethrow_exception(std::move(e));
            }
        }

        [[gnu::always_inline]]
        runtime::Context *set_runtime_context(runtime::Context *ctx) noexcept
        {
            auto *const prev = runtime_context_;
            runtime_context_ = ctx;
            return prev;
        }

        runtime::Context *runtime_context_{nullptr};
        uint64_t txn_start_seqno_;
        std::vector<uint64_t> msg_call_seqno_stack_;
        mutable std::exception_ptr active_exception_;
    };
}
