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

#include <category/vm/llvm/llvm_state.hpp>
#include <category/vm/llvm/virtual_stack.hpp>

#include <category/vm/evm/traits.hpp>
#include <category/vm/runtime/call.hpp>
#include <category/vm/runtime/create.hpp>
#include <category/vm/runtime/data.hpp>
#include <category/vm/runtime/detail.hpp>
#include <category/vm/runtime/environment.hpp>
#include <category/vm/runtime/keccak.hpp>
#include <category/vm/runtime/log.hpp>
#include <category/vm/runtime/math.hpp>
#include <category/vm/runtime/memory.hpp>
#include <category/vm/runtime/selfdestruct.hpp>
#include <category/vm/runtime/storage.hpp>

namespace monad::vm::llvm
{
    using namespace monad::vm::compiler;
    using namespace monad::vm::runtime;

    using enum Terminator;
    using enum OpCode;

    inline std::string instr_name(Instruction const &instr)
    {
        return std::format("{}", instr);
    }

    inline std::string term_name(Terminator term)
    {
        return std::format("{}", term);
    }

    struct OpDefnArgs
    {
        Value *ctx_ref;
        Value *gas_remaining;
        std::vector<Value *> var_args;
    };

    struct SaveInsert
    {
        explicit SaveInsert(LLVMState &llvm)
            : llvm(llvm)
        {
            llvm.save_insert();
        }

        ~SaveInsert()
        {
            llvm.restore_insert();
        }

    private:
        LLVMState &llvm;
    };

    template <Traits traits>
    struct Emitter
    {

    public:
        Emitter(LLVMState &llvm, BasicBlocksIR &ir)
            : llvm(llvm)
            , ir(ir)
            , gas_from_inlining(ir.blocks().size())
        {
            inline_empty_fallthroughs();
        }

        void terminate_block(
            Block const &blk, VirtualStack &stack, Value *stack_top,
            bool const stack_top_updated)
        {
            auto const term = blk.terminator;
            switch (term) {
            case Jump:
                jump(stack, stack_top, stack_top_updated);
                return;
            case JumpI:
                jumpi(blk, stack, stack_top, stack_top_updated);
                return;
            case FallThrough:
                fallthrough_to_jumpdest(
                    blk, stack, stack_top, stack_top_updated);
                return;
            case Stop:
                llvm.debug("stop\n");
                llvm.br(return_lbl);
                return;
            case Return:
                llvm.debug("return\n");
                prep_for_return(stack);
                llvm.br(return_lbl);
                return;
            case Revert:
                llvm.debug("revert\n");
                prep_for_return(stack);
                llvm.br(revert_lbl);
                return;
            case SelfDestruct:
                llvm.debug("self destruct\n");
                selfdestruct_(stack);
                return;
            default:
                llvm.debug("invalid instruction\n");
                MONAD_VM_ASSERT(term == InvalidInstruction);
                llvm.br(error_lbl);
                return;
            };
        };

        void emit_contract()
        {
            bool const any_jumpdests = ir.jump_dests().size() > 0;

            contract_start(any_jumpdests);

            VirtualStack stack;
            Value *stack_top = evm_stack_begin;
            int64_t total_delta = 0;

            for (size_t i = 0; i < ir.blocks().size(); ++i) {
                auto const &blk = ir.blocks()[i];

                base_gas_remaining =
                    block_base_gas<traits>(blk) + gas_from_inlining[i];

                auto *lbl = get_block_lbl(blk);

                llvm.insert_at(lbl);

                llvm.debug(std::format(
                    "\nblock {} is {}\n",
                    blk.offset,
                    is_jumpdest(blk) ? "jumpdest" : "fall through"));

                if (is_jumpdest(blk)) {
                    llvm.debug("clear stack and update stack_top\n");
                    stack.clear();
                    stack_top = load_stack_top_p();
                    total_delta = 0;
                    jumpdests.emplace_back(blk.offset, lbl);
                }

                else {
                    llvm.debug(std::format(
                        "carry over stack (size = {}) and stack_top\n",
                        stack.size()));
                }

                // compute low/delta/high stack water marks
                auto [low, delta, high] = blk.stack_deltas();

                llvm.debug(std::format("virtstack size={}\n", stack.size()));

                llvm.debug(std::format(
                    "low={}, high={}, delta={}, total_delta={}\n",
                    low,
                    high,
                    delta,
                    total_delta));

                if (low < -1024 || // impossible to not be out of bounds
                    high > 1024 || (blk.terminator == Jump && !any_jumpdests)) {
                    llvm.br(error_lbl);
                    continue;
                }

                // compute gas
                int64_t const min_gas = is_jumpdest(blk)
                                            ? 1 + base_gas_remaining
                                            : base_gas_remaining;

                update_gas(min_gas, blk.offset);

                Value *stack_top_pre = stack_top;
                if (total_delta != 0) {
                    stack_top_pre = evm_stack_idx(stack_top, total_delta);
                }

                check_underflow(low, stack_top_pre, blk.offset);
                check_overflow(high, stack_top_pre, blk.offset);
                stack_unspill(low, stack, stack_top_pre);

                for (auto const &instr : blk.instrs) {
                    base_gas_remaining -= instr.static_gas_cost();

                    emit_instr(instr, stack);
                }

                base_gas_remaining -=
                    terminator_static_gas<traits>(blk.terminator);

                total_delta += delta;

                Value *stack_top_next = stack_top;
                bool const stack_top_updated = total_delta != 0;
                if (stack_top_updated) {
                    stack_top_next = evm_stack_idx(stack_top, total_delta);
                }

                terminate_block(blk, stack, stack_top_next, stack_top_updated);
            }

            contract_finish();
        }

    private:
        LLVMState &llvm;
        BasicBlocksIR &ir;

        Value *g_ctx_ref = nullptr;
        Value *g_ctx_gas_ref = nullptr;
        Value *g_local_gas_ref = nullptr;

        Value *evm_stack_begin = nullptr;
        Value *evm_stack_end = nullptr;
        Value *evm_stack_top_p = nullptr;

        std::unordered_map<std::string, Function *> llvm_opcode_tbl;
        // ^ string instead of opcode for Log

        std::vector<std::tuple<byte_offset, BasicBlock *>> jumpdests;

        std::vector<int32_t> gas_from_inlining;

        std::unordered_map<byte_offset, BasicBlock *> block_tbl;
        int64_t base_gas_remaining;

        Type *context_ty = llvm.void_ty;

        Function *exit_f = init_exit();
        Function *selfdestruct_f = nullptr;

        Value *jump_mem = nullptr;
        BasicBlock *jump_lbl = nullptr;
        BasicBlock *error_lbl = nullptr;
        BasicBlock *return_lbl = nullptr;
        BasicBlock *revert_lbl = nullptr;
        BasicBlock *entry = nullptr;
        Function *contract = nullptr;

        Function *evm_push_f = nullptr;
        Function *evm_pop_f = nullptr;

        void copy_gas(Value *from, Value *to)
        {
            auto *gas = llvm.load(llvm.int_ty(64), from);
            llvm.store(gas, to);
        }

        void store_stack_top_p(Value *stack_top)
        {
            llvm.debug("storing new stack_top_p\n");
            llvm.store(stack_top, evm_stack_top_p);
        }

        Value *load_stack_top_p()
        {
            llvm.debug("loading stacktop_p\n");
            return llvm.load(llvm.ptr_ty(llvm.word_ty), evm_stack_top_p);
        }

        void contract_start(bool any_jumpdests)
        {
            auto [contractf, arg] = llvm.external_function_definition(
                "contract",
                llvm.void_ty,
                {llvm.ptr_ty(llvm.word_ty), llvm.ptr_ty(context_ty)});
            contractf->addFnAttr(Attribute::NoReturn);
            contract = contractf;

            entry = llvm.basic_block("entry", contract);
            error_lbl = llvm.basic_block("error_lbl", contract);
            return_lbl = llvm.basic_block("return_lbl", contract);
            revert_lbl = llvm.basic_block("revert_lbl", contract);

            llvm.insert_at(entry);

            // BAL: should the stack be allocated here instead of passed in?
            evm_stack_begin = arg[0];
            g_ctx_ref = arg[1];

            // llvm.comment("init.the.gas");
            g_ctx_gas_ref = context_gep(
                g_ctx_ref, context_offset_gas_remaining, "ctx_gas_ref");

            g_local_gas_ref = llvm.alloca_(llvm.int_ty(64), "local_gas_ref");
            copy_gas(g_ctx_gas_ref, g_local_gas_ref);

            // llvm.comment("init.the.stack");

            evm_stack_end = llvm.gep(
                llvm.word_ty, evm_stack_begin, llvm.u64(1024), "evm_stack_end");

            evm_stack_top_p =
                llvm.alloca_(llvm.ptr_ty(llvm.word_ty), "evm_stack_top_p");

            if (any_jumpdests) {
                store_stack_top_p(evm_stack_begin);
            }

            llvm.insert_at(error_lbl);
            exit_(StatusCode::Error);

            llvm.insert_at(return_lbl);
            exit_(StatusCode::Success);

            llvm.insert_at(revert_lbl);
            exit_(StatusCode::Revert);

            llvm.insert_at(entry);
        }

        void emit_jumptable()
        {
            MONAD_VM_ASSERT(jump_lbl != nullptr);
            MONAD_VM_ASSERT(jump_mem != nullptr);
            MONAD_VM_ASSERT(jumpdests.size() > 0);

            llvm.insert_at(jump_lbl);
            auto *d = llvm.load(llvm.word_ty, jump_mem);

            // create switch
            auto *jump_lbl_switch = llvm.switch_(
                d, error_lbl, static_cast<unsigned>(jumpdests.size()));

            for (auto [k, v] : jumpdests) {
                auto *c = llvm.lit_word(static_cast<uint256_t>(k));
                jump_lbl_switch->addCase(c, v);
            }
        };

        Value *evm_stack_idx(Value *stack_top, int64_t i)
        {
            return llvm.gep(
                llvm.word_ty, stack_top, llvm.i64(i), "evm_stack_idx");
        };

        // spill virtual stack values to the evm runtime stack
        void stack_spill(
            VirtualStack const &stack, Value *stack_top,
            bool const stack_top_updated)
        {
            int64_t sz = stack.size();

            llvm.debug(std::format("spilling stack size {}\n", sz));

            if (stack_top_updated) {
                llvm.debug("storing stack top pointer\n");
                store_stack_top_p(stack_top);
            }
            else {
                llvm.debug("no need to store stack top pointer\n");
            }

            for (int64_t i = -1; i >= -sz; --i) {
                llvm.debug(std::format("spilling stack index {}\n", i));
                Value *v = stack.peek(i);
                Value *p = evm_stack_idx(stack_top, i);
                llvm.store(v, p);
            }
        };

        // unspill values from the evm runtime stack to the virtual stack (if
        // necessary)
        void stack_unspill(int64_t low, VirtualStack &stack, Value *stack_top)
        {
            auto sz = stack.size();

            llvm.debug(std::format(
                "unspilling stack size {}, low = {}, net = {}\n",
                sz,
                -low,
                sz + low));

            for (int64_t i = -sz - 1; i >= low; --i) {
                llvm.debug(std::format("unspilling stack index {}\n", i));
                Value *p = evm_stack_idx(stack_top, i);
                Value *v = llvm.load(llvm.word_ty, p);
                // fallthroughs want to be inserted at the beginning
                stack.push_front(v);
            }
        };

        void contract_finish()
        {
            llvm.insert_at(entry);
            MONAD_VM_ASSERT(ir.blocks().size() > 0);
            llvm.br(get_block_lbl(ir.blocks().front()));

            // add jump table if needed
            if (jump_lbl != nullptr) {
                emit_jumptable();
            }
        };

        bool reads_ctx_gas(OpCode op)
        {
            return (
                op == Balance || op == BlobHash || op == BlockHash ||
                op == Call || op == CallCode || op == CallDataCopy ||
                op == CallDataLoad || op == CodeCopy || op == Create ||
                op == Create2 || op == DelegateCall || op == Exp ||
                op == ExtCodeCopy || op == ExtCodeHash || op == ExtCodeSize ||
                op == Log || op == MCopy || op == MLoad || op == MStore ||
                op == MStore8 || op == ReturnDataCopy || op == SLoad ||
                op == SStore || op == SelfBalance || op == Sha3 ||
                op == StaticCall || op == TLoad || op == TStore);
        };

        bool writes_ctx_gas(OpCode op)
        {
            return (
                op == Balance || op == Call || op == CallCode ||
                op == CallDataCopy || op == CodeCopy || op == Create ||
                op == Create2 || op == DelegateCall || op == Exp ||
                op == ExtCodeCopy || op == ExtCodeHash || op == ExtCodeSize ||
                op == Log || op == MCopy || op == MLoad || op == MStore ||
                op == MStore8 || op == ReturnDataCopy || op == SLoad ||
                op == SStore || op == Sha3 || op == StaticCall);
        };

        void emit_instr(Instruction const &instr, VirtualStack &stack)
        {
            auto const op = instr.opcode();

            switch (op) {
            case Push:
                stack.push(llvm.lit_word(instr.immediate_value()));
                break;

            case Pc:
                stack.push(llvm.lit_word(instr.pc()));
                break;

            case Dup:
                stack.dup(instr.index());
                break;

            case Swap:
                stack.swap(instr.index());
                break;

            case Pop:
                stack.pop();
                break;

            case Gas:
                llvm_gas(stack);
                break;

            default:
                Function *f;
                auto const nm = instr_name(instr);

                auto const item = llvm_opcode_tbl.find(nm);
                if (item != llvm_opcode_tbl.end()) {
                    f = item->second;
                }
                else {
                    f = init_instr(instr);
                    llvm_opcode_tbl.insert({nm, f});
                }

                std::vector<Value *> args;

                args.push_back(g_ctx_ref);

                MONAD_VM_DEBUG_ASSERT(base_gas_remaining >= 0);

                auto *g =
                    llvm.lit(64, static_cast<uint64_t>(base_gas_remaining));
                args.push_back(g);

                for (auto i = 0; i < instr.stack_args(); ++i) {
                    auto *v = stack.pop();
                    args.push_back(v);
                }

                if (reads_ctx_gas(op)) {
                    copy_gas(g_local_gas_ref, g_ctx_gas_ref);
                }

                if (instr.increases_stack()) {
                    stack.push(llvm.call(f, args));
                }
                else {
                    llvm.call_void(f, args);
                }

                if (writes_ctx_gas(op)) {
                    copy_gas(g_ctx_gas_ref, g_local_gas_ref);
                }
            }
        };

        std::tuple<Value *, BasicBlock *> get_jump_info()
        {
            if (jump_mem == nullptr) {
                SaveInsert const _unused(llvm);

                MONAD_VM_ASSERT(jump_lbl == nullptr);

                llvm.insert_at(entry);
                jump_mem = llvm.alloca_(llvm.word_ty, "jump_mem");

                jump_lbl = llvm.basic_block("do_jump", contract);
            }

            return std::tuple(jump_mem, jump_lbl);
        };

        void inline_empty_fallthroughs()
        {
            // rewrite from the bottom up so we can take advantage of previous
            // rewrites
            uint64_t i = ir.blocks().size();
            while (i > 0) {
                --i;
                Block &blk = ir.blocks()[i];
                if (blk.terminator == Terminator::FallThrough) {
                    Block const &dest = ir.blocks()[blk.fallthrough_dest];
                    if (dest.instrs.size() == 0) {
                        gas_from_inlining[i] = is_jumpdest(dest) ? 1 : 0;
                        gas_from_inlining[i] +=
                            gas_from_inlining[blk.fallthrough_dest];
                        blk.terminator = dest.terminator;
                        blk.fallthrough_dest = dest.fallthrough_dest;
                    }
                    else {
                        gas_from_inlining[i] = 0;
                    }
                }
            }

            MONAD_VM_DEBUG_ASSERT(ir.is_valid());
        }

        bool is_jumpdest(Block const &blk)
        {
            auto const item = ir.jump_dests().find(blk.offset);
            return (item != ir.jump_dests().end());
        };

        void emit_jump(Value *v)
        {
            if (ir.jump_dests().size() == 0) {
                llvm.br(error_lbl);
            }
            else {
                auto [p, lbl] = get_jump_info();
                llvm.store(v, p);
                llvm.br(lbl);
            }
        };

        Block const &get_fallthrough_block(Block const &blk)
        {
            auto const dest = blk.fallthrough_dest;
            MONAD_VM_ASSERT(
                dest != INVALID_BLOCK_ID && dest < ir.blocks().size());
            return ir.blocks()[dest];
        };

        void fallthrough_to_jumpdest(
            Block const &blk, VirtualStack const &stack, Value *stack_top,
            bool const stack_top_updated)
        {
            auto const next_blk = get_fallthrough_block(blk);
            MONAD_VM_ASSERT(is_jumpdest(next_blk));
            llvm.debug("fall through to jumpdest\n");
            stack_spill(stack, stack_top, stack_top_updated);
            llvm.br(get_block_lbl(next_blk));
        };

        void jump(
            VirtualStack &stack, Value *stack_top, bool const stack_top_updated)
        {
            auto *v = stack.pop();
            llvm.debug("jump\n");
            stack_spill(stack, stack_top, stack_top_updated);
            emit_jump(v);
        };

        void jumpi(
            Block const &blk, VirtualStack &stack, Value *stack_top,
            bool const stack_top_updated)
        {
            llvm.debug("jumpi\n");
            auto *v = stack.pop();
            auto *b = stack.pop();
            auto *isz = llvm.eq(b, llvm.lit_word(0));

            auto const fallthrough_block = get_fallthrough_block(blk);
            BasicBlock *then_lbl = get_block_lbl(fallthrough_block);

            BasicBlock *else_lbl = llvm.basic_block(
                std::format("else_lbl_{}", blk.offset), contract);

            auto const fallthrough_is_jumpdest = is_jumpdest(fallthrough_block);

            if (fallthrough_is_jumpdest) {
                llvm.debug("jumpi fallthrough is jumpdest, spilling prior to "
                           "condbr\n");
                stack_spill(stack, stack_top, stack_top_updated);
            }
            else {
                llvm.debug("jumpi fallthrough not jumpdest, ");
                llvm.debug("spilling in else branch\n");
            }

            llvm.condbr(isz, then_lbl, else_lbl);

            llvm.insert_at(else_lbl);

            if (!fallthrough_is_jumpdest) {
                llvm.debug("else branch spill\n");
                stack_spill(stack, stack_top, stack_top_updated);
            }

            emit_jump(v);
        }

        Function *init_exit()
        {
            auto [f, _arg] = llvm.external_function_definition(
                "rt_EXIT",
                llvm.void_ty,
                {llvm.ptr_ty(context_ty), llvm.int_ty(64)});
            f->addFnAttr(Attribute::NoReturn);
            return f;
        }

        void exit_(StatusCode status)
        {
            copy_gas(g_local_gas_ref, g_ctx_gas_ref);

            llvm.call_void(
                exit_f,
                {g_ctx_ref, llvm.lit(64, static_cast<uint64_t>(status))});
            llvm.unreachable();
        }

        void selfdestruct_(VirtualStack &stack)
        {
            if (selfdestruct_f == nullptr) {
                selfdestruct_f = declare_symbol(
                    term_name(SelfDestruct),
                    (void *)(&selfdestruct<traits>),
                    llvm.void_ty,
                    {llvm.ptr_ty(context_ty), llvm.ptr_ty(llvm.word_ty)});
            }

            copy_gas(g_local_gas_ref, g_ctx_gas_ref);

            auto *addr = stack.pop();
            auto *p = assign(addr, "addr");
            llvm.call_void(selfdestruct_f, {g_ctx_ref, p});
            llvm.unreachable();
            llvm.ret_void();
        };

        void prep_for_return(VirtualStack &stack)
        {
            auto *a = stack.pop();
            auto *b = stack.pop();
            auto *offsetp = context_gep(
                g_ctx_ref, context_offset_result_offset, "result_offset");
            llvm.store(a, offsetp);
            auto *sizep = context_gep(
                g_ctx_ref, context_offset_result_size, "result_size");
            llvm.store(b, sizep);
        }

        void check_underflow(int64_t low, Value *stack_top, byte_offset offset)
        {
            if (low >= 0) {
                llvm.debug("no need to check underflow\n");
                return;
            }
            auto *no_underflow_lbl = llvm.basic_block(
                std::format("no_underflow_lbl_{}", offset), contract);

            auto *stack_low = evm_stack_idx(stack_top, low);

            auto *low_pred = llvm.slt(stack_low, evm_stack_begin);
            llvm.condbr(low_pred, error_lbl, no_underflow_lbl);

            llvm.insert_at(no_underflow_lbl);
        };

        void check_overflow(int64_t high, Value *stack_top, byte_offset offset)
        {
            if (high <= 0) {
                llvm.debug("no need to check overflow\n");
                return;
            }
            auto *no_overflow_lbl = llvm.basic_block(
                std::format("no_overflow_lbl_{}", offset), contract);

            auto *stack_high = evm_stack_idx(stack_top, high);

            auto *high_pred = llvm.sgt(stack_high, evm_stack_end);
            llvm.condbr(high_pred, error_lbl, no_overflow_lbl);

            llvm.insert_at(no_overflow_lbl);
        };

        void update_gas(int64_t const min_gas, byte_offset offset)
        {
            auto *gas = llvm.load(llvm.int_ty(64), g_local_gas_ref);
            auto *gas1 =
                llvm.sub(gas, llvm.lit(64, static_cast<uint64_t>(min_gas)));
            auto *gas_lt_zero = llvm.slt(gas1, llvm.lit(64, 0));

            auto *gas_ok_lbl = llvm.basic_block(
                std::format("gas_ok_lbl_{}", offset), contract);

            llvm.condbr(gas_lt_zero, error_lbl, gas_ok_lbl);
            llvm.insert_at(gas_ok_lbl);
            llvm.store(gas1, g_local_gas_ref);
        }

        BasicBlock *get_block_lbl(Block const &blk)
        {
            auto const item = block_tbl.find(blk.offset);
            if (item == block_tbl.end()) {
                auto const *nm = is_jumpdest(blk) ? "jd" : "fallthrough";
                auto *lbl = llvm.basic_block(
                    std::format("{}_lbl_{}", nm, blk.offset), contract);
                block_tbl.insert({blk.offset, lbl});
                return lbl;
            }
            return item->second;
        };

        Value *context_gep(Value *ctx_ref, uint64_t offset, std::string_view nm)
        {
            return llvm.gep(llvm.int_ty(8), ctx_ref, llvm.lit(64, offset), nm);
        };

        Value *assign(Value *v, std::string_view nm)
        {
            Value *p = llvm.alloca_(llvm.word_ty, nm);
            llvm.store(v, p);
            return p;
        }

        Function *declare_symbol(
            std::string_view nm0, void *f, Type *ty,
            std::vector<Type *> const &tys)
        {
            std::string const nm = "ffi_" + std::string(nm0);
            llvm.insert_symbol(nm, f);
            return llvm.declare_function(nm, ty, tys, true);
        };

        template <typename... FnArgs>
        Function *ffi_runtime(Instruction const &instr, void (*fun)(FnArgs...))
        {
            SaveInsert const _unused(llvm);

            constexpr auto has_ctx = detail::uses_context_v<FnArgs...>;
            constexpr auto has_gas = detail::uses_remaining_gas_v<FnArgs...>;
            bool const has_ret = instr.increases_stack();
            size_t const n = instr.stack_args();
            std::string const nm = instr_name(instr);

            std::vector<Type *> tys;
            std::vector<Type *> ffi_tys;

            tys.push_back(
                llvm.ptr_ty(context_ty)); // first param always context
            tys.push_back(
                llvm.int_ty(64)); // second param always block gas remaining

            if (has_ctx) {
                ffi_tys.push_back(llvm.ptr_ty(context_ty));
            }

            if (has_ret) {
                ffi_tys.push_back(llvm.ptr_ty(llvm.word_ty)); // result
            }

            for (size_t i = 0; i < n; ++i) {
                tys.push_back(llvm.word_ty);
                ffi_tys.push_back(llvm.ptr_ty(llvm.word_ty));
            }

            if (has_gas) {
                ffi_tys.push_back(llvm.int_ty(64));
            }

            auto *ffi = declare_symbol(nm, (void *)fun, llvm.void_ty, ffi_tys);

            auto [f, arg] = llvm.internal_function_definition(
                nm, has_ret ? llvm.word_ty : llvm.void_ty, tys);
            auto *entry = llvm.basic_block("entry", f);
            llvm.insert_at(entry);

            std::vector<Value *> vals;

            if (has_ctx) {
                vals.push_back(arg[0]);
            }

            for (size_t i = 0; i < n; ++i) {
                auto *p = assign(
                    arg[i + 2], "arg"); // uint256 values start at index 2
                vals.push_back(p);
            }

            Value *r = nullptr;

            long const di = has_ctx ? 1 : 0;

            if (has_ret) {
                r = n == 0 ? llvm.alloca_(llvm.word_ty, "retval") : vals[1];
                vals.insert(vals.begin() + di, r);
            }

            if (has_gas) {
                vals.push_back(arg[1]);
            }

            llvm.call_void(ffi, vals);

            if (has_ret) {
                llvm.ret(llvm.load(llvm.word_ty, r));
            }
            else {
                llvm.ret_void();
            }

            return f;
        };

        std::tuple<Function *, OpDefnArgs const>
        internal_op_definition(Instruction const &instr, int n)
        {
            std::vector<Type *> tys;
            tys.push_back(llvm.ptr_ty(context_ty));
            tys.push_back(llvm.int_ty(64));
            for (auto i = 0; i < n; ++i) {
                tys.push_back(llvm.word_ty);
            }
            auto [f, arg] = llvm.internal_function_definition(
                instr_name(instr), llvm.word_ty, tys);

            auto *a = arg[0];
            auto *b = arg[1];
            arg.erase(arg.begin(), arg.begin() + 2);

            OpDefnArgs const args = {a, b, arg};

            return std::make_tuple(f, args);
        }

        std::tuple<Function *, Value *> context_fun(Instruction const &instr)
        {
            auto [f, args] = internal_op_definition(instr, 0);
            auto *entry = llvm.basic_block("entry", f);
            llvm.insert_at(entry);
            return std::make_tuple(f, args.ctx_ref);
        };

        Function *load_context_addr(Instruction const &instr, uint64_t offset)
        {
            SaveInsert const _unused(llvm);

            auto [f, vctx] = context_fun(instr);
            auto *ref = context_gep(vctx, offset, "context_addr");
            auto *val = llvm.load(llvm.addr_ty, ref);
            llvm.ret(llvm.addr_to_word(val));
            return f;
        };

        Function *load_context_uint32(Instruction const &instr, uint64_t offset)
        {
            SaveInsert const _unused(llvm);

            auto [f, vctx] = context_fun(instr);
            auto *ref = context_gep(vctx, offset, "context_u32");
            auto *val = llvm.load(llvm.int_ty(32), ref);
            llvm.ret(llvm.cast_word(val));
            return f;
        };

        Function *load_context_uint64(Instruction const &instr, uint64_t offset)
        {
            SaveInsert const _unused(llvm);

            auto [f, vctx] = context_fun(instr);
            auto *ref = context_gep(vctx, offset, "context_u64");
            auto *val = llvm.load(llvm.int_ty(64), ref);
            llvm.ret(llvm.cast_word(val));
            return f;
        };

        Function *load_context_be(Instruction const &instr, uint64_t offset)
        {
            SaveInsert const _unused(llvm);

            auto [f, vctx] = context_fun(instr);
            auto *ref = context_gep(vctx, offset, "context_be");
            auto *val = llvm.load(llvm.word_ty, ref);
            llvm.ret(llvm.bswap(val));
            return f;
        };

        Function *llvm_unop(
            Instruction const &instr, Value *(LLVMState::*method)(Value *))
        {
            SaveInsert const _unused(llvm);

            auto [f, args] = internal_op_definition(instr, 1);
            auto *entry = llvm.basic_block("entry", f);
            llvm.insert_at(entry);
            llvm.ret((&llvm->*method)(args.var_args[0]));
            return f;
        }

        Function *llvm_binop(
            Instruction const &instr,
            Value *(LLVMState::*method)(Value *, Value *))
        {
            SaveInsert const _unused(llvm);

            auto [f, args] = internal_op_definition(instr, 2);
            auto *a = args.var_args[0];
            auto *b = args.var_args[1];
            auto *entry = llvm.basic_block("entry", f);
            llvm.insert_at(entry);
            llvm.ret(llvm.cast_word((&llvm->*method)(a, b)));
            return f;
        }

        Function *llvm_modop(
            Instruction const &instr,
            Value *(LLVMState::*method)(Value *, Value *, Value *))
        {
            SaveInsert const _unused(llvm);

            auto [f, args] = internal_op_definition(instr, 3);

            auto *a = args.var_args[0];
            auto *b = args.var_args[1];
            auto *n = args.var_args[2];

            auto *entry = llvm.basic_block("entry", f);
            auto *denom_is_0 = llvm.basic_block("denom_is_0", f);
            auto *denom_not_0 = llvm.basic_block("denom_not_0", f);

            llvm.insert_at(entry);
            llvm.condbr(llvm.eq(n, llvm.lit_word(0)), denom_is_0, denom_not_0);

            llvm.insert_at(denom_is_0);
            llvm.ret(llvm.lit_word(0));

            llvm.insert_at(denom_not_0);
            llvm.ret(llvm.cast_word((&llvm->*method)(a, b, n)));

            return f;
        }

        // needed for sdiv overflow semantics (minBound / -1)
        Function *llvm_sdivop(Instruction const &instr)
        {
            SaveInsert const _unused(llvm);

            auto [f, args] = internal_op_definition(instr, 2);
            Value *numer = args.var_args[0];
            Value *denom = args.var_args[1];

            auto *zero = llvm.lit_word(0);
            auto *neg1 = llvm.lit_word(
                0xffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff_u256);
            auto *minbound = llvm.lit_word(
                0x8000000000000000000000000000000000000000000000000000000000000000_u256);

            auto *entry = llvm.basic_block("entry", f);
            auto *ret_zero = llvm.basic_block("ret_zero", f);
            auto *ret_overflow = llvm.basic_block("ret_overflow", f);
            auto *ret_sdiv = llvm.basic_block("ret_sdiv", f);
            auto *try_denominator_neg1 =
                llvm.basic_block("try_denominator_neg1", f);
            auto *try_overflow_semantics =
                llvm.basic_block("try_overflow_semantics", f);

            llvm.insert_at(ret_zero);
            llvm.ret(zero);

            llvm.insert_at(ret_overflow);
            llvm.ret(minbound);

            llvm.insert_at(ret_sdiv);
            llvm.ret(llvm.sdiv(numer, denom));

            llvm.insert_at(entry); // check for denominator is 0
            llvm.condbr(llvm.eq(denom, zero), ret_zero, try_denominator_neg1);

            llvm.insert_at(try_denominator_neg1); // check for denominator is -1
            llvm.condbr(llvm.eq(denom, neg1), try_overflow_semantics, ret_sdiv);

            llvm.insert_at(
                try_overflow_semantics); // check for numerator is minbound
            llvm.condbr(llvm.eq(numer, minbound), ret_overflow, ret_sdiv);

            return f;
        }

        Function *llvm_divop(
            Instruction const &instr,
            Value *(LLVMState::*method)(Value *, Value *))
        {
            SaveInsert const _unused(llvm);

            auto [f, args] = internal_op_definition(instr, 2);
            Value *numer = args.var_args[0];
            Value *denom = args.var_args[1];
            auto *entry = llvm.basic_block("entry", f);
            llvm.insert_at(entry);

            auto *isz = llvm.eq(denom, llvm.lit_word(0));
            auto *then_lbl = llvm.basic_block("then_lbl", f);
            auto *else_lbl = llvm.basic_block("else_lbl", f);

            llvm.condbr(isz, then_lbl, else_lbl);

            llvm.insert_at(then_lbl);
            llvm.ret(llvm.lit_word(0));

            llvm.insert_at(else_lbl);
            llvm.ret((&llvm->*method)(numer, denom));

            return f;
        }

        Function *llvm_shiftop(
            Instruction const &instr,
            Value *(LLVMState::*method)(Value *, Value *))
        {
            SaveInsert const _unused(llvm);

            auto [f, args] = internal_op_definition(instr, 2);
            auto *entry = llvm.basic_block("entry", f);
            llvm.insert_at(entry);

            auto *a = args.var_args[0];
            auto *b = args.var_args[1];

            auto *isgt = llvm.ugt(a, llvm.lit_word(255));
            auto *then_lbl = llvm.basic_block("then_lbl", f);
            auto *else_lbl = llvm.basic_block("else_lbl", f);

            llvm.condbr(isgt, then_lbl, else_lbl);

            llvm.insert_at(then_lbl);
            llvm.ret(llvm.lit_word(0));

            llvm.insert_at(else_lbl);
            llvm.ret((&llvm->*method)(b, a));

            return f;
        }

        void llvm_gas(VirtualStack &stack)
        {
            auto *gas = llvm.load(llvm.int_ty(64), g_local_gas_ref);
            auto *r = llvm.add(
                gas, llvm.lit(64, static_cast<uint64_t>(base_gas_remaining)));
            stack.push(llvm.cast_word(r));
        }

        Function *llvm_byte(Instruction const &instr)
        {
            SaveInsert const _unused(llvm);

            auto [f, args] = internal_op_definition(instr, 2);

            auto *a = args.var_args[0];
            auto *b = args.var_args[1];

            auto *entry = llvm.basic_block("entry", f);
            llvm.insert_at(entry);

            auto *isgt = llvm.ugt(a, llvm.lit_word(31));
            auto *then_lbl = llvm.basic_block("then_lbl", f);
            auto *else_lbl = llvm.basic_block("else_lbl", f);

            llvm.condbr(isgt, then_lbl, else_lbl);

            llvm.insert_at(then_lbl);
            llvm.ret(llvm.lit_word(0));

            llvm.insert_at(else_lbl);

            auto *nbytes = llvm.sub(llvm.lit_word(31), a);
            auto *nbits = llvm.mul(nbytes, llvm.lit_word(8));
            llvm.ret(llvm.and_(llvm.shr(b, nbits), llvm.lit_word(255)));
            return f;
        }

        Function *llvm_sar(Instruction const &instr)
        {
            SaveInsert const _unused(llvm);

            auto [f, args] = internal_op_definition(instr, 2);
            auto *entry = llvm.basic_block("entry", f);
            llvm.insert_at(entry);

            auto *a = args.var_args[0];
            auto *b = args.var_args[1];

            auto *isgt = llvm.ugt(a, llvm.lit_word(255));
            auto *then_lbl = llvm.basic_block("then_lbl", f);
            auto *else_lbl = llvm.basic_block("else_lbl", f);

            llvm.condbr(isgt, then_lbl, else_lbl);

            llvm.insert_at(then_lbl);
            llvm.ret(llvm.sar(b, llvm.lit_word(255)));

            llvm.insert_at(else_lbl);
            llvm.ret(llvm.sar(b, a));

            return f;
        }

        Function *llvm_signextend(Instruction const &instr)
        {
            SaveInsert const _unused(llvm);

            auto [f, args] = internal_op_definition(instr, 2);

            auto *a = args.var_args[0];
            auto *b = args.var_args[1];

            auto *entry = llvm.basic_block("entry", f);
            llvm.insert_at(entry);

            auto *isgt = llvm.ugt(a, llvm.lit_word(30));
            auto *then_lbl = llvm.basic_block("then_lbl", f);
            auto *else_lbl = llvm.basic_block("else_lbl", f);

            llvm.condbr(isgt, then_lbl, else_lbl);

            llvm.insert_at(then_lbl);
            llvm.ret(b);

            llvm.insert_at(else_lbl);

            auto *nbytes = llvm.sub(llvm.lit_word(31), a);
            auto *nbits = llvm.mul(nbytes, llvm.lit_word(8));
            llvm.ret(llvm.sar(llvm.shl(b, nbits), nbits));
            return f;
        }

        Function *init_instr(Instruction const &instr)
        {
            auto const op = instr.opcode();
            switch (op) {
            case SStore:
                return ffi_runtime(instr, sstore<traits>);

            case Create:
                return ffi_runtime(instr, create<traits>);

            case Create2:
                return ffi_runtime(instr, create2<traits>);

            case DelegateCall:
                return ffi_runtime(instr, delegatecall<traits>);

            case StaticCall:
                return ffi_runtime(instr, staticcall<traits>);

            case Call:
                return ffi_runtime(instr, call<traits>);

            case CallCode:
                return ffi_runtime(instr, callcode<traits>);

            case SelfBalance:
                return ffi_runtime(instr, selfbalance);

            case Balance:
                return ffi_runtime(instr, balance<traits>);

            case ExtCodeHash:
                return ffi_runtime(instr, extcodehash<traits>);

            case ExtCodeSize:
                return ffi_runtime(instr, extcodesize<traits>);

            case SLoad:
                return ffi_runtime(instr, sload<traits>);

            case BlobHash:
                return ffi_runtime(instr, blobhash);

            case BlockHash:
                return ffi_runtime(instr, blockhash);

            case CallDataLoad:
                return ffi_runtime(instr, calldataload);

            case MLoad:
                return ffi_runtime(instr, mload);

            case TLoad:
                return ffi_runtime(instr, tload);

            case Exp:
                return ffi_runtime(instr, exp<traits>);

            case Sha3:
                return ffi_runtime(instr, sha3);

            case MStore:
                return ffi_runtime(instr, mstore);

            case MStore8:
                return ffi_runtime(instr, mstore8);

            case TStore:
                return ffi_runtime(instr, tstore);

            case CallDataCopy:
                return ffi_runtime(instr, calldatacopy);

            case CodeCopy:
                return ffi_runtime(instr, codecopy);

            case MCopy:
                return ffi_runtime(instr, mcopy);

            case ReturnDataCopy:
                return ffi_runtime(instr, returndatacopy);

            case ExtCodeCopy:
                return ffi_runtime(instr, extcodecopy<traits>);

            case Log:
                switch (instr.index()) {
                case 0:
                    return ffi_runtime(instr, log0);

                case 1:
                    return ffi_runtime(instr, log1);

                case 2:
                    return ffi_runtime(instr, log2);

                case 3:
                    return ffi_runtime(instr, log3);

                default:
                    MONAD_VM_ASSERT(instr.index() == 4);
                    return ffi_runtime(instr, log4);
                }

            case Address:
                return load_context_addr(instr, context_offset_env_recipient);

            case Coinbase:
                return load_context_addr(
                    instr, context_offset_env_tx_context_block_coinbase);

            case Caller:
                return load_context_addr(instr, context_offset_env_sender);

            case Origin:
                return load_context_addr(
                    instr, context_offset_env_tx_context_origin);

            case GasLimit:
                return load_context_uint64(
                    instr, context_offset_env_tx_context_block_gas_limit);

            case Number:
                return load_context_uint64(
                    instr, context_offset_env_tx_context_block_number);

            case MSize:
                return load_context_uint32(instr, context_offset_memory_size);

            case CodeSize:
                return load_context_uint32(instr, context_offset_env_code_size);

            case CallDataSize:
                return load_context_uint32(
                    instr, context_offset_env_input_data_size);

            case Timestamp:
                return load_context_uint64(
                    instr, context_offset_env_tx_context_block_timestamp);

            case ReturnDataSize:
                return load_context_uint64(
                    instr, context_offset_env_return_data_size);

            case ChainId:
                return load_context_be(
                    instr, context_offset_env_tx_context_chain_id);

            case Difficulty:
                return load_context_be(
                    instr, context_offset_env_tx_context_block_prev_randao);

            case BlobBaseFee:
                return load_context_be(
                    instr, context_offset_env_tx_context_blob_base_fee);

            case BaseFee:
                return load_context_be(
                    instr, context_offset_env_tx_context_block_base_fee);

            case GasPrice:
                return load_context_be(
                    instr, context_offset_env_tx_context_tx_gas_price);

            case CallValue:
                return load_context_be(instr, context_offset_env_value);

            case Gas:
                return nullptr; // Gas opcode is inlined

            case Byte:
                return llvm_byte(instr);

            case SignExtend:
                return llvm_signextend(instr);

            case SDiv:
                return llvm_sdivop(instr);

            case Div:
                return llvm_divop(instr, &LLVMState::udiv);

            case Mod:
                return llvm_divop(instr, &LLVMState::urem);

            case SMod:
                return llvm_divop(instr, &LLVMState::srem);

            case Shl:
                return llvm_shiftop(instr, &LLVMState::shl);

            case Shr:
                return llvm_shiftop(instr, &LLVMState::shr);

            case Sar:
                return llvm_sar(instr);

            case IsZero:
                return llvm_unop(instr, &LLVMState::is_zero);

            case AddMod:
                return llvm_modop(instr, &LLVMState::addmod);

            case MulMod:
                return llvm_modop(instr, &LLVMState::mulmod);

            case Lt:
                return llvm_binop(instr, &LLVMState::ult);

            case Gt:
                return llvm_binop(instr, &LLVMState::ugt);

            case SLt:
                return llvm_binop(instr, &LLVMState::slt);

            case SGt:
                return llvm_binop(instr, &LLVMState::sgt);

            case Eq:
                return llvm_binop(instr, &LLVMState::equ);

            case XOr:
                return llvm_binop(instr, &LLVMState::xor_);

            case Or:
                return llvm_binop(instr, &LLVMState::or_);

            case And:
                return llvm_binop(instr, &LLVMState::and_);

            case Not:
                return llvm_unop(instr, &LLVMState::not_);

            case Sub:
                return llvm_binop(instr, &LLVMState::sub);

            case Mul:
                return llvm_binop(instr, &LLVMState::mul);

            default:
                MONAD_VM_ASSERT(op == Add);
                return llvm_binop(instr, &LLVMState::add);
            }
        };
    };
};
