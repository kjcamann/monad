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

#include "command.hpp"
#include "err_cxx.hpp"
#include "evm_opcodes.hpp"
#include "file.hpp"
#include "iterator.hpp"

#include <cstddef>
#include <cstdint>
#include <cstdio>
#include <print>
#include <string>
#include <unordered_map>
#include <utility>

#include <sysexits.h>

#include <category/core/assert.h>
#include <category/core/event/event_def.h>
#include <category/execution/ethereum/event/blockcap.h>
#include <category/vm/event/evmt_event_ctypes.h>

namespace {

inline void BCAP_CHECK(int rc)
{
    if (rc != 0) [[unlikely]] {
        errx_f(
            EX_SOFTWARE,
            "bcap library error -- {}",
            monad_bcap_get_last_error());
    }
}

struct VmStats
{
    uint64_t total_instructions;
    uint64_t total_gas;
    uint64_t total_evm_gas;
    uint64_t total_evm_nanos;
    uint64_t instr_count[256];
    uint64_t instr_gas[256];
    uint64_t instr_nanos[256];
};

void visit_block(
    EventSourceSpec const &exec_source, EventSourceSpec const &evmt_source,
    VmStats *stats)
{
    EventIterator exec_iter;
    EventIterator evmt_iter;

    if (std::string const err = exec_source.init_iterator(&exec_iter); !err.empty()) {
        errx_f(EX_SOFTWARE, "exec iterator init failed: {}", err);
    }
    if (std::string const err = evmt_source.init_iterator(&evmt_iter); !err.empty()) {
        errx_f(EX_SOFTWARE, "evmt iterator init failed: {}", err);
    }

    std::unordered_map<uint64_t, monad_event_descriptor> prev_events;
    std::unordered_map<uint64_t, std::byte const *> prev_payloads;
    std::unordered_map<uint64_t, monad_event_descriptor> prev_events_evm;
    std::unordered_map<uint64_t, std::byte const *> prev_payloads_evm;
    monad_event_descriptor event;
    std::byte const *payload;

    while (true) {
        switch (evmt_iter.next(&event, &payload)) {
        case EventIteratorResult::End:
            return;

        case EventIteratorResult::Success:
            break;

        default:
            std::unreachable();
        }

        uint64_t const txn_flow_id =
            event.content_ext[MONAD_EVMT_EXT_TXN_SEQNO];
        auto const i_prev_event = prev_events.find(txn_flow_id);
        auto const i_prev_event_evm = prev_events.find(txn_flow_id);

        uint64_t const gas_used = i_prev_event != prev_events.end()
                ? i_prev_event->second.content_ext[MONAD_EVMT_EXT_GAS_LEFT] - event.content_ext[MONAD_EVMT_EXT_GAS_LEFT]
                : 0;

        uint64_t const nanos_elapsed_evm = i_prev_event_evm != prev_events_evm.end()
                ? event.record_epoch_nanos - i_prev_event_evm->second.record_epoch_nanos
                : 0;

        stats->total_gas += gas_used;
        if (i_prev_event != prev_events.end() &&
            i_prev_event->second.event_type == MONAD_EVMT_VM_DECODE) {
            auto const *const vm_decode =
                reinterpret_cast<monad_evmt_vm_decode const *>(prev_payloads[txn_flow_id]);
            ++stats->total_instructions;
            stats->total_evm_gas += gas_used;
            stats->total_evm_nanos += nanos_elapsed_evm;
            ++stats->instr_count[vm_decode->opcode];
            stats->instr_gas[vm_decode->opcode] += gas_used;
            stats->instr_nanos[vm_decode->opcode] += nanos_elapsed_evm;
        }
        if (event.event_type == MONAD_EVMT_VM_DECODE) {
            prev_events_evm[txn_flow_id] = event;
            prev_payloads_evm[txn_flow_id] = payload;
        }
        prev_events[txn_flow_id] = event;
        prev_payloads[txn_flow_id] = payload;
    }
}

void dump_vm_stats(VmStats const *vms, size_t block_count, std::FILE *out)
{
    std::println(out, "VM stats: {} instructions, {} gas in {} blocks",
                 vms->total_instructions, vms->total_evm_gas, block_count);
    std::println(out, "{:16} {:>10} {:>10} {:>6} {:>6} {:>7}", "NAME", "#OPS", "GAS", "%OPS", "%GAS", "NS/G");
    for (unsigned i = 0; i < std::size(EvmOpcodeInfoTable); ++i) {
        EvmOpcodeInfoEntry const &e = EvmOpcodeInfoTable[i];
        uint64_t const instr_count = vms->instr_count[i];
        uint64_t const instr_gas = vms->instr_gas[i];
        uint64_t const instr_nanos = vms->instr_nanos[i];
        if (!e.name) {
            continue;
        }
        std::println(out, "{:16} {:10} {:10} {:>6.2f} {:>6.2f} {:>7.1f}",
                     e.name, instr_count, instr_gas,
                     static_cast<double>(100 * instr_count) / static_cast<double>(vms->total_instructions),
                     static_cast<double>(100 * instr_gas) / static_cast<double>(vms->total_evm_gas),
                     static_cast<double>(instr_nanos) / static_cast<double>(instr_gas));
    }
}

} // end of anonymous namespace

void run_vmstat_command(Command const *command)
{
    MONAD_ASSERT(command->event_sources.size() == 1);

    EventSourceSpec const &event_source = command->event_sources.front();
    if (event_source.source_file->get_type() != EventSourceFile::Type::BlockArchiveDirectory) {
        // This command is not interactive
        errx_f(EX_USAGE, "vmstat currently requires a block archive directory");
    }

    auto *const block_archive =
        static_cast<BlockArchiveDirectory *>(event_source.source_file);

    uint64_t min_block;
    uint64_t max_block;

    BCAP_CHECK(monad_bcap_archive_find_minmax(
        block_archive->get_block_archive(), &min_block, &max_block));

    VmStats vmstats{};
    for (uint64_t b = min_block; b <= max_block; ++b) {
        BlockLabel const block_label = {
            .type = BlockLabel::Type::BlockNumber,
            .block_number = b,
        };

        EventSourceSpec const exec_source = {
            .source_file = block_archive,
            .source_query = {
                .section = CaptureSectionSpec{
                    .origin = CaptureSectionSpec::SeekOrigin::ContentType,
                    .content_type = MONAD_EVENT_CONTENT_TYPE_EXEC,
                },
                .block = block_label,
                .count = 1,
            }
        };

        EventSourceSpec const evmt_source = {
            .source_file = block_archive,
            .source_query = {
                .section = CaptureSectionSpec{
                    .origin = CaptureSectionSpec::SeekOrigin::ContentType,
                    .content_type = MONAD_EVENT_CONTENT_TYPE_EVMT,
                },
                .block = block_label,
                .count = 1,
            }
        };

        visit_block(exec_source, evmt_source, &vmstats);
    }

    dump_vm_stats(&vmstats, max_block - min_block + 1, command->output->file);
}
