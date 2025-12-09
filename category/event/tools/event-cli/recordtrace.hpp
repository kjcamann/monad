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

#include <cstdint>
#include <flat_map>
#include <latch>
#include <string>
#include <thread>

#include <pthread.h>
#include <sys/queue.h>

#include <category/core/event/event_def.h>
#include <category/core/mem/virtual_buf.h>
#include <category/execution/ethereum/event/exec_event_ctypes.h>

struct monad_bcap_proposal;
struct monad_vbuf_segment_allocator;

struct EventIterator;
struct EventSourceSpec;
struct RecordTraceCommandOptions;
struct TracedProposal;

// Holds in the in-progress or completed vbuf chains for the event sections of
// a trace, plus some metadata (uncompressed size, start sequence number, etc.)
struct BlockTrace
{
    TracedProposal *traced_proposal;
    monad_event_content_type_t trace_type;
    bool finished;
    monad_vbuf_chain event_vbufs;
    monad_vbuf_chain seqno_vbufs;
    uint64_t start_seqno;
    uint64_t event_count;
    uint64_t initial_seqno;
};

struct TracedProposal
{
    using trace_map_t = std::flat_map<monad_event_content_type, BlockTrace *>;

    uint64_t hold_count;
    monad_bcap_proposal *proposal;
    trace_map_t trace_map;
    TAILQ_ENTRY(TracedProposal) entry;
};

struct RecordTraceContext
{
    EventIterator const *exec_iterator;
    int output_fd;
    std::string output_spec;
    RecordTraceCommandOptions const *options;
};

struct RecordTraceState
{
    alignas(64) pthread_spinlock_t pending_proposal_lock;
    TAILQ_HEAD(, TracedProposal) pending_proposal_queue;
    alignas(64) pthread_spinlock_t sync_proposal_lock;
    TAILQ_HEAD(, TracedProposal) sync_proposal_queue;
    std::latch *start_latch;

    bool release_hold(TracedProposal *);
};

void recordtrace_drain(
    std::stop_token, EventSourceSpec const *, monad_vbuf_segment_allocator *,
    RecordTraceContext const *, RecordTraceState *);

void recordtrace_sync(
    std::stop_token, RecordTraceContext const *, RecordTraceState *);
