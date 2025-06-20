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

/**
 * @file
 *
 * This file defines utilities used with the event capture ("evcap") system,
 * for writing block-oriented event streams. They are called the "block
 * capture" (blockcap) utilities.
 */

#include <stddef.h>
#include <stdint.h>

#include <sys/queue.h>

#include <category/core/mem/virtual_buf.h>
#include <category/execution/ethereum/event/exec_event_ctypes.h>

#ifdef __cplusplus
extern "C"
{
#endif

enum monad_exec_event_type : uint16_t;
enum monad_event_content_type : uint16_t;

enum monad_evcap_section_compression : uint8_t;

struct monad_evcap_writer;
struct monad_event_descriptor;
struct monad_vbuf_writer_options;

struct monad_blockcap_compression_info
{
    enum monad_evcap_section_compression compression;
    size_t uncompressed_length;
};

/// This object represents the "recorded form" of a proposed block's execution.
///
/// It contains:
///
///    - The block number and ID of the proposed block
///
///    - A vbuf chain holding all the events associated with the proposal's
///      execution, recorded in the event capture format
///
/// Note that this object, which records the events in a "proposed block",
/// has a different meaning than the word "proposal" in the consensus
/// algorithm. There, it refers to an attempt to vote on a particular block, in
/// a particular round; here it means "a block which is not yet finalized".
struct monad_blockcap_proposal
{
    struct monad_exec_block_tag block_tag;
    size_t event_count;
    uint64_t start_seqno;
    struct monad_vbuf_chain event_vbuf_chain;
    struct monad_vbuf_chain seqno_index_vbuf_chain;
    struct monad_blockcap_compression_info event_compression_info;
    struct monad_blockcap_compression_info seqno_index_compression_info;
    TAILQ_ENTRY(monad_blockcap_proposal) entry;
};

void monad_blockcap_proposal_free(struct monad_blockcap_proposal *);

TAILQ_HEAD(monad_blockcap_proposal_list, monad_blockcap_proposal);

/*
 * monad_blockcap_builder
 *
 * This API is used to build `struct monad_blockcap_proposal` objects, which
 * are vbuf chains holding all recorded events in the scope of a proposal
 */

enum monad_blockcap_append_result
{
    MONAD_BLOCKCAP_ERROR,
    MONAD_BLOCKCAP_OUTSIDE_BLOCK_SCOPE,
    MONAD_BLOCKCAP_PROPOSAL_APPENDED,
    MONAD_BLOCKCAP_PROPOSAL_FINISHED,
    MONAD_BLOCKCAP_PROPOSAL_ABORTED,
};

struct monad_blockcap_builder;

int monad_blockcap_builder_create(
    struct monad_blockcap_builder **,
    struct monad_vbuf_writer_options const *event_vbuf_options,
    struct monad_vbuf_writer_options const *seqno_index_vbuf_options);

void monad_blockcap_builder_destroy(struct monad_blockcap_builder *);

int monad_blockcap_builder_append_event(
    struct monad_blockcap_builder *, enum monad_event_content_type,
    struct monad_event_descriptor const *, void const *payload,
    enum monad_blockcap_append_result *, struct monad_blockcap_proposal **);

/*
 * monad_blockcap_finalize_tracker
 *
 * This API tracks when block proposals are finalized or abandoned, based on
 * consensus events
 */

struct monad_blockcap_finalize_tracker;

int monad_blockcap_finalize_tracker_create(
    struct monad_blockcap_finalize_tracker **);

void monad_blockcap_finalize_tracker_destroy(
    struct monad_blockcap_finalize_tracker *);

void monad_blockcap_finalize_tracker_add_proposal(
    struct monad_blockcap_finalize_tracker *, struct monad_blockcap_proposal *);

int monad_blockcap_finalize_tracker_on_finalize(
    struct monad_blockcap_finalize_tracker *,
    struct monad_exec_block_tag const *block_tag,
    struct monad_blockcap_proposal **finalized,
    struct monad_blockcap_proposal_list *abandoned);

/*
 * monad_blockcap_writer
 *
 * This API defines a layer on top of the "evcap" (event capture) file format,
 * adding in simple indexing and metadata about block boundaries for recording
 * execution rings
 *
 * A "block capture" file is just a regular event capture file with:
 *
 *   - Multiple EVENT_BUNDLE sections in it, with one section containing all
 *     the events for a particular finalized block
 *
 *   - A BLOCK_INDEX section that describes the finalized block number -> event
 *     section mapping. It is designed to be mmap'ed with MAP_SHARED and is
 *     updated atomically for readers that are "polling" the finalized block
 *     index during recovery
 */

struct monad_blockcap_writer;

int monad_blockcap_writer_create(struct monad_blockcap_writer **, int fd);

void monad_blockcap_writer_destroy(struct monad_blockcap_writer *);

struct monad_evcap_writer *
monad_blockcap_writer_get_evcap_writer(struct monad_blockcap_writer *);

int monad_blockcap_writer_add_block(
    struct monad_blockcap_writer *, struct monad_blockcap_proposal *);

/// Return a description of the last block capture API error that occurred on
/// this thread
char const *monad_blockcap_get_last_error();

struct monad_blockcap_index_entry
{
    alignas(16) uint64_t block_number;
    uint64_t section_desc_offset;
};

// This must be a power of 2, so that an integral number of them fit into an
// mmap'ed page
static_assert(sizeof(struct monad_blockcap_index_entry) == 16);

#ifdef __cplusplus
} // extern "C"
#endif
