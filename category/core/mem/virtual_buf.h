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
 * This file defines the virtual buffer ("vbuf") utility. It is used as an
 * append-only buffer that holds the bytes of aligned memcpy operations,
 * typically for writing large files.
 *
 * The virtual buffer is conceptually a single large buffer, but it is composed
 * of multiple segments. As segments fill up, they are returned to the caller
 * to be incrementally flushed, typically to a disk file. Large contiguous
 * memcpy operations, including those that span multiple segments, will succeed
 * (the memcpy will return multiple full segments) and when flushed, will
 * appear contiguous on disk.
 *
 * The vbuf is used when we want the speed of a single memcpy in almost all
 * cases, but we either (1) don't know the total size of the output buffer a
 * prioi or (2) we don't know if the commit to disk will happen or not.
 *
 * There are four important objects in the virtual buffer design:
 *
 *   1. `struct monad_vbuf_segment` represents a single segment of the virtual
 *      buffer. These are returned to the caller when a memcpy operation fills
 *      up one or more segments, or when the vbuf writer is explicitly flushed
 *
 *   2. `struct monad_vbuf_chain` is a linked list (a <sys/queue.h> TAILQ) of
 *      vbuf segments. The caller passes a pointer to a chain into the memcpy
 *      operation, so that any segments that become full as a result of the
 *      operation are linked onto the chain
 *
 *   3. `struct monad_vbuf_writer` manages the state of the virtual buffer
 *
 *   4. `struct monad_vbuf_segment_allocator` knows how to allocate new vbuf
 *      segments
 *
 * See the UTF-8 diagrams in virtual_buf.c for an illustrated example of how
 * the vbuf works
 */

#include <stddef.h>
#include <stdint.h>
#include <string.h>

#include <sys/queue.h>

#ifdef __cplusplus
extern "C"
{
#endif

/*
 * vbuf segments and chains
 */

struct monad_vbuf_segment_allocator;

// clang-format off

/// Segment of a virtual buffer; this segment holds the byte range
/// `[virtual_offset, virtual_offset + written)`
struct monad_vbuf_segment
{
    size_t base_virtual_offset; ///< Virtual offset where segment starts
    size_t written;             ///< Number of bytes written to segment
    size_t capacity;            ///< Total size of segment
    struct monad_vbuf_segment_allocator
        *allocator;             ///< Allocator that created / will free us
    uint8_t *map_base;          ///< Where this segment is mapped, if it is
    uintptr_t alloc_private;    ///< Private data for allocator to use
    uintptr_t user;             ///< User defined data associated with vbuf
    TAILQ_ENTRY(monad_vbuf_segment) entry; ///< Linkage for vbuf chain
};

// clang-format on

struct monad_vbuf_segment_alloc_ops
{
    int (*allocate)(
        struct monad_vbuf_segment_allocator *, struct monad_vbuf_segment **);
    void (*free)(
        struct monad_vbuf_segment_allocator *, struct monad_vbuf_segment *);
    void (*activate)(
        struct monad_vbuf_segment_allocator *, struct monad_vbuf_segment *);
    void (*deactivate)(
        struct monad_vbuf_segment_allocator *, struct monad_vbuf_segment *);
};

struct monad_vbuf_segment_allocator
{
    struct monad_vbuf_segment_alloc_ops const *ops;
};

/// Release the memory for the vbuf segment; the user is responsible for
/// calling this on any vbuf segments returned by `monad_vbuf_writer_flush` or
/// in a vbuf chain returned by the write operations
void monad_vbuf_segment_free(struct monad_vbuf_segment *);

TAILQ_HEAD(monad_vbuf_segment_list, monad_vbuf_segment);

/// A vbuf chain is a linked list of vbuf segments whose virtual address ranges
/// are contiguous
struct monad_vbuf_chain
{
    struct monad_vbuf_segment_list segments; ///< vbuf segment TAILQ
    size_t segment_count; ///< Number of vbuf segments in TAILQ
    size_t vbuf_length; ///< Total number of bytes across all segments
};

/// Convenience function for freeing all segments in a chain
void monad_vbuf_chain_free(struct monad_vbuf_chain *);

/*
 * vbuf writer API
 */

struct monad_vbuf_writer;

/// Create a vbuf writer using the given vbuf segment allocator
int monad_vbuf_writer_create(
    struct monad_vbuf_writer **, struct monad_vbuf_segment_allocator *);

struct monad_vbuf_segment_allocator *
monad_vbuf_writer_get_allocator(struct monad_vbuf_writer *);

/// Return the current virtual offset in the buffer
static size_t monad_vbuf_writer_get_offset(struct monad_vbuf_writer const *);

/// Skip `n` bytes in the virtual buffer (they will be filled with zeros),
/// plus any additional bytes that need to be skipped to ensure the virtual
/// offset has the requested alignment. All segments that fill up as a result
/// of this operation are added to the `full_segments` chain. If the operation
/// fails, the skip is rolled back entirely
static int monad_vbuf_writer_skip_bytes(
    struct monad_vbuf_writer *, size_t n, size_t align,
    struct monad_vbuf_chain *full_segments);

/// memcpy `n` bytes from the `src` buffer, after first ensuring that the
/// virtual offset has the requested alignment. All segments that fill up as a
/// result of this operation are added to the `full_segments` chain. If the
/// operation fails, the memcpy is rolled back entirely, but the initial
/// alignment operation may or may not be rolled back (a failed memcpy may
/// still produce new segments, from the alignment)
static int monad_vbuf_writer_memcpy(
    struct monad_vbuf_writer *, void const *src, size_t n, size_t align,
    struct monad_vbuf_chain *full_segments);

/// Append the partially-filled active vbuf segment to a chain
void monad_vbuf_writer_flush(
    struct monad_vbuf_writer *, struct monad_vbuf_chain *);

/// Has the effect of calling monad_vbuf_writer_flush and also resets the
/// virtual offset to zero, returning the previous virtual offset
size_t
monad_vbuf_writer_reset(struct monad_vbuf_writer *, struct monad_vbuf_chain *);

/// Destroy a vbuf writer created by an earlier call to monad_vbuf_writer_create
void monad_vbuf_writer_destroy(
    struct monad_vbuf_writer *, struct monad_vbuf_chain *);

/// Return a description of the last vbuf error that occurred on this thread
char const *monad_vbuf_writer_get_last_error();

/*
 * vbuf segment inlines
 */

[[gnu::always_inline]] static inline size_t
monad_vbuf_segment_bytes_free(struct monad_vbuf_segment const *vs)
{
    return vs != nullptr ? (size_t)(vs->capacity - vs->written) : 0;
}

/*
 * vbuf chain inlines (TAILQ macros with aggregate length updates)
 */

[[gnu::always_inline]] static inline void
monad_vbuf_chain_init(struct monad_vbuf_chain *c)
{
    memset(c, 0, sizeof *c);
    TAILQ_INIT(&c->segments);
}

[[gnu::always_inline]] static inline void monad_vbuf_chain_insert_tail(
    struct monad_vbuf_chain *c, struct monad_vbuf_segment *s)
{
    TAILQ_INSERT_TAIL(&c->segments, s, entry);
    ++c->segment_count;
    c->vbuf_length += s->written;
}

[[gnu::always_inline]] static inline struct monad_vbuf_segment *
monad_vbuf_chain_remove(
    struct monad_vbuf_chain *c, struct monad_vbuf_segment *s)
{
    TAILQ_REMOVE(&c->segments, s, entry);
    --c->segment_count;
    c->vbuf_length -= s->written;
    return s;
}

[[gnu::always_inline]] static inline struct monad_vbuf_chain *
monad_vbuf_chain_concat(
    struct monad_vbuf_chain *lhs, struct monad_vbuf_chain *rhs)
{
    TAILQ_CONCAT(&lhs->segments, &rhs->segments, entry);
    lhs->segment_count += rhs->segment_count;
    lhs->vbuf_length += rhs->vbuf_length;
    rhs->segment_count = 0;
    rhs->vbuf_length = 0;
    return lhs;
}

/*
 * mmap-based vbuf segment allocator
 */

struct monad_vbuf_mmap_allocator;

int monad_vbuf_mmap_allocator_create(
    struct monad_vbuf_mmap_allocator **, uint8_t segment_shift, int mmap_flags);

void monad_vbuf_mmap_allocator_destroy(struct monad_vbuf_mmap_allocator *);

#ifdef __cplusplus
} // extern "C"
#endif

#define MONAD_VIRTUAL_BUF_INTERNAL
#include "virtual_buf_inline.h"
#undef MONAD_VIRTUAL_BUF_INTERNAL
