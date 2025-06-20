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
 * of multiple segments, all of which are the same size. As segments fill up,
 * they are returned to the caller to be incrementally flushed, typically to a
 * disk file. Large contiguous memcpy operations, including those that span
 * multiple segments, will succeed (the memcpy will return multiple full
 * segments) and when flushed, will appear contiguous on disk.
 *
 * The vbuf is used when we want the speed of a single memcpy in almost all
 * cases, but we either (1) don't know the total size of the output buffer a
 * prioi or (2) we don't know if the commit to disk will happen or not.
 *
 * There are three important objects in the virtual buffer design:
 *
 *   1. `struct monad_vbuf_segment` represents a single segment of the virtual
 *      buffer. These are returned to the caller when a memcpy operation fills
 *      up one or more segments, or when the vbuf writer is explicitly flushed
 *
 *   2. `struct monad_vbuf_chain` is a linked list (actually a <sys/queue.h>
 *      TAILQ) of vbuf segments. The caller passes a pointer to a chain into
 *      the memcpy operation, so that any segments that become full as a
 *      result of the operation are linked onto the chain
 *
 *   3. `struct monad_vbuf_writer` manages the state of the virtual buffer
 *
 * See the UTF-8 diagrams in virtual_buf.c for an illustrated example of how
 * the vbuf works
 */

#include <stddef.h>
#include <stdint.h>

#include <sys/queue.h>

typedef struct ZSTD_CCtx_s ZSTD_CCtx;

#ifdef __cplusplus
extern "C"
{
#endif

/*
 * vbuf segments and chains
 */

// clang-format off

/// Segment of a virtual buffer; this segment holds the byte range
/// `[virtual_offset, virtual_offset + size)` in the anonymous memory region
/// referred to by `fd`
struct monad_vbuf_segment
{
    int fd;                     ///< memfd_create(2) fd for segment
    size_t base_virtual_offset; ///< Virtual offset where segment starts
    size_t size;                ///< Number of bytes written to segment
    size_t capacity;            ///< Total size of segment (i.e., segment_size)
    TAILQ_ENTRY(monad_vbuf_segment) entry; ///< Linkage for vbuf chain
};

// clang-format on

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

// clang-format off

struct monad_vbuf_writer_options
{
    uint8_t segment_shift; ///< vbuf segments will have size 1 << segment_shift
    unsigned memfd_flags;  ///< All vbuf segments memfd_create'd w/ these flags
    ZSTD_CCtx *zstd_cctx;  ///< vbuf streaming compressed w/ this zstd context
};

// clang-format on

/// Shift value passed to monad_vbuf_writer_create when we want to let the zstd
/// streaming API decide the input and output chunk sizes
constexpr uint8_t MONAD_VBUF_ZSTD_SHIFT = 0;

/// Create a vbuf writer with the given options; if the zstd_cctx field in the
/// options structure is not nullptr, it becomes owned by (and will be freed
/// by) the vbuf writer
int monad_vbuf_writer_create(
    struct monad_vbuf_writer **, struct monad_vbuf_writer_options const *);

struct monad_vbuf_writer_options const *
monad_vbuf_writer_get_create_options(struct monad_vbuf_writer const *);

/// Return the current virtual offset in the buffer
size_t monad_vbuf_writer_get_offset(struct monad_vbuf_writer const *);

/// Skip `n` bytes in the virtual buffer (they will be filled with zeros),
/// plus any additional bytes that need to be skipped to ensure the virtual
/// offset has the requested alignment. All segments that fill up as a result
/// of this operation are added to the `full_segments` chain. If the operation
/// fails, the skip is rolled back entirely
int monad_vbuf_writer_skip_bytes(
    struct monad_vbuf_writer *, size_t n, size_t align,
    struct monad_vbuf_chain *full_segments);

/// memcpy `n` bytes from the `src` buffer, after first ensuring that the
/// virtual offset has the requested alignment. All segments that fill up as a
/// result of this operation are added to the `full_segments` chain. If the
/// operation fails, the memcpy is rolled back entirely, but the initial
/// alignment operation may or may not be rolled back (a failed memcpy may
/// still produce new segments, from the alignment)
int monad_vbuf_writer_memcpy(
    struct monad_vbuf_writer *, void const *src, size_t n, size_t align,
    struct monad_vbuf_chain *full_segments);

/// For regular vbuf writers, this appends the partially-filled active vbuf
/// segment to a chain; for zstd-compressed vbufs, this ends the zstd frame
/// and flushes as many vbuf segments as needed to complete the frame
int monad_vbuf_writer_flush(
    struct monad_vbuf_writer *, struct monad_vbuf_chain *);

/// Has the effect of calling monad_vbuf_writer_flush and also resets the
/// virtual offset to zero; if zstd compression is enabled, also resets the
/// compression session
int monad_vbuf_writer_reset(
    struct monad_vbuf_writer *, struct monad_vbuf_chain *,
    size_t *prev_virtual_offset);

/// Destroy a vbuf writer created by an earlier call to monad_vbuf_writer_create
int monad_vbuf_writer_destroy(
    struct monad_vbuf_writer *, struct monad_vbuf_chain *);

/// Return a description of the last vbuf error that occurred on this thread
char const *monad_vbuf_writer_get_last_error();

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
    c->vbuf_length += s->size;
}

[[gnu::always_inline]] static inline struct monad_vbuf_segment *
monad_vbuf_chain_remove(
    struct monad_vbuf_chain *c, struct monad_vbuf_segment *s)
{
    TAILQ_REMOVE(&c->segments, s, entry);
    --c->segment_count;
    c->vbuf_length -= s->size;
    return s;
}

[[gnu::always_inline]] inline struct monad_vbuf_chain *monad_vbuf_chain_concat(
    struct monad_vbuf_chain *lhs, struct monad_vbuf_chain *rhs)
{
    TAILQ_CONCAT(&lhs->segments, &rhs->segments, entry);
    lhs->segment_count += rhs->segment_count;
    lhs->vbuf_length += rhs->vbuf_length;
    rhs->segment_count = 0;
    rhs->vbuf_length = 0;
    return lhs;
}

#ifdef __cplusplus
} // extern "C"
#endif
