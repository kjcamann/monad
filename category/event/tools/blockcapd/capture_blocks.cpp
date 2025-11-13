#include <cstddef>
#include <cstdint>
#include <format>
#include <optional>
#include <string>

#include <err.h>
#include <errno.h>
#include <fcntl.h>
#include <poll.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <syscall.h>
#include <sysexits.h>
#include <unistd.h>

#include <category/core/assert.h>
#include <category/core/cleanup.h>
#include <category/core/event/event_def.h>
#include <category/core/event/event_ring.h>
#include <category/core/event/event_ring_iter.h>
#include <category/core/event/event_ring_util.h>
#include <category/core/mem/virtual_buf.h>
#include <category/execution/ethereum/event/blockcap.h>
#include <category/execution/ethereum/event/exec_event_ctypes.h>
#include <category/execution/ethereum/event/exec_iter_help.h>

#include <zstd.h>

#include "blockcapd.hpp"

namespace
{

struct ExecutionDaemon
{
    monad_event_ring event_ring;
    pid_t pid;
    int pidfd;

    bool has_exited() const
    {
        struct pollfd pfd = {.fd = pidfd, .events = POLLIN, .revents = 0};
        return poll(&pfd, 1, 0) == -1 || (pfd.revents & POLLIN) == POLLIN;
    }
};

struct ArchiverState
{
    monad_vbuf_mmap_allocator *vbuf_mmap_allocator;
    monad_bcap_block_archive *block_archive;
    monad_bcap_builder *block_builder;
    monad_bcap_finalize_tracker *finalize_tracker;
    ZSTD_CCtx *event_zstd_cctx;
    ZSTD_CCtx *seqno_index_zstd_cctx;
};

inline void BC_CHECK(int rc)
{
    if (rc != 0) [[unlikely]] {
        errx(
            EX_SOFTWARE,
            "bcap library error -- %s",
            monad_bcap_get_last_error());
    }
}

ZSTD_CCtx *create_zstd_cctx(std::optional<uint8_t> const &compression_level)
{
    if (!compression_level) {
        return nullptr;
    }
    ZSTD_CCtx *const cctx = ZSTD_createCCtx();
    if (cctx == nullptr) {
        errx(EX_SOFTWARE, "ZSTD_createCCtx failed");
    }
    size_t const r = ZSTD_CCtx_setParameter(
        cctx, ZSTD_c_compressionLevel, *compression_level);
    if (ZSTD_isError(r)) {
        ZSTD_freeCCtx(cctx);
        errx(
            EX_SOFTWARE,
            "ZSTD_CCtx_setParameter failed for level %hhu: %s",
            *compression_level,
            ZSTD_getErrorName(r));
    }
    return cctx;
}

void init_archiver_state(
    BlockCapOptions const *options, monad_bcap_block_archive *block_archive,
    ArchiverState *state)
{
    if (monad_vbuf_mmap_allocator_create(
            &state->vbuf_mmap_allocator,
            *options->vbuf_segment_shift,
            MAP_PRIVATE) != 0) {
        errx(
            EX_SOFTWARE,
            "vbuf library error -- %s",
            monad_vbuf_writer_get_last_error());
    }
    state->block_archive = block_archive;
    BC_CHECK(monad_bcap_builder_create(
        &state->block_builder,
        (monad_vbuf_segment_allocator *)state->vbuf_mmap_allocator,
        (monad_vbuf_segment_allocator *)state->vbuf_mmap_allocator));
    BC_CHECK(monad_bcap_finalize_tracker_create(&state->finalize_tracker));
    state->event_zstd_cctx = create_zstd_cctx(options->event_zstd_level);
    state->seqno_index_zstd_cctx =
        create_zstd_cctx(options->seqno_index_zstd_level);
}

void reset_archiver_state(ArchiverState *state)
{
    monad_bcap_builder_reset(state->block_builder);
    monad_bcap_finalize_tracker_reset(state->finalize_tracker);
}

void cleanup_archiver_state(ArchiverState *state)
{
    monad_bcap_builder_destroy(state->block_builder);
    monad_bcap_finalize_tracker_destroy(state->finalize_tracker);
    monad_vbuf_mmap_allocator_destroy(state->vbuf_mmap_allocator);
    ZSTD_freeCCtx(state->event_zstd_cctx);
    ZSTD_freeCCtx(state->seqno_index_zstd_cctx);
}

std::string describe(monad_exec_block_tag const &bt)
{
    std::string s = std::format("{} 0x", bt.block_number);
    for (uint8_t const &b : bt.id) {
        s += std::format("{:02x}", b);
    }
    return s;
}

bool try_connect_execution_daemon(
    BlockCapOptions const *options, ExecutionDaemon *daemon)
{
    struct stat ring_stat;
    int ring_fd [[gnu::cleanup(cleanup_close)]] =
        open(options->exec_ring_path.c_str(), O_RDONLY);
    if (ring_fd == -1) {
        BCD_WARN(
            "open of event ring file `{}` failed: {} [{}]",
            options->exec_ring_path,
            strerror(errno),
            errno);
        return false;
    }
    size_t n_pids = 1;
    if (monad_event_ring_find_writer_pids(ring_fd, &daemon->pid, &n_pids) !=
        0) {
        errx(
            EX_SOFTWARE,
            "event ring library error -- %s",
            monad_event_ring_get_last_error());
    }
    if (options->force_live) {
        daemon->pid = getpid();
    }
    else {
        switch (n_pids) {
        case 0:
            BCD_WARN(
                "no writer pids for `{}` detected; zombie event ring file?",
                options->exec_ring_path);
            return false;

        case 1:
            break; // Handled in the rest of the function

        default:
            BCD_WARN(
                "found {} writers of `{}` but expected one; ignoring",
                n_pids,
                options->exec_ring_path);
            return false;
        }
    }
    daemon->pidfd = (int)syscall(SYS_pidfd_open, daemon->pid, 0);
    if (daemon->pidfd == -1) {
        BCD_WARN(
            "pidfd_open failed for pid {} owning `{}`: {} [{}]",
            daemon->pid,
            options->exec_ring_path,
            strerror(errno),
            errno);
        return false;
    }
    if (fstat(ring_fd, &ring_stat) == -1) {
        BCD_WARN(
            "fstat of file `{}` failed: {} [{}]",
            options->exec_ring_path,
            strerror(errno),
            errno);
        return false;
    }
    if (ring_stat.st_size == 0) {
        BCD_WARN(
            "`{}` has size zero; maybe initiailizing?",
            options->exec_ring_path);
        return false;
    }
    if (monad_event_ring_mmap(
            &daemon->event_ring,
            PROT_READ,
            MAP_POPULATE,
            ring_fd,
            0,
            options->exec_ring_path.c_str()) != 0) {
        errx(
            EX_SOFTWARE,
            "event ring library error -- %s",
            monad_event_ring_get_last_error());
    }
    return true;
}

void wait_for_execution_daemon(
    BlockCapOptions const *options, ExecutionDaemon *daemon)
{
    unsigned seconds_elapsed = 0;

    monad_event_ring_unmap(&daemon->event_ring);
    (void)close(daemon->pidfd);
    daemon->pid = -1;

    while (g_exit_signaled == 0 &&
           (!options->connect_timeout ||
            seconds_elapsed <= *options->connect_timeout) &&
           !try_connect_execution_daemon(options, daemon)) {
        sleep(1);
        ++seconds_elapsed;
    }
    if (daemon->event_ring.header == nullptr) {
        errx(
            EX_UNAVAILABLE,
            "could not detect monad-execution daemon after %u seconds",
            seconds_elapsed);
    }
}

enum class ResetReason
{
    DaemonConnect,
    Gap
};

void reset_iterator(monad_event_ring_iter *const iter, ResetReason reason)
{
    size_t const descriptor_capacity =
        iter->event_ring->header->size.descriptor_capacity;
    uint64_t const last_written_seqno =
        monad_event_ring_get_last_written_seqno(iter->event_ring, false);
    if (reason == ResetReason::DaemonConnect &&
        last_written_seqno < descriptor_capacity / 2) {
        // We're resetting the iterator because we created a new connection to
        // the daemon, and it has written less than half of the total available
        // descriptor capacity. In this case, we assume we're seeing a newly
        // created daemon after a restart, with none of its blocks captured
        // yet. We rewind to the beginning of the event ring.
        monad_event_ring_iter_set_seqno(iter, 1);
    }
    else {
        // Otherwise we just start at whatever BLOCK_START is most recent
        (void)monad_event_ring_iter_reset(iter);
        (void)monad_exec_iter_consensus_prev(
            iter, MONAD_EXEC_BLOCK_START, nullptr, nullptr);
    }
}

enum class ProcessEventResult
{
    DroppedBlock,
    Duplicate,
    EventAppended,
    NewFinalizedBlock,
    OutsideBlockScope,
    PayloadExpired,
    UnknownFinalization,
};

ProcessEventResult finalize_block(
    monad_exec_block_tag const *const finalized_tag, ArchiverState *const state)
{
    monad_bcap_proposal *proposal;
    monad_bcap_proposal_list abandon_chain;

    BC_CHECK(monad_bcap_finalize_tracker_update(
        state->finalize_tracker, finalized_tag, &proposal, &abandon_chain));
    if (proposal == nullptr) {
        // Finalization for a block we never saw; this is near the
        // beginning of the sequence when we reset
        return ProcessEventResult::UnknownFinalization;
    }

    // TODO(ken): can move writer infrastructure to a different thread,
    //  do more expensive compression levels there
    char path_buf[32];
    monad_evcap_writer *evcap_writer;
    monad_evcap_section_desc const *exec_schema_sd;

    // Open a writer to an anonymous capture file; this computes the name
    // the file will eventually have (into path_buf), but won't link it
    // into the filesystem yet, to prevent partial writes from being seen
    uint64_t const block_number = proposal->block_tag.block_number;
    BC_CHECK(monad_bcap_block_archive_open_block_writer(
        state->block_archive,
        block_number,
        DirCreateMode,
        FileCreateMode,
        path_buf,
        sizeof path_buf,
        nullptr,
        &evcap_writer,
        &exec_schema_sd));

    // Write the block capture proposal into the file
    BC_CHECK(monad_bcap_write_proposal_evcap_ext(
        evcap_writer,
        proposal,
        exec_schema_sd,
        nullptr,
        nullptr,
        state->event_zstd_cctx,
        state->seqno_index_zstd_cctx));

    // Link the anonymous file into the filesystem at the name
    // computed earlier; also destroys the writer
    int const commit_error = monad_bcap_block_archive_close_block_writer(
        state->block_archive, block_number, evcap_writer, path_buf);
    if (commit_error == EEXIST) {
        // Linking the anonymous file into the filesystem is not allowed to
        // overwrite a file that is already there, and this error is not
        // fatal, but we log it
        BCD_ERR(
            "could not write finalized block {} to file `{}`: {} [{}]",
            describe(proposal->block_tag),
            path_buf,
            strerror(EEXIST),
            EEXIST);
        monad_bcap_proposal_free(proposal);
        return ProcessEventResult::Duplicate;
    }
    BC_CHECK(commit_error);

    BCD_INFO_NS("wrote finalized block {}", describe(proposal->block_tag));
    monad_bcap_proposal_free(proposal);
    while ((proposal = TAILQ_FIRST(&abandon_chain)) != nullptr) {
        TAILQ_REMOVE(&abandon_chain, proposal, entry);
        BCD_INFO_NS(
            "dropped abandoned proposal {}", describe(proposal->block_tag));
        monad_bcap_proposal_free(proposal);
    }

    return ProcessEventResult::NewFinalizedBlock;
}

ProcessEventResult process_event(
    monad_event_ring const *event_ring, monad_event_descriptor const *event,
    ArchiverState *state)
{
    monad_bcap_append_result_t append_result;
    monad_bcap_proposal *proposal;

    void const *const payload =
        monad_event_ring_payload_peek(event_ring, event);
    BC_CHECK(monad_bcap_builder_append_event(
        state->block_builder, event, payload, &append_result, &proposal));

    if (event->event_type == MONAD_EXEC_BLOCK_FINALIZED) {
        auto const block_tag =
            *reinterpret_cast<monad_exec_block_tag const *>(payload);
        if (!monad_event_ring_payload_check(event_ring, event)) {
            return ProcessEventResult::PayloadExpired;
        }
        return finalize_block(&block_tag, state);
    }

    if (append_result == MONAD_BCAP_OUTSIDE_BLOCK_SCOPE) {
        // XXX: not sure if this is interesting or not
        return ProcessEventResult::OutsideBlockScope;
    }

    if (!monad_event_ring_payload_check(event_ring, event)) {
        return ProcessEventResult::PayloadExpired;
    }

    if (append_result == MONAD_BCAP_PROPOSAL_ABORTED) {
        monad_exec_block_tag const aborted_block_tag = proposal->block_tag;
        monad_bcap_proposal_free(proposal);
        if (event->event_type == MONAD_EXEC_BLOCK_REJECT) {
            uint32_t const reject_code =
                *reinterpret_cast<uint32_t const *>(payload);
            BCD_WARN(
                "proposal {} rejected with transaction error code {}",
                describe(aborted_block_tag),
                reject_code);
        }
        else {
            MONAD_ASSERT_PRINTF(
                event->event_type == MONAD_EXEC_EVM_ERROR,
                "proposal aborted on unexpected event type %s [%hu]",
                g_monad_exec_event_metadata[event->event_type].c_name,
                event->event_type);
            auto const *const error_info =
                reinterpret_cast<monad_exec_evm_error const *>(payload);
            BCD_WARN(
                "EVM error {}:{} encountered during execution of proposal {}",
                error_info->domain_id,
                error_info->status_code,
                describe(aborted_block_tag));
        }
        return ProcessEventResult::DroppedBlock;
    }

    if (append_result == MONAD_BCAP_PROPOSAL_FINISHED) {
        MONAD_ASSERT(proposal != nullptr);
        monad_bcap_finalize_tracker_add_proposal(
            state->finalize_tracker, proposal);
    }

    return ProcessEventResult::EventAppended;
}

void drain_event_ring(
    ExecutionDaemon const *exec_daemon, monad_event_ring_iter *iter,
    ArchiverState *state)
{
    monad_event_descriptor event;
    unsigned long not_ready_count = 0;
    bool process_exited = false;

    while (g_exit_signaled == 0 && !process_exited) {
        switch (monad_event_ring_iter_try_next(iter, &event)) {
        case MONAD_EVENT_RING_NOT_READY:
            if ((++not_ready_count & NotReadyCheckMask) == 0) {
                process_exited = exec_daemon->has_exited();
                if (process_exited) {
                    reset_archiver_state(state);
                    BCD_WARN(
                        "monad-execution daemon {} has exited",
                        exec_daemon->pid);
                }
            }
            continue; // Nothing produced yet

        case MONAD_EVENT_RING_GAP:
            BCD_ERR(
                "event gap from {} -> {}, resetting iterator",
                iter->cur_seqno,
                monad_event_ring_get_last_written_seqno(
                    iter->event_ring, false));
            reset_archiver_state(state);
            reset_iterator(iter, ResetReason::Gap);
            break;

        case MONAD_EVENT_RING_SUCCESS:
            switch (process_event(iter->event_ring, &event, state)) {
            case ProcessEventResult::PayloadExpired:
                BCD_ERR(
                    "payload expiration at {}; resetting iterator",
                    iter->cur_seqno);
                reset_archiver_state(state);
                reset_iterator(iter, ResetReason::Gap);
                break;

            default:
                break; // No special processing in these cases
            }
            break;
        }
        not_ready_count = 0;
    }
}

} // End of anonymous namespace

void capture_blocks(
    BlockCapOptions const *options, monad_bcap_block_archive *block_archive)
{
    size_t session_count = 0;
    ExecutionDaemon exec_daemon{};
    ArchiverState state{};

    exec_daemon.pidfd = -1;
    init_archiver_state(options, block_archive, &state);
    while (g_exit_signaled == 0) {
        wait_for_execution_daemon(options, &exec_daemon);
        ++session_count;

        monad_event_ring_iter iter;
        if (monad_event_ring_init_iterator(&exec_daemon.event_ring, &iter) !=
            0) {
            errx(
                EX_SOFTWARE,
                "event ring library error -- %s",
                monad_event_ring_get_last_error());
        }
        reset_iterator(&iter, ResetReason::DaemonConnect);

        if (session_count == 1) {
            // For the first session only, allow --finalized_block and --seqno
            if (options->seek_finalized_block) {
                if (!monad_exec_iter_rewind_for_simple_replay(
                        &iter,
                        *options->seek_finalized_block,
                        nullptr,
                        nullptr)) {
                    BCD_ERR(
                        "seek to finalized block {} failed",
                        *options->seek_finalized_block);
                }
            }
            if (options->seek_seqno) {
                monad_event_ring_iter_set_seqno(&iter, *options->seek_seqno);
            }
        }

        BCD_INFO_NS(
            "connected to monad-execution daemon {}, iterator is set to "
            "sequence number: {}",
            exec_daemon.pid,
            iter.cur_seqno);
        drain_event_ring(&exec_daemon, &iter, &state);
    }
    cleanup_archiver_state(&state);
}
