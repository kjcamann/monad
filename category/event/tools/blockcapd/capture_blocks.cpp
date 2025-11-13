#include <chrono>
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
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/un.h>
#include <syscall.h>
#include <sysexits.h>
#include <unistd.h>

#include <category/core/assert.h>
#include <category/core/cleanup.h>
#include <category/core/event/evcap_file.h>
#include <category/core/event/evcap_writer.h>
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
    monad_bcap_archive *block_archive;
    monad_bcap_builder *block_builder;
    monad_bcap_finalize_tracker *finalize_tracker;
    uint64_t *last_finalized;
    ZSTD_CCtx *event_zstd_cctx;
    ZSTD_CCtx *seqno_index_zstd_cctx;
};

struct PrometheusRelay
{
    int sock_fd;
    sockaddr_un sock_addr;
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
    BlockCapOptions const *options, monad_bcap_archive *block_archive,
    uint64_t *last_finalized, ArchiverState *state)
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
    state->last_finalized = last_finalized;
    state->event_zstd_cctx = create_zstd_cctx(options->event_zstd_level);
    state->seqno_index_zstd_cctx =
        create_zstd_cctx(options->seqno_index_zstd_level);
}

// When any kind of error occurs, we drop the in-progress (partially assembled)
// proposed block in the block builder, and we drop all pending unfinalized
// proposed blocks from the finalization tracker.
//
// The latter happens because `monad_bcap_finalize_tracker_update` expects to
// finalize blocks in strict order. The lowest numbered block must be finalized
// first, or ENOTRECOVERABLE is returned (which is fatal).
//
// If the event flow is interrupted in any way, there is no way to guarantee
// we'll see a finalization event for any pending proposal, so we drop them all.
// This ensures there we will be no "zombie" unfinalized proposals that can
// block the finalization of later proposals. If a finalization ends up occuring
// for a pending proposal that we threw away, this is unfortunate but not fatal.
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

void check_prometheus_relay_connection(PrometheusRelay *prom_relay)
{
    static std::chrono::system_clock::time_point s_last_error_log{};

    if (prom_relay->sock_addr.sun_family != AF_UNIX) {
        return; // Not enabled
    }
    if (prom_relay->sock_fd != -1) {
        // Already connected, make sure it's still alive
        struct pollfd pfd = {
            .fd = prom_relay->sock_fd,
            .events = POLLOUT,
            .revents = 0,
        };
        if (poll(&pfd, 1, 0) != 1) {
            BCD_ERR(
                "poll of relay socket `{}` failed: {} [{}]",
                prom_relay->sock_addr.sun_path,
                strerror(errno),
                errno);
            (void)close(prom_relay->sock_fd = -1);
            return;
        }
        if ((pfd.revents & (POLLERR | POLLHUP)) == 0) {
            // Connection is alive
            return;
        }
        int sock_error;
        socklen_t len = sizeof sock_error;
        std::string error_description;
        if (getsockopt(
                prom_relay->sock_fd, SOL_SOCKET, SO_ERROR, &sock_error, &len) !=
                0 &&
            sock_error != 0) {
            error_description =
                std::format("{} [{}]", strerror(sock_error), sock_error);
        }
        else {
            error_description = std::format(
                "relay server disconnected or unknown error, poll mask 0x{:x}",
                pfd.revents);
        }
        BCD_ERR(
            "Prometheus relay socket `{}` not available: {}",
            prom_relay->sock_addr.sun_path,
            error_description);
        (void)close(prom_relay->sock_fd);
    }
    prom_relay->sock_fd = socket(PF_UNIX, SOCK_SEQPACKET, 0);
    if (prom_relay->sock_fd == -1) {
        BCD_ERR(
            "socket(2) failed for relay connection: {} [{}]",
            strerror(errno),
            errno);
        return;
    }
    if (connect(
            prom_relay->sock_fd,
            (sockaddr const *)&prom_relay->sock_addr,
            sizeof prom_relay->sock_addr) == -1) {
        // Make sure we don't log the same error message too often
        if (auto const now = std::chrono::system_clock::now();
            now - s_last_error_log > std::chrono::seconds(10)) {
            BCD_ERR(
                "connect(2) to Prometheus relay socket `{}` failed: {} [{}]",
                prom_relay->sock_addr.sun_path,
                strerror(errno),
                errno);
            s_last_error_log = now;
        }
        (void)close(prom_relay->sock_fd);
        prom_relay->sock_fd = -1;
    }
}

void wait_for_execution_daemon(
    BlockCapOptions const *options, ExecutionDaemon *daemon,
    PrometheusRelay const *relay, BlockCapMetrics const *metrics)
{
    monad_event_ring_unmap(&daemon->event_ring);
    (void)close(daemon->pidfd);
    daemon->pid = -1;

    timespec const timeout = {
        .tv_sec = options->connect_timeout.value_or(0), .tv_nsec = 0};

    while (g_exit_signaled == 0) {
        int ring_fd;
        int rc;

        BCD_INFO_NS("waiting for {}", options->exec_ring_path);
        rc = monad_event_ring_wait_for_excl_writer(
            options->exec_ring_path.c_str(),
            options->connect_timeout ? &timeout : nullptr,
            nullptr,
            O_RDONLY,
            &ring_fd,
            &daemon->pid);
        if (rc == EINTR || rc == ESRCH) {
            // TODO: deduct time spent from timeout
            if (g_scrape_signaled) {
                scrape_metrics(relay->sock_fd, metrics);
            }
            continue;
        }
        if (rc == ETIMEDOUT) {
            break;
        }
        daemon->pidfd = (int)syscall(SYS_pidfd_open, daemon->pid, 0);
        if (daemon->pidfd == -1) {
            BCD_WARN(
                "pidfd_open failed for pid {} owning `{}`: {} [{}]",
                daemon->pid,
                options->exec_ring_path,
                strerror(errno),
                errno);
            // TODO: deduct time spent from timeout
            (void)close(ring_fd);
            continue;
        }
        if (rc == 0) {
            rc = monad_event_ring_mmap(
                &daemon->event_ring,
                PROT_READ,
                MAP_POPULATE,
                ring_fd,
                0,
                options->exec_ring_path.c_str());
        }
        (void)close(ring_fd);
        if (rc != 0) {
            errx(
                EX_SOFTWARE,
                "event library error -- %s",
                monad_event_ring_get_last_error());
        }
        return;
    }
    if (daemon->event_ring.header == nullptr) {
        errx(
            EX_UNAVAILABLE,
            "could not detect monad-execution daemon after %ld seconds",
            timeout.tv_sec);
    }
}

enum class ResetReason
{
    DaemonConnect,
    Gap
};

void reset_iterator(
    ResetReason const reason, monad_event_ring_iter *const iter,
    uint64_t const *const last_finalized)
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
        // Otherwise we'll start after the last finalized block, unless this
        // is because of a gap, or it is not available, or the rewind fails.
        // In that case, we'll start at whatever BLOCK_START is most recent
        (void)monad_event_ring_iter_reset(iter);
        bool has_rewound = false;
        if (reason == ResetReason::DaemonConnect && *last_finalized != 0) {
            has_rewound = monad_exec_iter_rewind_for_simple_replay(
                iter, *last_finalized, nullptr, nullptr);
            if (!has_rewound) {
                BCD_WARN(
                    "unable to rewind to last finalized block {}",
                    *last_finalized);
            }
        }
        if (!has_rewound) {
            (void)monad_exec_iter_consensus_prev(
                iter, MONAD_EXEC_BLOCK_START, nullptr, nullptr);
        }
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
    monad_exec_block_tag const &finalized_tag, ArchiverState *const state,
    BlockCapMetrics *metrics)
{
    monad_bcap_proposal *proposal;
    monad_bcap_proposal_list abandon_chain;

    BC_CHECK(monad_bcap_finalize_tracker_update(
        state->finalize_tracker, &finalized_tag, &proposal, &abandon_chain));
    if (proposal == nullptr) {
        // Finalization for a block we never saw; this is near the
        // beginning of the sequence when we reset
        BCD_WARN(
            "encountered finalization of unseen proposed block {}",
            describe(finalized_tag));
        ++metrics->unknown_finalizations_total;
        return ProcessEventResult::UnknownFinalization;
    }
    if (*state->last_finalized != 0 &&
        finalized_tag.block_number != *state->last_finalized + 1) {
        uint64_t const missing_count =
            finalized_tag.block_number - *state->last_finalized - 1;
        BCD_WARN(
            "finalization of proposed block {} suggests {} missing blocks "
            "[last finalized = {}]",
            describe(finalized_tag),
            missing_count,
            *state->last_finalized);
        ++metrics->missing_ranges_total;
        metrics->missing_range_size_total += missing_count;
        metrics->last_missing_range_start_block_number =
            *state->last_finalized + 1;
        metrics->last_missing_range_size = missing_count;
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
    BC_CHECK(monad_bcap_archive_open_block_writer(
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
    monad_evcap_section_desc const *event_sd;
    monad_evcap_section_desc const *seqno_index_sd;
    BC_CHECK(monad_bcap_write_proposal_evcap_ext(
        evcap_writer,
        proposal,
        exec_schema_sd,
        const_cast<monad_evcap_section_desc **>(&event_sd),
        const_cast<monad_evcap_section_desc **>(&seqno_index_sd),
        state->event_zstd_cctx,
        state->seqno_index_zstd_cctx));

    // Link the anonymous file into the filesystem at the name
    // computed earlier
    int const commit_error = monad_bcap_archive_commit_block(
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
        ++metrics->duplicate_proposals_total;
        monad_evcap_writer_destroy(evcap_writer);
        return ProcessEventResult::Duplicate;
    }
    BC_CHECK(commit_error);
    __atomic_store_n(
        state->last_finalized, finalized_tag.block_number, __ATOMIC_RELEASE);

    ++metrics->num_blocks_written;
    metrics->last_block_number = finalized_tag.block_number;
    metrics->captured_bytes_uncompressed +=
        event_sd->content_length + seqno_index_sd->content_length;
    metrics->captured_bytes_compressed +=
        event_sd->file_length + seqno_index_sd->file_length;

    BCD_INFO_NS("wrote finalized block {}", describe(proposal->block_tag));
    monad_bcap_proposal_free(proposal);
    monad_evcap_writer_destroy(evcap_writer);
    while ((proposal = TAILQ_FIRST(&abandon_chain)) != nullptr) {
        TAILQ_REMOVE(&abandon_chain, proposal, entry);
        BCD_INFO_NS(
            "dropped abandoned proposal {}", describe(proposal->block_tag));
        monad_bcap_proposal_free(proposal);
        ++metrics->abandoned_proposals_total;
    }

    return ProcessEventResult::NewFinalizedBlock;
}

ProcessEventResult process_event(
    monad_event_ring const *event_ring, monad_event_descriptor const *event,
    ArchiverState *state, BlockCapMetrics *metrics)
{
    monad_bcap_append_result_t append_result;
    monad_bcap_proposal *proposal;

    void const *const payload =
        monad_event_ring_payload_peek(event_ring, event);
    BC_CHECK(monad_bcap_builder_append_event(
        state->block_builder, event, payload, &append_result, &proposal));
    ++metrics->events_total;

    if (event->event_type == MONAD_EXEC_BLOCK_FINALIZED) {
        monad_exec_block_tag const block_tag =
            *reinterpret_cast<monad_exec_block_tag const *>(payload);
        if (!monad_event_ring_payload_check(event_ring, event)) {
            return ProcessEventResult::PayloadExpired;
        }
        return finalize_block(block_tag, state, metrics);
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
        ++metrics->aborted_proposals_total;
        return ProcessEventResult::DroppedBlock;
    }

    if (append_result == MONAD_BCAP_PROPOSAL_FINISHED) {
        MONAD_ASSERT(proposal != nullptr);
        monad_bcap_finalize_tracker_add_proposal(
            state->finalize_tracker, proposal);
        ++metrics->executed_proposals_total;
    }

    return ProcessEventResult::EventAppended;
}

void drain_event_ring(
    ExecutionDaemon const *exec_daemon, monad_event_ring_iter *iter,
    ArchiverState *state, PrometheusRelay *prom_relay, BlockCapMetrics *metrics)
{
    monad_event_descriptor event;
    unsigned long not_ready_count = 0;
    bool process_exited = false;

    while (g_exit_signaled == 0 && !process_exited) {
        switch (monad_event_ring_iter_try_next(iter, &event)) {
        case MONAD_EVENT_RING_NOT_READY:
            if (g_scrape_signaled) {
                scrape_metrics(prom_relay->sock_fd, metrics);
            }
            if ((++not_ready_count & NotReadyCheckMask) == 0) {
                process_exited = exec_daemon->has_exited();
                if (process_exited) {
                    reset_archiver_state(state);
                    BCD_WARN(
                        "monad-execution daemon {} has exited",
                        exec_daemon->pid);
                }
                check_prometheus_relay_connection(prom_relay);
            }
            continue; // Nothing produced yet

        case MONAD_EVENT_RING_GAP:
            BCD_ERR(
                "event gap from {} -> {}, resetting iterator",
                iter->cur_seqno,
                monad_event_ring_get_last_written_seqno(
                    iter->event_ring, false));
            reset_archiver_state(state);
            reset_iterator(ResetReason::Gap, iter, state->last_finalized);
            ++metrics->gaps_total;
            break;

        case MONAD_EVENT_RING_SUCCESS:
            switch (process_event(iter->event_ring, &event, state, metrics)) {
            case ProcessEventResult::PayloadExpired:
                BCD_ERR(
                    "payload expiration at {}; resetting iterator",
                    iter->cur_seqno);
                reset_archiver_state(state);
                reset_iterator(ResetReason::Gap, iter, state->last_finalized);
                ++metrics->payload_expirations_total;
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
    BlockCapOptions const *options, monad_bcap_archive *block_archive,
    uint64_t *last_finalized)
{
    ExecutionDaemon exec_daemon{};
    ArchiverState state{};
    PrometheusRelay prom_relay{};
    BlockCapMetrics metrics{};

    exec_daemon.pidfd = -1;
    init_archiver_state(options, block_archive, last_finalized, &state);

    prom_relay.sock_fd = -1;
    if (!options->prom_relay_path.empty()) {
        prom_relay.sock_addr.sun_family = AF_UNIX;
        constexpr size_t MAX_ADDR_LEN = sizeof prom_relay.sock_addr.sun_path;
        if (strlcpy(
                prom_relay.sock_addr.sun_path,
                options->prom_relay_path.c_str(),
                MAX_ADDR_LEN) >= MAX_ADDR_LEN) {
            errno = ENAMETOOLONG;
            err(EX_CONFIG,
                "Prometheus relay socket path %s is too long",
                options->prom_relay_path.c_str());
        }
    }
    check_prometheus_relay_connection(&prom_relay);

    while (g_exit_signaled == 0) {
        wait_for_execution_daemon(options, &exec_daemon, &prom_relay, &metrics);
        ++metrics.sessions_total;
        metrics.active_session_pid = static_cast<uint64_t>(exec_daemon.pid);

        monad_event_ring_iter iter;
        if (monad_event_ring_init_iterator(&exec_daemon.event_ring, &iter) !=
            0) {
            errx(
                EX_SOFTWARE,
                "event ring library error -- %s",
                monad_event_ring_get_last_error());
        }
        reset_iterator(ResetReason::DaemonConnect, &iter, last_finalized);

        if (metrics.sessions_total == 1) {
            // For the first session only, allow --finalized-block and --seqno
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
        drain_event_ring(&exec_daemon, &iter, &state, &prom_relay, &metrics);
        metrics.active_session_pid = 0;
    }
    cleanup_archiver_state(&state);
}
