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

#include "err_cxx.hpp"
#include "eventcap.hpp"
#include "eventsource.hpp"
#include "options.hpp"
#include "util.hpp"

#include <bit>
#include <cstddef>
#include <cstdint>
#include <iterator>
#include <optional>
#include <print>
#include <span>

#include <alloca.h>
#include <sysexits.h>

#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/types.h>

#include <category/core/event/event_iterator.h>
#include <category/core/event/event_ring.h>
#include <category/core/hex.hpp>

namespace
{

struct EventSourceState
{
    EventSource::Iterator iter;
    size_t not_ready_count;
    EVP_MD_CTX *hash_ctx;
    EventSource *event_source;
    bool finished;
    Command *command;
};

} // End of anonymous namespace

void digest_thread_main(std::span<Command *const> commands)
{
    EventSourceState *state_bufs = static_cast<EventSourceState *>(
        alloca(sizeof(EventSourceState) * size(commands)));
    std::span<EventSourceState> states = std::span{state_bufs, size(commands)};
    EVP_MD const *const sha256_md = EVP_sha256();

    for (size_t i = 0; Command *const c : commands) {
        auto const *const options = c->get_common_options();
        EventSourceState &state = *new (&states[i++]) EventSourceState{};
        state.hash_ctx = EVP_MD_CTX_create();
        if (EVP_DigestInit_ex(state.hash_ctx, sha256_md, nullptr) != 1) {
            ERR_print_errors_fp(stderr);
            errx_f(EX_SOFTWARE, "EVP_DigestInit_ex failed");
        }
        state.event_source = c->event_sources[0];
        state.command = c;
        state.event_source->init_iterator(
            &state.iter, options->start_seqno, options->end_seqno);
    }

    size_t active_state_count = size(states);
    while (g_should_exit == 0 && active_state_count > 0) {
        for (EventSourceState &state : states) {
            if (state.finished) {
                continue;
            }

            using enum EventIteratorResult;
            monad_event_content_type content_type;
            monad_event_descriptor event;
            std::byte const *payload;
            switch (state.iter.next(&content_type, &event, &payload)) {
            case AfterStart:
                errx_f(
                    EX_SOFTWARE,
                    "event seqno {} occurs after start seqno {};"
                    "events missing",
                    event.seqno,
                    *state.iter.start_seqno);

            case AfterEnd:
                errx_f(
                    EX_SOFTWARE,
                    "event seqno {} occurs after end seqno {}; "
                    "did a gap occur?",
                    event.seqno,
                    *state.iter.end_seqno);

            case Finished:
                --active_state_count;
                state.finished = true;
                continue;

            case NotReady:
                if ((++state.not_ready_count & NotReadyCheckMask) == 0) {
                    if (state.event_source->is_finalized()) {
                        --active_state_count;
                        state.finished = true;
                    }
                }
                [[fallthrough]];
            case Skipped:
                continue;

            case Gap:
                errx_f(
                    EX_SOFTWARE,
                    "ERROR: event gap from {} -> {}, digest can't be computed",
                    state.iter.get_last_read_seqno(),
                    state.iter.get_last_written_seqno());

            case Success:
                state.not_ready_count = 0;
                break; // Handled in the main loop body
            }
            auto const *const options =
                state.command->get_options<DigestCommandOptions>();
            // Compute the digest of the payload first; we might set the
            // payload_buf_offset to zero to better compare against snapshots,
            // which might have a different buffer layout order, and clearing
            // it early will break monad_event_payload_check
            EVP_DigestUpdate(state.hash_ctx, payload, event.payload_size);
            if (!state.iter.check_payload(&event)) {
                errx_f(
                    EX_SOFTWARE, "payload for event {} expired", event.seqno);
            }
            if (options->erase_timestamps) {
                event.record_epoch_nanos = 0;
            }
            if (options->erase_payload_offset) {
                event.payload_buf_offset = 0;
            }
            uint8_t resid_mask = options->erase_content_ext_mask;
            while (resid_mask != 0) {
                auto const to_clear = std::countr_zero(resid_mask);
                event.content_ext[to_clear] = 0;
                resid_mask &= ~static_cast<uint8_t>(1U << to_clear);
            }
            EVP_DigestUpdate(state.hash_ctx, &event, sizeof event);
        }
    }

    for (EventSourceState &state : states) {
        using monad::as_hex;
        uint8_t event_digest[32];
        OutputFile const *o = state.command->output;

        EVP_DigestFinal_ex(state.hash_ctx, event_digest, nullptr);
        EVP_MD_CTX_destroy(state.hash_ctx);
        std::println(
            o->file,
            "{} message digest: {:}",
            state.event_source->describe(),
            as_hex(std::as_bytes(std::span{event_digest})));

        state.~EventSourceState();
    }
}
