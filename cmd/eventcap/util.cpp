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

#include "util.hpp"
#include "err_cxx.hpp"
#include "eventcap.hpp"
#include "eventsource.hpp"
#include "options.hpp"

#include <iterator>

#include <stdio.h>
#include <sysexits.h>
#include <unistd.h>

#include <category/core/event/evcap_file.h>
#include <category/core/event/evcap_reader.h>
#include <category/core/event/evcap_writer.h>
#include <category/core/event/event_ring.h>
#include <category/core/event/event_ring_util.h>

void copy_all_schema_sections(
    monad_evcap_writer *evcap_writer, EventCaptureFile const *capture_file,
    monad_event_content_type skip)
{
    monad_evcap_section_desc const *sd = nullptr;
    monad_evcap_reader *const evcap_reader = capture_file->get_reader();
    while (monad_evcap_reader_next_section(
        evcap_reader, MONAD_EVCAP_SECTION_SCHEMA, &sd)) {
        if (sd->schema.content_type == skip) {
            continue;
        }
        if (monad_evcap_writer_add_schema_section(
                evcap_writer,
                sd->schema.content_type,
                sd->schema.schema_hash) != 0) {
            errx_f(
                EX_SOFTWARE,
                "evcap writer library error -- {}",
                monad_evcap_writer_get_last_error());
        }
    }
}

bool event_ring_is_abandoned(int ring_fd)
{
    pid_t writer_pids[32];
    size_t n_pids = std::size(writer_pids);
    if (monad_event_ring_find_writer_pids(ring_fd, writer_pids, &n_pids) != 0) {
        errx_f(
            EX_SOFTWARE,
            "event library error -- {}",
            monad_event_ring_get_last_error());
    }
    return n_pids == 0;
}

bool use_tty_control_codes(TextUIMode tui_mode, OutputFile const *output)
{
    switch (tui_mode) {
    case TextUIMode::Always:
        return true;
    case TextUIMode::Never:
        return false;
    case TextUIMode::Auto:
        break; // Handled in the body of the function
    }
    if (int const rc = isatty(fileno(output->file)); rc == -1) {
        err_f(
            EX_OSERR,
            "isatty on output `{}` failed",
            output->canonical_path.string());
    }
    else {
        return static_cast<bool>(rc);
    }
}
