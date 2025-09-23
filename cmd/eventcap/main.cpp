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
#include "file.hpp"
#include "init.hpp"
#include "options.hpp"

#include <array>
#include <csignal>
#include <cstdlib>
#include <format>
#include <memory>
#include <string>
#include <string_view>
#include <thread>
#include <unordered_map>
#include <utility>
#include <vector>

#include <CLI/CLI.hpp>
#include <pthread.h>
#include <sysexits.h>

#include <category/core/event/event_ring.h>

namespace
{

void should_exit_handler(int)
{
    g_should_exit = 1;
}

void add_common_options(
    CLI::App *subcommand, CommonCommandOptions &options,
    std::string_view subcommand_verb)
{
    CLI::Option *const source_opt =
        subcommand
            ->add_option(
                "-s,--source",
                options.event_source_spec,
                "Event ring, capture file, archive directory, or --input name")
            ->type_name("<event-source-spec>");
    if (!empty(options.event_source_spec)) {
        source_opt->default_val(options.event_source_spec)
            ->capture_default_str();
    }
    subcommand
        ->add_option(
            "-t,--thread",
            options.thread,
            std::format("Thread to run {} reader on", subcommand_verb))
        ->type_name("<thread-name>");
    subcommand
        ->add_option(
            "-o,--output",
            options.output_spec,
            std::format("Output file for {}", subcommand_verb))
        ->type_name("<output>");
}

void add_seqno_range_options(
    CLI::App *subcommand, CommonCommandOptions &options)
{
    subcommand
        ->add_option(
            "-b,--begin",
            options.begin_seqno,
            "Start iteration at this sequence number")
        ->type_name("<seqno>");
    subcommand
        ->add_option(
            "-e,--end",
            options.end_seqno,
            "Stop iteration at this sequence number")
        ->type_name("<seqno>");
}

CLI::Option *add_tui_mode_option(CLI::App *subcommand, TextUIMode &tui_mode)
{
    return subcommand
        ->add_option(
            "-m,--mode", tui_mode, "When to emit control characters for TUI")
        ->default_val(TextUIMode::Auto)
        ->capture_default_str()
        ->type_name("<tui-mode>")
        ->transform(CLI::CheckedTransformer(
            std::unordered_map<std::string, TextUIMode>{
                {"yes", TextUIMode::Always},
                {"no", TextUIMode::Never},
                {"auto", TextUIMode::Auto}},
            CLI::ignore_case));
}

} // end of anonymous namespace

std::sig_atomic_t g_should_exit;

int main(int argc, char **argv)
{
    BlockStatCommandOptions blockstat_command{};
    ExecStatCommandOptions execstat_command{};
    HeadStatCommandOptions headstat_command{};
    InfoCommandOptions info_command{};
    RecordCommandOptions record_command{};
    RecordExecCommandOptions recordexec_command{};

    DigestCommandOptions digest_var{};
    std::vector<DigestCommandOptions> digest_commands;

    DumpCommandOptions dump_var{};
    std::vector<DumpCommandOptions> dump_commands;

    SnapshotCommandOptions snap_var{};
    std::vector<SnapshotCommandOptions> snapshot_commands;

    std::vector<std::pair<std::string, std::string>> input_specs;
    std::vector<std::string> force_live_specs;

    CLI::App cli{"monad event capture tool"};
    cli.set_help_all_flag(
        "--help-all", "Show full help, including all subcommands");

    cli.add_option("-i,--input", input_specs, "Add named event source file")
        ->type_name("<input-name>:<file-or-ring-type>")
        ->type_size(-2)
        ->delimiter(':');

    // This option is used when the `event_ring_is_abandoned` logic doesn't
    // work, e.g., because the writer lives inside a docker container with a
    // different process namespace (i.e., we can't scrape procfs)
    cli.add_option(
           "-f,--force-live",
           force_live_specs,
           "Force event rings to appear alive")
        ->type_name("<ring-spec>")
        ->delimiter(',');

    cli.require_subcommand(1, 0);

    /*
     * blockstat command
     */

    CLI::App *const blockstat = cli.add_subcommand(
        "blockstat", "Compute aggregate statistics about blocks");
    add_common_options(
        blockstat, blockstat_command.common_options, "blockstat");
    add_seqno_range_options(blockstat, blockstat_command.common_options);
    blockstat->alias("bs");
    blockstat->add_flag(
        "--blocks",
        blockstat_command.display_blocks,
        "Display information about each block");
    CLI::Option *const outliers_opt =
        blockstat
            ->add_option(
                "--outliers",
                blockstat_command.outlier_size,
                "Size of outlier table to display at the end")
            ->check(CLI::Range(0, 1000));
    blockstat
        ->add_option(
            "--long-txn-time-min-txn",
            blockstat_command.long_txn_time_min_txn,
            "Minimum number of txns to be included as a long txn time outlier")
        ->needs(outliers_opt);
    blockstat
        ->add_option(
            "--gas-efficiency-min-txn",
            blockstat_command.gas_efficiency_min_txn,
            "Minimum number of txns to be included as a gas efficiency outlier")
        ->needs(outliers_opt);

    /*
     * digest subcommand
     */

    CLI::App *const digest = cli.add_subcommand(
        "digest", "Compute a cryptographic digest of events");
    add_common_options(digest, digest_var.common_options, "digest");
    add_seqno_range_options(digest, digest_var.common_options);
    digest->add_flag(
        "-T,--no-time",
        digest_var.erase_timestamps,
        "Set the epoch nanosecond timestamps to zero");
    digest->add_flag(
        "-P,--no-payload-offset",
        digest_var.erase_payload_offset,
        "Set the payload buffer offset to zero");
    digest
        ->add_option(
            "-C,--erase-content-ext-mask",
            digest_var.erase_content_ext_mask,
            "Erase user fields bitmask")
        ->type_name("<hex-mask>")
        ->check(CLI::Range(0, 15));
    digest->immediate_callback();
    digest->callback([&digest_var, &digest_commands] {
        digest_commands.push_back(digest_var);
        digest_var = {};
    });

    /*
     * dump subcommand
     */

    CLI::App *const dump = cli.add_subcommand("dump", "Dump events to a file");
    add_common_options(dump, dump_var.common_options, "dump");
    add_seqno_range_options(dump, dump_var.common_options);
    dump->add_flag("-H,--hex", dump_var.hexdump, "Hexdump event payloads");
    dump->add_flag("-d,--decode", dump_var.decode, "Decode event payloads");
    dump->add_flag(
        "-c,--content-ext",
        dump_var.always_dump_content_ext,
        "Force dump raw content extension values");
    dump->immediate_callback();
    dump->callback([&dump_var, &dump_commands] {
        dump_commands.push_back(dump_var);
        dump_var = {};
    });
    dump->footer(
        R"(The dump subcommand configures the options for formatting events to an output
file. This subcommand can be repeated, and each instance of it will configure a
a new dump operation. This can be used to dump multiple event rings into one
output stream.

If the ---thread or --output option is missing, their values are taken from the
last instance of the dump subcommand to specify them. This behavior (or
explicitly specifying the same thread name) can cause multiple dump operations
to occur on the same thread. In this case, the events are dumped in a
round-robin fashion.

If no subcommand instance specifies an --output option, stdout will be used.)");

    /*
     * execstat subcommand
     */

    CLI::App *const execstat =
        cli.add_subcommand("execstat", "Print execution statistics");
    execstat->alias("xs");
    execstat_command.common_options.event_source_spec =
        g_monad_event_content_type_names[MONAD_EVENT_CONTENT_TYPE_EXEC];
    add_common_options(execstat, execstat_command.common_options, "execstat");
    add_tui_mode_option(execstat, execstat_command.tui_mode);

    /*
     * headstat subcommand
     */

    CLI::App *const headstat =
        cli.add_subcommand("headstat", "Print live event ring file statistics");
    headstat->alias("hs");
    add_common_options(headstat, headstat_command.common_options, "headstat");
    headstat->remove_option(headstat->get_option("--source"));
    headstat->add_option("file", headstat_command.inputs, "Event ring fil")
        ->type_name("<event-ring-file>");
    headstat
        ->add_option(
            "-s,--stat",
            headstat_command.stats_interval,
            "Print statistics update after this period")
        ->type_name("<seconds>")
        ->check(CLI::Range(1, 600))
        ->required();
    headstat->get_option("--output")
        ->description("Output file, stdout if not specified");
    headstat->add_flag(
        "-Z,--no-zeros",
        headstat_command.discard_zero_samples,
        "Remove samples when no events are recorded");
    add_tui_mode_option(headstat, headstat_command.tui_mode);
    headstat->footer(
        R"(The event ring file header will be statistically sampled at the
specified rate, to produce a sample distribution for events/second and the
MiB/s payload consumption rate.)");

    /*
     * info subcommand
     */

    CLI::App *const info =
        cli.add_subcommand("info", "Print event source file information");
    add_common_options(info, info_command.common_options, "info");
    info->remove_option(info->get_option("--source"));
    info->remove_option(info->get_option("--thread"));
    info->add_option(
            "file",
            info_command.inputs,
            "Event ring file, type, evcap file, or archive directory")
        ->type_name("<event-source-file>");
    info->add_flag(
        "--full-section-table",
        info_command.full_evcap_section_table,
        "Print the full section table for evcap files");

    /*
     * record subcommand
     */

    CLI::App *const record = cli.add_subcommand("record", "Record events");
    add_common_options(record, record_command.common_options, "record");
    add_seqno_range_options(record, record_command.common_options);
    record
        ->add_option(
            "-i,--index-zstd-level",
            record_command.seqno_zstd_level,
            "zstd compression level for sequence number index")
        ->type_name("<zstd-level>")
        ->check(CLI::Range(0, 22));
    record
        ->add_option(
            "--vbuf-shift",
            record_command.vbuf_segment_shift,
            "vbuf segment size shift (power of 2)")
        ->default_val(26)
        ->capture_default_str()
        ->type_name("<vbuf-size-shift>")
        ->check(CLI::Range(12, 32));
    record->add_flag(
        "--no-seqno-index",
        record_command.no_seqno_index,
        "Disable the sequence number index");
    record->add_flag(
        "--backpressure",
        record_command.print_backpressure_stats,
        "Print backpressure statistics to stderr");

    /*
     * recordexec subcommand
     */

    CLI::App *const recordexec = cli.add_subcommand(
        "recordexec", "Record execution events with in a block-aware format");
    recordexec->alias("rex");
    recordexec_command.common_options.event_source_spec =
        g_monad_event_content_type_names[MONAD_EVENT_CONTENT_TYPE_EXEC];
    add_common_options(
        recordexec, recordexec_command.common_options, "recordexec");
    add_seqno_range_options(recordexec, recordexec_command.common_options);
    recordexec->get_option("--output")->required();
    recordexec
        ->add_option(
            "-f,--format",
            recordexec_command.block_format,
            "block recording format")
        ->required()
        ->default_val(BlockRecordFormat::Archive)
        ->type_name("<block-format>")
        ->transform(CLI::CheckedTransformer(
            std::unordered_map<std::string, BlockRecordFormat>{
                {"archive", BlockRecordFormat::Archive},
                {"packed", BlockRecordFormat::Packed}},
            CLI::ignore_case));
    recordexec
        ->add_option(
            "-z,--event-zstd-level",
            recordexec_command.event_zstd_level,
            "zstd compression level for finalized block sections")
        ->type_name("<zstd-level>")
        ->check(CLI::Range(0, 22));
    recordexec
        ->add_option(
            "-i,--index-zstd-level",
            recordexec_command.seqno_zstd_level,
            "zstd compression level for sequence number index")
        ->type_name("<zstd-level>")
        ->check(CLI::Range(0, 22));
    recordexec
        ->add_option(
            "--vbuf-shift",
            recordexec_command.vbuf_segment_shift,
            "vbuf segment size shift (power of 2)")
        ->default_val(26)
        ->capture_default_str()
        ->type_name("<vbuf-size-shift>")
        ->check(CLI::Range(12, 32));

    /*
     * snapshot subcommand
     */

    CLI::App *const snapshot =
        cli.add_subcommand("snapshot", "Create snapshot of event ring");
    snapshot->alias("snap");
    add_common_options(snapshot, snap_var.common_options, "snapshot");
    add_seqno_range_options(snapshot, snap_var.common_options);
    snapshot
        ->add_option(
            "--vbuf-shift",
            snap_var.vbuf_segment_shift,
            "Max payload shift (power of 2)")
        ->default_val(26)
        ->capture_default_str()
        ->type_name("<payload-size-shift>")
        ->check(CLI::Range(22, 32));
    snapshot->add_flag(
        "-k,--kill",
        snap_var.kill_at_end,
        "Set SIGINT signal to processes when terminated");
    snapshot->add_flag(
        "-T,--no-time",
        snap_var.erase_timestamps,
        "Set the epoch nanosecond timestamps to zero");
    snapshot->immediate_callback();
    snapshot->callback([&snap_var, &snapshot_commands] {
        snapshot_commands.push_back(snap_var);
        snap_var = {};
    });
    snapshot->footer(
        R"(The snapshot subcommand configures the options for writing events to a
snapshot event ring file. A snapshot event ring file is just a copy of a
regular event ring file, but is large enough to hold many events number without
wrapping around and over-writing earlier ones. This is used to create test
case data, or to re-create replay inputs. Typically the user runs zstd to
compress the output ring file, e.g.:

    eventcap snap -sexec -o- -e 100000 | zstd -19 > /tmp/snapshot.zst

If the user does not specify an ending sequence number describing when to
terminate the snapshot, it must be terminated manually by sending SIGINT to
eventcap, usually via the Ctrl^C control character entered into the controlling
terminal.

In that case, the typical way of running the above command would require
setsid(1) to be used for the later pipeline stage so it is not interrupted
along with the process group leader (which is eventcap), e.g.:

    eventcap snap -sexec -o- | sedsid zstd -19 > /tmp/snapshot.zst

The threading model behaves the same as the dump command.)");

    if (std::signal(SIGINT, should_exit_handler) == SIG_ERR) {
        err_f(EX_OSERR, "signal(3) failed");
    }

    try {
        cli.parse(argc, argv);
    }
    catch (CLI::CallForHelp const &e) {
        std::exit(cli.exit(e));
    }
    catch (CLI::ParseError const &e) {
        std::exit(cli.exit(e));
    }

    CommandBuilder builder{input_specs, force_live_specs};

    if (blockstat->count() > 0) {
        builder.build_blockstat_command(blockstat_command);
    }
    for (DigestCommandOptions const &c : digest_commands) {
        builder.build_digest_command(c);
    }
    for (DumpCommandOptions const &dco : dump_commands) {
        builder.build_dump_command(dco);
    }
    if (execstat->count() > 0) {
        builder.build_execstat_command(execstat_command);
    }
    if (headstat->count() > 0) {
        builder.build_headstat_command(headstat_command);
    }
    if (info->count() > 0) {
        builder.build_info_command(info_command);
    }
    if (record->count() > 0) {
        builder.build_record_command(record_command);
    }
    if (recordexec->count() > 0) {
        builder.build_recordexec_command(recordexec_command);
    }
    for (SnapshotCommandOptions const &c : snapshot_commands) {
        builder.build_snapshot_command(c);
    }

    Topology const topology = builder.finish();

    // Some commands are "one-offs" and don't need their own thread; these are
    // handled immediately on the main thread
    for (std::unique_ptr<Command> const &command : topology.commands) {
        if (command->has_type(Command::Type::Info)) {
            auto const *const opts = command->get_options<InfoCommandOptions>();
            print_event_source_headers(
                command->event_sources,
                opts->full_evcap_section_table,
                command->output->file);
        }
    }

    std::vector<std::thread> threads;
    threads.reserve(size(topology.thread_map));
    for (auto const &[thread_name, thread_input] : topology.thread_map) {
        threads.emplace_back(thread_input.thread_main, thread_input.commands);
        pthread_setname_np(threads.back().native_handle(), thread_name.c_str());
    }
    for (auto &thr : threads) {
        thr.join();
    }
    return 0;
}
