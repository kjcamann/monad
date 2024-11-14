#include "options.hpp"
#include <CLI/CLI.hpp>
#include <cstdlib>

extern void extract_block_main(Options const *);
extern void merge_main(Options const *);
extern void show_main(Options const *);
extern void strip_main(Options const *);

int main(int argc, char **argv)
{
    Options options{};
    CLI::App cli{"monad trace file editor"};

    CLI::App *show_command =
        cli.add_subcommand("show", "show contents of trace files");
    show_command
        ->add_option(
            "input_files", options.input_files, "set of input trace files")
        ->required();
    show_command->add_flag(
        "-a,--all",
        options.show_options.all,
        "show all information in a trace file");
    show_command->add_flag(
        "-f,--file-header",
        options.show_options.file_header,
        "show the file header");
    show_command->add_flag(
        "-S,--section-tables",
        options.show_options.section_tables,
        "show the contents of the section tables");
    show_command->add_flag(
        "-D,--domain-list",
        options.show_options.domain_list,
        "list trace domain metadata entries; repeat for to dump full metadata");
    show_command->add_flag(
        "-T,--thread-list",
        options.show_options.thread_list,
        "list the thread directory in this trace file");
    show_command->add_flag(
        "--event-count",
        options.show_options.event_counts,
        "show the total number of events across all trace pages");
    show_command->add_flag(
        "-e,--event",
        options.show_options.dump_events,
        "show the contents of the event tables");
    show_command->add_flag(
        "--no-track-scopes",
        options.show_options.no_track_scopes,
        "do not track scopes when printing the contents of merge pages");
    show_command->add_option(
        "-d,--domain",
        options.show_options.domain_filter,
        "set of domains to use as filters");
    show_command->add_option(
        "-t,--thread",
        options.show_options.thread_filter,
        "set of threads to use as filters");
    show_command->add_option(
        "-b,--block",
        options.show_options.blocks,
        "only show specific block pages; can be repeated");
    show_command->final_callback([&options]() { show_main(&options); });

    CLI::App *extract_block_command =
        cli.add_subcommand("extract-block", "extract blocks from time-merged files");
    extract_block_command
        ->add_option(
            "-b,--block", options.extract_block_options.blocks, "blocks to extract");
    extract_block_command->add_flag(
            "-B,--combined-block", options.extract_block_options.combined_block_file,
            "block file will contain the original merge section");
    extract_block_command->add_flag(
            "-p,--always-try-prune", options.extract_block_options.always_try_prune,
            "try pruning block pages instead of scanning merge pages, if both exist");
    extract_block_command
        ->add_option(
            "-o,--output", options.extract_block_options.output_file, "trace output file");
    extract_block_command
        ->add_option(
            "input_file", options.extract_block_options.input_file, "trace input file")->required();
    extract_block_command->final_callback([&options]() { extract_block_main(&options); });

    CLI::App *merge_command =
        cli.add_subcommand("merge", "create a time-merged trace file");
    merge_command
        ->add_option(
            "input_files", options.input_files, "set of input trace files")
        ->required();
    merge_command->add_option(
        "-m,--merge", options.merge_options.output_file, "merged trace file");
    merge_command->add_option(
        "-b,--block", options.extract_block_options.output_file, "block trace file");
    merge_command->add_flag(
        "-B,--combined-block", options.extract_block_options.combined_block_file,
        "block file will contain a merge section");
    merge_command->final_callback([&options]() { merge_main(&options); });

    CLI::App *strip_command =
        cli.add_subcommand("strip", "remove sections from a trace file");
    strip_command
        ->add_option(
            "-o,--output", options.strip_options.output_file, "output trace file");
    strip_command
        ->add_option(
            "input_file", options.strip_options.input_file, "trace input file")
        ->required();
    strip_command
        ->add_option(
            "sections", options.strip_options.section_numbers, "global section indices")
        ->required();
    strip_command->final_callback([&options] { strip_main(&options); });

    cli.require_subcommand(1, 1);
    try {
        cli.parse(argc, argv);
    }
    catch (CLI::CallForHelp const &e) {
        std::exit(cli.exit(e));
    }
    catch (CLI::ParseError const &e) {
        std::exit(cli.exit(e));
    }
    return 0;
}
