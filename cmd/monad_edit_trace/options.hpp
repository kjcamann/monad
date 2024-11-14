#pragma once

#include <cstdint>
#include <filesystem>
#include <set>
#include <string>
#include <unordered_set>
#include <vector>

struct ExtractBlockOptions
{
    std::filesystem::path input_file;
    std::filesystem::path output_file;
    std::set<uint64_t> blocks;
    bool combined_block_file;
    bool always_try_prune;
};

struct MergeOptions
{
    std::filesystem::path output_file;
};

struct ShowOptions
{
    bool all;
    bool file_header;
    bool section_tables;
    bool thread_list;
    bool event_counts;
    bool dump_events;
    bool no_track_scopes;
    unsigned domain_list;
    std::unordered_set<std::string> domain_filter;
    std::unordered_set<std::string> thread_filter;
    std::set<uint64_t> blocks;
};

struct StripOptions
{
    std::filesystem::path input_file;
    std::filesystem::path output_file;
    std::set<unsigned> section_numbers;
};

struct Options
{
    std::vector<std::filesystem::path> input_files;
    ExtractBlockOptions extract_block_options;
    MergeOptions merge_options;
    ShowOptions show_options;
    StripOptions strip_options;
};
