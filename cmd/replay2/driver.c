/**
 * @file
 *
 * This command-line utility is used to replay Ethereum history from an
 * on-disk collection of files containing historical Ethereum block data.
 */

#include <getopt.h>
#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <sysexits.h>

#include <monad-c/db/block_db.h>
#include <monad-c/ethereum/block.h>
#include <monad-c/execution/block_vm.h>
#include <monad-c/support/parse_util.h>
#include <monad-c/support/result.h>

#include "options.h"

enum long_only_options {
    LO_FIBER_STACK_SIZE = 256
};

constexpr unsigned DEFAULT_NUM_THREADS = 4;
constexpr unsigned DEFAULT_NUM_FIBERS = DEFAULT_NUM_THREADS * 256;

// clang-format: off
// @formatter:off
static struct option longopts[] = {
    {.name = "nthreads", .has_arg = 1, .flag = nullptr, .val = 't'},
    {.name = "nfibers", .has_arg = 1, .flag = nullptr, .val = 'f'},
    {.name = "genesis-file", .has_arg = 1, .flag = nullptr, .val = 'g'},
    {.name = "fiber-stack-size", .has_arg = 1, .flag = nullptr, .val = LO_FIBER_STACK_SIZE},
    {.name = "verbose", .has_arg = 0, .flag = nullptr, .val = 'v'},
    {.name = "help", .has_arg = 0, .flag = nullptr, .val = 'h'},
    {}
};
// @formatter:on
// clang-format: on

static void usage(FILE *out) {
    fprintf(out, "%s: [options] <block-db-dir> <num-blocks>\n", getprogname());
}

extern struct mdb_trie_db *init_trie_db(const struct program_options *opts);

extern int replay_ethereum(const struct program_options *opts,
                           struct mel_block_db *block_db,
                           struct mex_block_vm *block_vm,
                           mel_block_range blocks);

int parse_options(int argc, char **argv, struct program_options *opts) {
    int ch;
    monad_result mr;

    while ((ch = getopt_long(argc, argv, "t:f:v", longopts, nullptr)) != -1) {
        switch (ch) {
        case 'f':
            mr = mcl_parse_int(optarg, 1, MEX_BLOCK_VM_MAX_FIBERS);
            if (monad_is_error(mr))
                mcl_errc(EX_CONFIG, mr, "invalid number of block VM fibers: %s", optarg);
            opts->block_vm_options.num_exec_fibers = monad_value(mr);
            break;

        case 't':
            mr = mcl_parse_int(optarg, 1, MEX_BLOCK_VM_MAX_THREADS);
            if (monad_is_error(mr))
                mcl_errc(EX_CONFIG, mr, "invalid number of block VM threads: %s", optarg);
            opts->block_vm_options.num_exec_threads = monad_value(mr);
            break;

        case 'g':
            opts->genesis_file = optarg;
            break;

        case 'h':
            usage(stdout);
            exit(EX_OK);

        case 'v':
            ++opts->verbose;
            break;

        case LO_FIBER_STACK_SIZE:
            mr = mcl_parse_int(optarg, MEX_MIN_FIBER_STACK_SIZE, INTPTR_MAX);
            if (monad_is_error(mr))
                mcl_errc(EX_CONFIG, mr, "invalid fiber stack size: %s", optarg);
            opts->block_vm_options.fiber_stack_size = monad_value(mr);
            break;

        default:
            usage(stderr);
            exit(EX_USAGE);
        }
    }

    return optind;
}

int main(int argc, char **argv) {
    struct program_options opts = {};
    struct mel_block_db *block_db;
    struct mdb_trie_db *trie_db;
    struct mex_block_vm *block_vm;
    mel_block_num block_count;
    monad_result mr;

    /*
     * Set some reasonable defaults before parsing the command line
     */
    opts.block_vm_options.num_exec_threads = DEFAULT_NUM_THREADS;
    opts.block_vm_options.num_exec_fibers = DEFAULT_NUM_FIBERS;

    /*
     * Parse the command line arguments
     */

    const int next_opt = parse_options(argc, argv, &opts);
    argc -= next_opt;
    argv += next_opt;

    if (argc != 2) {
        usage(stderr);
        return EX_USAGE;
    }

    mr = mcl_parse_int(argv[1], 0, INTPTR_MAX);
    if (monad_is_error(mr))
        mcl_errc(EX_CONFIG, mr, "could not parse block count parameter `%s`", argv[1]);
    block_count = monad_value(mr);

    /*
     * Create the resources we need for replay:
     *
     *   1. A block_db instance, to replay RLP-encoded blocks
     *   2. A mdb_trie_db instance, to hold the Ethereum world state
     *   3. A mex_block_vm instance, to execute blocks
     */

    mr = mel_block_db_open(argv[0], &block_db);
    if (monad_is_error(mr))
        mcl_errc(EX_NOINPUT, mr, "could not load block_db at %s", argv[0]);

    trie_db = init_trie_db(&opts);
    mr = mex_block_vm_create(&opts.block_vm_options, trie_db, &block_vm);
    if (monad_is_error(mr)) {
        // mdb_trie_db_close(trie_db);
        mcl_errc(EX_SOFTWARE, mr, "could not create monad block vm");
    }

    const mel_block_range blocks = {
        .begin = 0,
        .end = block_count
    };

    return replay_ethereum(&opts, block_db, block_vm, blocks);
}
