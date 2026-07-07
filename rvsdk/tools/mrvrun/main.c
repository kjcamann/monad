#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <err.h>
#include <getopt.h>
#include <sysexits.h>

#include "exec.h"
#include "input.h"

extern char const *__progname;

extern void exec_sim_inputs(struct exec_env *, struct sim_input_list const *);

static void usage(FILE *const file)
{
    fprintf(file, "usage: %s [options] <input>...\n", __progname);
}

enum long_only_option
{
    LO_HOST_EXEC = 256,
};

// clang-format off
static struct option long_options[] = {
    {"help", no_argument, 0, 'h'},
    {"evm", required_argument, 0, 'e'},
    {"riscv", required_argument, 0, 'r'},
    {"state-db", required_argument, 0, 'd'},
    {"macho", required_argument, 0, 'm'},
    {"host-exec", no_argument, 0, LO_HOST_EXEC},
    {}
};

static void help()
{
  usage(stdout);
  fprintf(stdout, "\n"
"Monad RISC-V execution simulator\n"
"\n"
"Options:\n"
"  -h | --help                       print this message\n"
"  -e | --evm <evmc-load-spec>       load an EVM1 virtual machine library\n"
"  -r | --riscv <evmc-load-spec>     load an RV64 VM virtual machine library\n"
"  -d | --state-db <state-load-spec> load a prestate db provider\n"
"  -m | --macho <macho-override>     map contract address to Mach-O dylib\n"
"  --host-exec                       allow execution of native ELF files\n"
"\n"
"Positional arguments:\n"
"  <input> simulation input\n");
}

// clang-format on

struct driver_options
{
    struct exec_env_options ee_opts;
};

static int parse_options(
    int const argc, char **const argv, struct driver_options *const opts)
{
    int ch;

    while ((ch = getopt_long(argc, argv, "he:r:d:m:", long_options, nullptr)) !=
           -1) {
        switch (ch) {
        case 'h':
            help();
            exit(0);

        case 'e':
            opts->ee_opts.evm_config = optarg;
            break;

        case 'r':
            opts->ee_opts.rv64_config = optarg;
            break;

        case 'd':
            opts->ee_opts.db_config = optarg;
            break;

        case 'm':
            opts->ee_opts.macho_overrides = realloc(
                opts->ee_opts.macho_overrides,
                sizeof(char const *) *
                    (opts->ee_opts.macho_override_count + 1));
            if (opts->ee_opts.macho_overrides == nullptr) {
                err(EX_OSERR, "realloc(3) of macho_overrides failed");
            }
            opts->ee_opts
                .macho_overrides[opts->ee_opts.macho_override_count++] = optarg;
            break;

        case LO_HOST_EXEC:
            opts->ee_opts.elf_host_exec = true;
            break;

        default:
            usage(stdin);
            exit(EX_USAGE);
        }
    }

    return optind;
}

static struct sim_input_list
parse_positional_args(int const argc, char **const argv)
{
    struct sim_input_list all_inputs;
    struct sim_input_list file_inputs;

    STAILQ_INIT(&all_inputs);
    for (int i = 0; i < argc; ++i) {
        // TODO(ken): for the moment we only support ethereum-tests style JSON
        file_inputs = sim_input_load_eth_test(argv[i]);
        STAILQ_CONCAT(&all_inputs, &file_inputs);
    }
    return all_inputs;
}

static void free_simulation_inputs(struct sim_input_list *const inputs)
{
    struct sim_input *si;
    while ((si = STAILQ_FIRST(inputs)) != nullptr) {
        STAILQ_REMOVE_HEAD(inputs, next);
        sim_input_destroy(si);
    }
}

int main(int const argc, char **const argv)
{
    int pos_arg_index;
    struct exec_env *ee;
    struct sim_input_list all_inputs;
    struct driver_options opts = {};

    pos_arg_index = parse_options(argc, argv, &opts);

    // Parse the position arguments, which specify simulation input files
    all_inputs =
        parse_positional_args(argc - pos_arg_index, argv + pos_arg_index);

    // Create the execution environment, run it on all simulation inputs, then
    // destroy everything and exit
    ee = exec_env_create(&opts.ee_opts);
    exec_sim_inputs(ee, &all_inputs);

    exec_env_destroy(ee);
    free_simulation_inputs(&all_inputs);
    free(opts.ee_opts.macho_overrides);
    return 0;
}
