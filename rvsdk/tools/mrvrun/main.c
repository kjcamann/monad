#include <assert.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <err.h>
#include <getopt.h>
#include <sysexits.h>
#include <syslog.h>

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
    LO_RV_LOG_LEVEL,
};

// clang-format off
static struct option long_options[] = {
    {"help", no_argument, 0, 'h'},
    {"evm", required_argument, 0, 'e'},
    {"riscv", required_argument, 0, 'r'},
    {"state-db", required_argument, 0, 's'},
    {"dso", required_argument, 0, 'd'},
    {"mrv-sdk-sys", required_argument, 0, 'm'},
    {"host-exec", no_argument, 0, LO_HOST_EXEC},
    {"rv-log-level", required_argument, 0, LO_RV_LOG_LEVEL},
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
"  -r | --riscv <rvc-load-spec>      load an RV64 VM virtual machine library\n"
"  -s | --state-db <state-load-spec> load a prestate db provider\n"
"  -d | --dso <dso-override>         map contract address to host DSO\n"
"  -m | --mrv-sdk-sys <sdk-tar>      load an MRV SDK system library tar file\n"
"  --rv-log-level <syslog-level>     set the log level"
"  --host-exec                       allow execution of native shared objects\n"
"\n"
"Positional arguments:\n"
"  <input> simulation input\n");
}

// clang-format on

struct driver_options
{
    struct exec_env_options ee_opts;
};

static void append_dso_override(
    struct exec_env_options *const ee_opts, char const *const arg)
{
    int rc;
    struct dso_override *override;
    char const *const sep = strchr(arg, ':');

    ee_opts->dso_overrides = realloc(
        ee_opts->dso_overrides,
        sizeof(struct dso_override) * (ee_opts->dso_override_count + 1));
    if (ee_opts->dso_overrides == nullptr) {
        err(EX_OSERR, "realloc(3) of dso_overrides failed");
    }
    override = &ee_opts->dso_overrides[ee_opts->dso_override_count++];

    if (sep == nullptr) {
        errx(EX_USAGE, "parse error: expected ':' in DSO override `%s`", arg);
    }
    rc = asprintf((char **)&override->address, "%.*s", (int)(sep - arg), arg);
    assert(rc > 0);
    override->dso_path = strdup(sep + 1);
}

static int parse_options(
    int const argc, char **const argv, struct driver_options *const opts)
{
    int ch;
    unsigned long opt_ul;

    while ((ch = getopt_long(
                argc, argv, "he:r:s:d:m:", long_options, nullptr)) != -1) {
        switch (ch) {
        case 'h':
            help();
            exit(0);

        case 'e':
            opts->ee_opts.evm_config = optarg;
            break;

        case 'r':
            opts->ee_opts.rvc_config = optarg;
            break;

        case 's':
            opts->ee_opts.db_config = optarg;
            break;

        case 'd':
            append_dso_override(&opts->ee_opts, optarg);
            break;

        case 'm':
            opts->ee_opts.mrv_sys_paths = realloc(
                opts->ee_opts.mrv_sys_paths,
                sizeof(char const *) * (opts->ee_opts.mrv_sys_path_count + 1));
            opts->ee_opts.mrv_sys_paths[opts->ee_opts.mrv_sys_path_count++] =
                optarg;
            break;

        case LO_HOST_EXEC:
            opts->ee_opts.dso_host_exec = true;
            break;

        case LO_RV_LOG_LEVEL:
            // XXX: support setting by priority names, easy enough
            opt_ul = strtoul(optarg, nullptr, 10);
            if (opt_ul > LOG_DEBUG) {
                errx(EX_USAGE, "could not parse log level %s", optarg);
            }
            opts->ee_opts.rv_log_level = (uint8_t)opt_ul;
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

static void free_dso_overrides(struct exec_env_options const *const ee_opts)
{
    for (size_t i = 0; i < ee_opts->dso_override_count; ++i) {
        struct dso_override const *const override = &ee_opts->dso_overrides[i];
        free((void *) override->address);
        free((void *) override->dso_path);
    }
    free(ee_opts->dso_overrides);
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
    free_dso_overrides(&opts.ee_opts);
    return 0;
}
