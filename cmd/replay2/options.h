#pragma once

#include <monad-c/execution/block_vm.h>

struct program_options {
    struct mex_block_vm_options block_vm_options;
    const char *genesis_file;
    int verbose;
};

