#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>
#include <time.h>

#include <stdio.h> // FIXME: remove later

#include <monad-c/db/block_db.h>
#include <monad-c/ethereum/block.h>
#include <monad-c/execution/block_vm.h>
#include <monad-c/rlp/rlp_decode.h>
#include <monad-c/support/perf_counter.h>
#include <monad-c/support/result.h>

#include "options.h"

// XXX: move these
#define LOG_ERR(mr, ...) fprintf(stderr, __VA_ARGS__)
#define MONAD_MIN(x, y) ((x) < (y) ? (x) : (y))

constexpr unsigned BLOCK_CHUNK_SHIFT = 10;
constexpr size_t BLOCK_CHUNK_SIZE = (1ULL << (BLOCK_CHUNK_SHIFT - 1));
constexpr unsigned MAX_BLOCK_RLP_SIZE = (1 << 24);

constexpr struct timespec BLOCK_EXEC_TIMEOUT = {
    .tv_sec = 0,
    .tv_nsec = 100'000'000
};

// This is too large to place on the stack in macOS
static thread_local uint8_t block_rlp_buf[MAX_BLOCK_RLP_SIZE];

static monad_result
exec_block_chunk(const struct program_options *opts,
                 struct mel_block_db *block_db,
                 struct mex_block_vm *block_vm,
                 mel_block_range blocks) {
    monad_result mr;
    struct mex_block_exec_output *exec_output;

    for (mel_block_num b = blocks.begin; b < blocks.end; ++b) {
        /*
         * This loop executes Ethereum blocks. It does four things:
         *
         *  1. copy an RLP-encoded block into a local buffer using block_db
         *     (mel_block_db_copy_block)
         *
         *  2. start evaluation of the block using the Monad Block VM
         *     (mex_block_vm_exec)
         *
         *  3. wait for the block to finish processing (mex_block_vm_wait)
         *
         *  4. release the memory holding the block execution results back
         *     to the block VM system (mex_block_vm_release)
         *
         * We do not explicitly verify that the world state root hash matches
         * the value in the block header; the block VM does that for us.
         */
        mr = mel_block_db_copy_block(block_db, b, block_rlp_buf,
                                     sizeof block_rlp_buf);
        if (monad_is_error(mr)) {
            LOG_ERR(mr, "unable to map block %zu in database %s", b,
                    block_db->root_dir_path);
            return mr;
        }

        const rlp_buf_t block_rlp = {
            .begin = block_rlp_buf,
            .end = block_rlp_buf + monad_value(mr)
        };
        mr = mex_block_vm_exec(block_vm, block_rlp, &exec_output);
        if (monad_is_error(mr)) {
            LOG_ERR(mr, "block_vm could not execute block %llu in db %s", b,
                    block_db->root_dir_path);
            return mr;
        }

        mr = mex_block_vm_wait(exec_output, &BLOCK_EXEC_TIMEOUT);
        if (monad_is_error(mr)) {
            LOG_ERR(mr, "mex_block_vm_wait on block %llu in db %s", b,
                    block_db->root_dir_path);
        }

        (void)mex_block_vm_release(exec_output);
    }

    return monad_ok(0); // XXX: number of txns
}

#if 0
static void report_chunk_tps(uint64_t nano_start, uint64_t nano_end,
                             mel_block_range chunk_range) {
}
#endif

int replay_ethereum(const struct program_options *opts,
                    struct mel_block_db *block_db,
                    struct mex_block_vm *block_vm,
                    mel_block_range blocks) {
    monad_result mr;
    int return_code = 0;

    // Divide the block range into chunks; we'll gather statistics measuring
    // performance around each block.
    const size_t num_blocks = blocks.end - blocks.begin;
    const ldiv_t div_result = ldiv(num_blocks, BLOCK_CHUNK_SIZE);
    size_t num_chunks = div_result.quot;
    if (div_result.rem > 0)
        ++num_chunks;

    for (mel_block_num b = blocks.begin; b < blocks.end; b += BLOCK_CHUNK_SIZE) {
        const mel_block_range chunk_range = {
            .begin = b,
            .end = MONAD_MIN(b + BLOCK_CHUNK_SIZE, blocks.end)
        };

        //const uint64_t nano_start = mcl_take_timestamp_ns();
        mr = exec_block_chunk(opts, block_db, block_vm, chunk_range);
        if (monad_is_error(mr)) {
            LOG_ERR(mr, "exec_block_chunk failed");
            return_code = 1;
            goto Finished;
        }
        //report_chunk_tps(nano_start, mcl_take_timestamp_ns(), chunk_range);
    }

    fprintf(stderr, "block vm processed %zu blocks\n",
            mex_block_vm_get_stats(block_vm)->num_blocks);

Finished:
    (void)mex_block_vm_destroy(block_vm, true);
    return return_code;
}