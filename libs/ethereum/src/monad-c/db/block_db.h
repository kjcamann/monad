#pragma once

/**
 * @file
 *
 * This file provides a utility for accessing an on-disk database of Ethereum
 * blocks
 */

#include <stddef.h>
#include <stdint.h>

#include <monad-c/support/result.h>

struct mel_block_db {
    const char *root_dir_path;
    int root_dir_fd;
};

monad_result
mel_block_db_open(const char *root_dir_path, struct mel_block_db **db);

void mel_block_db_close(struct mel_block_db *db);

monad_result
mel_block_db_copy_block(struct mel_block_db *db, uint64_t block_num,
                        uint8_t *block_buf, size_t buf_size);