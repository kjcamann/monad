#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include <sys/mman.h>
#include <brotli/decode.h>

#include <monad-c/db/block_db.h>
#include <monad-c/support/assert.h>
#include <monad-c/support/mapped_file.h>
#include <monad-c/support/result.h>

static monad_result
map_compressed_block(struct mel_block_db *db, uint64_t block_num,
                     struct mcl_file_mapping *fm) {
    ldiv_t div_result;
    char full_path_buf[2048];
    char block_path_buf[32];
    const struct mcl_mmap_params mmap_params = {
        .addr = nullptr,
        .length = 0,
        .prot = PROT_READ,
        .flags = MAP_SHARED,
        .offset = 0
    };

    MONAD_ASSERT(db != nullptr && fm != nullptr);
    if (strlcpy(full_path_buf, db->root_dir_path, sizeof full_path_buf) >=
        sizeof full_path_buf)
        return monad_make_sys_error(ENAMETOOLONG);
    div_result = ldiv((long)block_num, 1'000'000L);
    (void)snprintf(block_path_buf, sizeof block_path_buf, "%ldM/%ld",
                   div_result.quot, div_result.rem);
    if (strlcat(full_path_buf, block_path_buf, sizeof full_path_buf) >=
        sizeof full_path_buf)
        return monad_make_sys_error(ENAMETOOLONG);
    fm->fd = openat(db->root_dir_fd, block_path_buf, O_RDONLY);
    if (fm->fd == -1)
        return monad_make_sys_error(errno);
    fm->file_path = strdup(full_path_buf);
    return mcl_map_fd(fm->fd, &mmap_params, MCL_MAP_ENTIRE_FILE, fm);
}

monad_result
mel_block_db_open(const char *root_dir_path, struct mel_block_db **db) {
    int saved_errno;
    int fd;
    if (db == nullptr)
        return monad_make_sys_error(EFAULT);
    fd = open(root_dir_path, O_RDONLY);
    if (fd == -1)
        return monad_make_sys_error(errno);
    *db = malloc(sizeof **db);
    if (*db == nullptr)
        goto Error;
    (*db)->root_dir_path = strdup(root_dir_path);
    if ((*db)->root_dir_path == nullptr) {
        free(*db);
        goto Error;
    }
    (*db)->root_dir_fd = fd;
    return monad_ok(0);

Error:
    saved_errno = errno;
    (void)close(fd);
    return monad_make_sys_error(saved_errno);
}

void mel_block_db_close(struct mel_block_db *db) {
    if (db == nullptr)
        return;
    if (db->root_dir_path != nullptr)
        free((void *)db->root_dir_path);
    (void)close(db->root_dir_fd);
}

monad_result
mel_block_db_copy_block(struct mel_block_db *db, uint64_t block_num,
                        uint8_t *block_buf, size_t buf_size) {
    struct mcl_file_mapping mapped_block_bits;
    BrotliDecoderResult decode_result;
    monad_result mr;

    if (db == nullptr || block_buf == nullptr)
        return monad_make_sys_error(EFAULT);
    mr = map_compressed_block(db, block_num, &mapped_block_bits);
    if (monad_is_error(mr))
        return mr;

    decode_result = BrotliDecoderDecompress(mapped_block_bits.map_length,
                                            (uint8_t*)mapped_block_bits.map_base,
                                            &buf_size,
                                            block_buf);
    mcl_unmap_file(&mapped_block_bits); // Unmap whether success or not
    if (decode_result != BROTLI_DECODER_RESULT_SUCCESS) {
        return monad_make_sys_error(EINVAL);
    }
    return monad_ok(buf_size);
}