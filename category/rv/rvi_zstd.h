#pragma once

#include <stddef.h>
#include <stdint.h>

#include <category/core/byteview.h>
#include <category/rv/rv_code.h>

struct rvi_zstd_decomp
{
    struct ZSTD_DCtx_s *dctx;
    uint8_t *outbuf;
    size_t outbuf_size;
};

int rvi_zstd_decomp_init(struct rvi_zstd_decomp *);

void rvi_zstd_decomp_cleanup(struct rvi_zstd_decomp *);

monad_rv_validate_code_result_t rvi_zstd_decompress_code(
    struct rvi_zstd_decomp *, struct monad_bv zstd_frame, uint8_t *buf,
    size_t *buflen, size_t *zstd_rc, char const **zstd_err);
