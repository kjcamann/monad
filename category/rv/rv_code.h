#pragma once

#include <stddef.h>
#include <stdint.h>

#include <category/core/byteview.h>

struct Elf;

#ifdef __cplusplus
extern "C"
{
#endif

constexpr uint32_t MONAD_RV_CODE_MAX_SIZE = 1U << 18; // 256 KiB

// clang-format off

struct monad_rv_code_header
{
    uint8_t prefix[3];    ///< The byte sequence 0xAE, 0x00, 0x01
    uint32_t code_length; ///< Length of code blob following this header (LE32)
} __attribute__((packed));

/// A contract creation transaction for RV64 code contains several sections,
/// which are described by this structure
struct monad_rv_code_sections
{
    struct monad_rv_code_header const
        *code_header;          ///< Header describing the code blob
    struct monad_bv db_blob;   ///< Binary stored in db (header + code_blob)
    struct monad_bv code_blob; ///< zstd frame containing ELF file
    struct monad_bv init_blob; ///< Init data for contract creation
};

/// RV64 code validation errors; RV64 code validation must go through several
/// stages, including parsing the transaction data, zstd decompression, and
/// loading the executable image with libelf
typedef enum monad_rv_validate_result
{
    MONAD_RV_VALIDATE_UNKNOWN,         ///< Zero initialization -> invalid
    MONAD_RV_VALIDATE_NO_PREFIX,       ///< 0xAE0001 prefix was not present
    MONAD_RV_VALIDATE_BAD_HEADER,      ///< Malformed monad_rv_code_header
    MONAD_RV_VALIDATE_CODE_OVERFLOW,   ///< Code exceeds MONAD_RV_MAX_CODE_SIZE
    MONAD_RV_VALIDATE_POINTS_OUTSIDE,  ///< code_length points past buffer end
    MONAD_RV_VALIDATE_INVALID_FORMAT,  ///< Code not in a recognized format
    MONAD_RV_VALIDATE_LIBZSTD_ERR,     ///< libzstd could not decompress code
    MONAD_RV_VALIDATE_HAS_ELF_MAGIC,   ///< Partially checked; ELF magic number
    MONAD_RV_VALIDATE_HAS_ZSTD_MAGIC,  ///< Partially checked; ZSTD magic number
    MONAD_RV_VALIDATE_LIBELF_ERROR,    ///< libelf could not open ELF image
    MONAD_RV_VALIDATE_ELF_NOT_RV64,    ///< ELF image is not RV64
    MONAD_RV_VALIDATE_NO_INIT_FN,      ///< init_contract function missing
    MONAD_RV_VALIDATE_NO_MAIN_FN,      ///< txn_main function missing
    MONAD_RV_VALIDATE_OK,              ///< Code ready for execution
} monad_rv_validate_result_t;

// clang-format on

/// Opaque handle to a RISC-V code decompressor
struct monad_rv_code_zstd_decomp;

/// Create a code decompressor object; use one decompressor object per
/// thread if parallel decompression is needed
int monad_rv_code_zstd_decomp_create(struct monad_rv_code_zstd_decomp **);

/// Destroy a code decompressor object
void monad_rv_code_zstd_decomp_destroy(struct monad_rv_code_zstd_decomp *);

/// Return a string explanation of a code validation error
char const *monad_rv_describe_validate_result(monad_rv_validate_result_t);

/// Parse the raw data of a contract creation transaction into sections
///
/// This can fail with many kinds of validation errors, or it can return
/// one of two possible "success" codes:
///
///   1. MONAD_RV_VALIDATE_HAS_ELF_MAGIC -- parsed successfully and the
///      `sections->code_blob` section contains the magic number of an ELF
///      file (we do not know if the ELF file contents are valid or not)
///
///   2. MONAD_RV_VALIDATE_HAS_ZSTD_MAGIC -- parsed successfully and the
///      `sections->code_blob` section contains the magic number of a zstd
///      frame; we do not know if the zstd frame contents are valid or not
monad_rv_validate_result_t monad_rv_parse_create_txn_data(
    struct monad_bv, struct monad_rv_code_sections *sections);

/// Given the bytes of a ZSTD frame, try to decompress its contents into
/// the provided buffer
///
/// On input, `buflen` describes the available buffer size and upon output
/// `buflen` is modified to describe the actual decompressed size. Possible
/// return codes are:
///
///   - MONAD_RV_VALIDATE_LIBZSTD_ERR -- decompression error from libzstd;
///       error details are available in zstd_rc and zstd_err
///
///   - MONAD_RV_VALIDATE_INVALID_FORMAT -- decompressed successfully, but
///       the contents were invalid (did not find an ELF magic number)
///
///   - MONAD_RV_VALIDATE_CODE_OVERFLOW -- decompressed successfully, but
///       the resulting code payload is too large; `buflen` will be set to
///       the actual size, but the decompressed contents are invalid
///
///   - MONAD_RV_VALIDATE_HAS_ELF_MAGIC -- the "success" code; decompression
///       was successful, and the payload contains an ELF magic number (it is
///       not known if the ELF contents are valid)
monad_rv_validate_result_t monad_rv_decompress_code(
    struct monad_bv zstd_frame, uint8_t *buf, size_t *buflen,
    struct monad_rv_code_zstd_decomp *, size_t *zstd_rc, char const **zstd_err);

/// Given the contents of an ELF file, validate that it contains the correct
/// structure for RV64 execution and (optionally) return a libelf handle to it;
/// if successful this returns MONAD_RV_VALIDATE_OK
monad_rv_validate_result_t monad_rv_validate_code(
    void const *buf, size_t size, bool strict_rv64, struct Elf **elf);

/// Performs all steps of validation without opening a libelf handle; this can
/// be used to validate a transaction during block construction
monad_rv_validate_result_t monad_rv_validate_create_txn_data(
    struct monad_bv, struct monad_rv_code_zstd_decomp *, bool strict_rv64,
    bool allow_uncompressed);

#ifdef __cplusplus
} // extern "C"
#endif
