#include <errno.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>

#include <fcntl.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>

#include <category/core/event/evcap_file.h>
#include <category/core/event/evcap_reader.h>
#include <category/core/event/evcap_writer.h>
#include <category/core/event/event_ring.h>
#include <category/core/format_err.h>
#include <category/core/srcloc.h>
#include <category/execution/ethereum/event/blockcap.h>
#include <category/execution/ethereum/event/exec_event_ctypes.h>

// Defined in blockcap_builder.c
extern thread_local char _g_monad_bcap_error_buf[1024];

#define FORMAT_ERRC(...)                                                       \
    monad_format_err(                                                          \
        _g_monad_bcap_error_buf,                                               \
        sizeof(_g_monad_bcap_error_buf),                                       \
        &MONAD_SOURCE_LOCATION_CURRENT(),                                      \
        __VA_ARGS__)

struct monad_bcap_block_archive
{
    int dirfd;
};

// Write an evcap file with SCHEMA section, an EVENT_BUNDLE section (with the
// block number set), and a sequence number index section
static int write_bcap_file(
    struct monad_evcap_writer *ecw, struct monad_bcap_proposal const *proposal)
{
    int rc;
    struct monad_evcap_dynamic_section *dyn_sec;
    struct monad_evcap_section_desc *event_sd;

    // Add SCHEMA section
    rc = monad_evcap_writer_add_schema_section(
        ecw, MONAD_EVENT_CONTENT_TYPE_EXEC, g_monad_exec_event_schema_hash);
    if (rc != 0) {
        goto EVCAP_Error;
    }

    // Flush the proposal's event vbuf chain to a dynamic section
    rc = monad_evcap_writer_dyn_sec_open(ecw, &dyn_sec, &event_sd);
    if (rc != 0) {
        goto EVCAP_Error;
    }

    event_sd->type = MONAD_EVCAP_SECTION_EVENT_BUNDLE;
    event_sd->compression = proposal->event_compression_info.compression;
    event_sd->content_length =
        proposal->event_compression_info.uncompressed_length;
    event_sd->event_bundle.event_count = proposal->event_count;
    event_sd->event_bundle.start_seqno = proposal->start_seqno;
    event_sd->event_bundle.block_number = proposal->block_tag.block_number;

    rc = (int)monad_evcap_writer_dyn_sec_sync_vbuf_chain(
        ecw, dyn_sec, &proposal->event_vbuf_chain);
    if (rc < 0) {
        rc = -rc;
        goto EVCAP_Error;
    }

    rc = monad_evcap_writer_dyn_sec_close(ecw, dyn_sec);
    if (rc != 0) {
        goto EVCAP_Error;
    }

    // If we have a seqno vbuf chain, flush that too
    if (proposal->seqno_index_vbuf_chain.segment_count > 0) {
        rc = monad_evcap_writer_commit_seqno_index(
            ecw,
            &proposal->seqno_index_vbuf_chain,
            proposal->seqno_index_compression_info.compression,
            proposal->seqno_index_compression_info.uncompressed_length,
            event_sd);
        if (rc != 0) {
            goto EVCAP_Error;
        }
    }

    return 0;

EVCAP_Error:
    return FORMAT_ERRC(
        rc,
        "cannot write finalized block %lu, caused by:\n%s",
        proposal->block_tag.block_number,
        monad_evcap_writer_get_last_error());
}

int monad_bcap_block_archive_open(
    struct monad_bcap_block_archive **bca_p, int dirfd, char const *error_name)
{
    int rc;
    struct stat archive_stat;

    struct monad_bcap_block_archive *bca = *bca_p = malloc(sizeof *bca);
    if (bca == nullptr) {
        return FORMAT_ERRC(errno, "malloc of monad_bcap_block_archive failed");
    }
    bca->dirfd = dup(dirfd);
    if (bca->dirfd == -1) {
        rc =
            FORMAT_ERRC(errno, "dup of fd for archive `%s` failed", error_name);
        goto Error;
    }
    if (fstat(bca->dirfd, &archive_stat) == -1) {
        rc = FORMAT_ERRC(errno, "stat of archive `%s` file failed", error_name);
        goto Error;
    }
    if ((archive_stat.st_mode & S_IFDIR) != S_IFDIR) {
        rc = FORMAT_ERRC(ENOTDIR, "path `%s` is not directory", error_name);
        goto Error;
    }
    return 0;

Error:
    monad_bcap_block_archive_close(bca);
    *bca_p = nullptr;
    return rc;
}

void monad_bcap_block_archive_close(struct monad_bcap_block_archive *bca)
{
    (void)close(bca->dirfd);
    free(bca);
}

int monad_bcap_block_archive_open_block(
    struct monad_bcap_block_archive *bca, uint64_t finalized_block,
    struct monad_evcap_reader **evcap_reader_p,
    struct monad_evcap_section_desc const **event_bundle_sd_p)
{
    int rc;
    int fd;
    char path_buf[32];
    char error_name_buf[64];
    struct monad_evcap_section_desc const *sd;

    // Form the path to the file, then open it
    ldiv_t const d =
        ldiv((long)finalized_block, (long)MONAD_BCAP_FILES_PER_SUBDIR);
    *evcap_reader_p = nullptr;
    sd = *event_bundle_sd_p = nullptr;
    // TODO(ken): MONAD_BCAP_FILES_PER_SUBDIR is constexpr, but then we
    //  hardcode a width of 4 in the format specifier, assuming we know the
    //  number of digits
    (void)sprintf(
        path_buf,
        "%ld/%04ld.bcap",
        d.quot * (long)MONAD_BCAP_FILES_PER_SUBDIR,
        d.rem);
    (void)sprintf(error_name_buf, "%s [block %lu]", path_buf, finalized_block);
    fd = openat(bca->dirfd, path_buf, O_RDONLY);
    if (fd == -1) {
        return FORMAT_ERRC(errno, "could not open %s", error_name_buf);
    }

    // Create an event capture reader for the file, and check if the schema
    // is compatible with the current library
    rc = monad_evcap_reader_create(evcap_reader_p, fd, error_name_buf);
    (void)close(fd);
    if (rc != 0) {
        return FORMAT_ERRC(
            rc,
            "could not open evcap reader for %s; caused by:\n%s",
            error_name_buf,
            monad_evcap_reader_get_last_error());
    }
    if (monad_evcap_reader_check_schema(
            *evcap_reader_p,
            MONAD_EVENT_RING_HEADER_VERSION,
            MONAD_EVENT_CONTENT_TYPE_EXEC,
            g_monad_exec_event_schema_hash) != 0) {
        return FORMAT_ERRC(
            rc,
            "evcap reader schema check failed for %s; caused by:\n%s",
            error_name_buf,
            monad_evcap_reader_get_last_error());
    }

    // Find an EVENT_BUNDLE section with a set block number; if there's more
    // than one, it's an overflow error
    while (monad_evcap_reader_next_section(
        *evcap_reader_p, MONAD_EVCAP_SECTION_EVENT_BUNDLE, &sd)) {
        if (sd->event_bundle.block_number == 0) {
            continue;
        }
        if (*event_bundle_sd_p != nullptr) {
            return FORMAT_ERRC(
                EOVERFLOW,
                "duplicate block event bundle sections in %s",
                error_name_buf);
        }
        *event_bundle_sd_p = sd;
    }

    return 0;
}

int monad_bcap_block_archive_add_block(
    struct monad_bcap_block_archive *bca,
    struct monad_bcap_proposal const *proposal, mode_t dir_create_mode,
    mode_t file_create_mode)
{
    int rc;
    int block_fd;
    char subdir_name_buf[32];
    char block_name_buf[64];
    struct monad_evcap_writer *evcap_writer;

    uint64_t const block_number = proposal->block_tag.block_number;
    ldiv_t const d =
        ldiv((long)block_number, (long)MONAD_BCAP_FILES_PER_SUBDIR);

    evcap_writer = nullptr;
    sprintf(subdir_name_buf, "%ld", d.quot * (long)MONAD_BCAP_FILES_PER_SUBDIR);
    if (mkdirat(bca->dirfd, subdir_name_buf, dir_create_mode) == -1 &&
        errno != EEXIST) {
        return FORMAT_ERRC(
            errno,
            "unable to create directory %ld to write block %lu",
            d.quot,
            block_number);
    }
    sprintf(block_name_buf, "%s/%04ld.bcap", subdir_name_buf, d.rem);
    block_fd = openat(
        bca->dirfd, subdir_name_buf, O_RDWR | O_TMPFILE, file_create_mode);
    if (block_fd == -1) {
        rc = FORMAT_ERRC(
            errno,
            "unable to open temporary file for block %lu in archive filesystem",
            block_number);
        goto Done;
    }
    if ((rc = monad_evcap_writer_create(&evcap_writer, block_fd)) != 0) {
        FORMAT_ERRC(
            rc,
            "could not open evcap write for block %lu; caused by:\n%s",
            block_number,
            monad_evcap_writer_get_last_error());
        goto Done;
    }
    if ((rc = write_bcap_file(evcap_writer, proposal)) != 0) {
        return rc;
    }
    if (linkat(block_fd, "", bca->dirfd, block_name_buf, AT_EMPTY_PATH) == -1) {
        rc = FORMAT_ERRC(
            errno,
            "could not link block file %lu into the filesystem at %s/%s",
            block_number,
            subdir_name_buf,
            block_name_buf);
        goto Done;
    }
    rc = 0;

Done:
    monad_evcap_writer_destroy(evcap_writer);
    (void)close(block_fd);
    return rc;
}
