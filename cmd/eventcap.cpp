/**
 * @file
 *
 * Execution event capture utility
 */

#include <bit>
#include <chrono>
#include <cstddef>
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <format>
#include <iterator>
#include <memory>
#include <optional>
#include <span>
#include <string>
#include <thread>
#include <utility>
#include <vector>

#include <alloca.h>
#include <err.h>
#include <fcntl.h>
#include <poll.h>
#include <signal.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <sys/types.h>
#include <sysexits.h>
#include <unistd.h>

#include <CLI/CLI.hpp>
#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/types.h>
#include <zstd.h>

#include <monad/core/assert.h>
#include <monad/core/bit_util.h>
#include <monad/core/exec_event_ctypes.h>
#include <monad/core/fmt/exec_event_ctypes_fmt.hpp>
#include <monad/event/event_iterator.h>
#include <monad/event/event_metadata.h>
#include <monad/event/event_ring.h>
#include <monad/event/event_ring_util.h>
#include <monad/event/test_event_types.h>

static sig_atomic_t g_should_exit = 0;

struct MetadataTableEntry
{
    uint8_t const (*hash)[32];
    std::span<monad_event_metadata const> entries;
} MetadataTable[] = {
    [MONAD_EVENT_RING_TYPE_NONE] =
        {
            nullptr,
            {},
        },
    [MONAD_EVENT_RING_TYPE_TEST] =
        {
            &g_monad_test_event_metadata_hash,
            std::span{g_monad_test_event_metadata},
        },
    [MONAD_EVENT_RING_TYPE_EXEC] =
        {&g_monad_exec_event_metadata_hash,
         std::span{g_monad_exec_event_metadata}},
};

struct EventRingNameToDefaultPathEntry
{
    std::string_view name;
    char const *default_path;
} EventRingNameToDefaultPathTable[] = {
    [MONAD_EVENT_RING_TYPE_NONE] =
        {
            g_monad_event_ring_type_names[MONAD_EVENT_RING_TYPE_NONE],
            {},
        },
    [MONAD_EVENT_RING_TYPE_TEST] =
        {.name = g_monad_event_ring_type_names[MONAD_EVENT_RING_TYPE_TEST],
         .default_path = MONAD_EVENT_DEFAULT_TEST_RING_PATH},
    [MONAD_EVENT_RING_TYPE_EXEC] = {
        .name = g_monad_event_ring_type_names[MONAD_EVENT_RING_TYPE_EXEC],
        .default_path = MONAD_EVENT_DEFAULT_EXEC_RING_PATH}};

static char const *get_default_path_for_event_ring_name(std::string_view name)
{
    auto const i_entry = std::ranges::find(
        EventRingNameToDefaultPathTable,
        name,
        &EventRingNameToDefaultPathEntry::name);
    return i_entry != std::ranges::end(EventRingNameToDefaultPathTable)
               ? i_entry->default_path
               : nullptr;
}

struct mapped_event_ring
{
    int ring_fd;
    std::string origin_path;
    monad_event_ring event_ring;
    std::span<monad_event_metadata const> metadata_entries;
    std::optional<uint64_t> start_seqno;
    monad_exec_block_header const *blocks;
};

constexpr size_t PAGE_2MB = 1UL << 21;

// TODO(ken): supposed to come from mem/align.h but the PR hasn't landed yet
[[gnu::always_inline]] static inline size_t
monad_round_size_to_align(size_t size, size_t align)
{
    return bit_round_up(size, static_cast<size_t>(std::countr_zero(align)));
}

static bool event_ring_is_abandoned(int ring_fd)
{
    pid_t writer_pids[32];
    size_t n_pids = std::size(writer_pids);
    if (monad_event_ring_find_writer_pids(ring_fd, writer_pids, &n_pids) != 0) {
        errx(
            EX_SOFTWARE,
            "event library error -- %s",
            monad_event_ring_get_last_error());
    }
    return n_pids == 0;
}

static bool all_writers_have_exited(std::span<int> pidfds)
{
    auto *const pollfds =
        std::bit_cast<pollfd *>(alloca(sizeof(pollfd) * size(pidfds)));
    for (size_t i = 0; int pidfd : pidfds) {
        pollfds[i++] = pollfd{.fd = pidfd, .events = POLLIN, .revents = 0};
    }
    int const n_ready = poll(pollfds, size(pidfds), 0);
    return n_ready == -1 || static_cast<size_t>(n_ready) == size(pidfds);
}

// Helper function which can open regular or zstd-compressed event ring files;
// the process will exit if the open fails
static int open_event_ring_file_or_exit(char const *path)
{
    static_assert(
        sizeof MONAD_EVENT_RING_HEADER_VERSION >= sizeof ZSTD_MAGICNUMBER);
    char magic[sizeof MONAD_EVENT_RING_HEADER_VERSION];

    int ring_fd = open(path, O_RDONLY);
    if (ring_fd == -1) {
        err(EX_CONFIG, "could not open event ring file `%s`", path);
    }

    // Read the first few bytes so we can figure out if this is a regular event
    // ring file, a compressed one, or neither
    if (ssize_t const nr = read(ring_fd, &magic, sizeof magic); nr == -1) {
        err(EX_CONFIG,
            "could not read magic number from event ring file `%s`",
            path);
    }
    else if (static_cast<size_t>(nr) < sizeof magic) {
        errx(
            EX_CONFIG,
            "file `%s` does not appear to be an event ring file or snapshot",
            path);
    }

    if (*std::bit_cast<unsigned const *>(&magic) == ZSTD_MAGICNUMBER) {
        // This is a zstd-compressed file; mmap it into place for decompression,
        // then create a memfd and load the contents into it
        struct stat zstd_file_stat;
        if (fstat(ring_fd, &zstd_file_stat) == -1) {
            err(EX_OSERR, "unable to stat zstd file `%s`", path);
        }
        size_t const compressed_size =
            static_cast<size_t>(zstd_file_stat.st_size);
        void *const compressed_base = mmap(
            nullptr,
            static_cast<size_t>(zstd_file_stat.st_size),
            PROT_READ,
            MAP_SHARED,
            ring_fd,
            0);
        if (compressed_base == MAP_FAILED) {
            err(EX_OSERR, "mmap of zstd file `%s` contents failed", path);
        }

        size_t const decompressed_bound =
            ZSTD_decompressBound(compressed_base, compressed_size);
        if (decompressed_bound == ZSTD_CONTENTSIZE_ERROR) {
            errx(EX_SOFTWARE, "ZSTD_decompressBound error for `%s`", path);
        }
        size_t const memfd_size =
            monad_round_size_to_align(decompressed_bound, PAGE_2MB);

        std::string const memfd_name = std::format("memfd-unzstd:{}", path);
        int memfd = memfd_create(memfd_name.c_str(), MFD_CLOEXEC | MFD_HUGETLB);
        if (memfd == -1) {
            err(EX_OSERR, "unable to open memfd file `%s`", memfd_name.c_str());
        }
        if (ftruncate(memfd, static_cast<off_t>(memfd_size)) == -1) {
            err(EX_OSERR,
                "ftruncate of memfd file `%s` failed",
                memfd_name.c_str());
        }
        void *const decompressed_base = mmap(
            nullptr,
            memfd_size,
            PROT_READ | PROT_WRITE,
            MAP_SHARED | MAP_HUGETLB,
            memfd,
            0);
        if (decompressed_base == MAP_FAILED) {
            err(EX_OSERR, "mmap of memfd file `%s` failed", memfd_name.c_str());
        }
        size_t const decompressed_size = ZSTD_decompress(
            decompressed_base, memfd_size, compressed_base, compressed_size);
        if (ZSTD_isError(decompressed_size)) {
            errx(
                EX_SOFTWARE,
                "zstd error decompressing `%s`: %s",
                path,
                ZSTD_getErrorName(decompressed_size));
        }
        if (decompressed_size < sizeof magic) {
            errx(
                EX_CONFIG,
                "zstd file `%s` does not contain an event ring",
                path);
        }

        // Remove the compressed mapping, and copy the decompressed magic bytes
        // into `magic` as if we read them ring_fd, then remove the decompressed
        // mapping and proceed as if memfd had actually been opened as ring_fd
        munmap(compressed_base, compressed_size);
        std::memcpy(magic, decompressed_base, sizeof magic);
        munmap(decompressed_base, memfd_size);
        std::swap(ring_fd, memfd);
        (void)close(memfd);
    }

    if (std::memcmp(magic, MONAD_EVENT_RING_HEADER_VERSION, sizeof magic) !=
        0) {
        // Not a snapshot, but also not a regular event ring file; if it starts
        // with RING this is a different version, otherwise it's just completely
        // wrong
        if (std::memcmp(magic, "RING", 4) == 0) {
            std::string_view const file_magic{magic, sizeof magic};
            std::string_view const library_magic{
                std::bit_cast<char *>(&MONAD_EVENT_RING_HEADER_VERSION),
                sizeof magic};
            std::string const error = std::format(
                "event ring library is version {}, file version  is {}",
                library_magic,
                file_magic);
            errx(EX_CONFIG, "version mismatch: %s", error.c_str());
        }
        errx(
            EX_CONFIG,
            "file `%s` does not appear to be an event ring file",
            path);
    }

    return ring_fd;
}

static void print_event_ring_header(
    char const *filename, monad_event_ring_header const *h, std::FILE *out)
{
    std::fprintf(out, "event ring %s\n", filename);
    // Print the event ring file header information:
    // <type-name> [<type-code>] <descriptor capacity> <descriptor byte size>
    //    <payload buf size> <context area size> <last write seqno>
    //    <next payload buf byte> <pbuf window start>
    std::fprintf(
        out,
        "%10s %9s %10s %10s %10s %12s %14s %14s\n",
        "TYPE",
        "DESC_CAP",
        "DESC_SZ",
        "PBUF_SZ",
        "CTX_SZ",
        "WR_SEQNO",
        "PBUF_NEXT",
        "PBUF_WIN");
    std::fprintf(
        out,
        "%6s [%hu] %9lu %10lu %10lu %10lu %12lu %14lu %14lu\n",
        g_monad_event_ring_type_names[h->type],
        h->type,
        h->size.descriptor_capacity,
        h->size.descriptor_capacity * sizeof(monad_event_descriptor),
        h->size.payload_buf_size,
        h->size.context_area_size,
        __atomic_load_n(&h->control.last_seqno, __ATOMIC_ACQUIRE),
        __atomic_load_n(&h->control.next_payload_byte, __ATOMIC_ACQUIRE),
        __atomic_load_n(&h->control.buffer_window_start, __ATOMIC_ACQUIRE));
}

static void hexdump_event_payload(
    monad_event_iterator const *iter, monad_event_descriptor const *event,
    std::FILE *out)
{
    // Large thread_locals will cause a stack overflow, so make the
    // thread-local a pointer to a dynamic buffer
    constexpr size_t hexdump_buf_size = 1UL << 25;
    thread_local static std::unique_ptr<char[]> const hexdump_buf{
        new char[hexdump_buf_size]};

    std::byte const *payload_base =
        static_cast<std::byte const *>(monad_event_payload_peek(iter, event));
    std::byte const *const payload_end = payload_base + event->payload_size;
    char *o = hexdump_buf.get();
    for (std::byte const *line = payload_base; line < payload_end; line += 16) {
        // Print one line of the dump, which is 16 bytes, in the form:
        // <offset> <8 bytes> <8 bytes>
        o = std::format_to(o, "{:#08x} ", line - payload_base);
        for (uint8_t b = 0; b < 16 && line + b < payload_end; ++b) {
            o = std::format_to(o, "{:02x}", std::to_underlying(line[b]));
            if (b == 7) {
                *o++ = ' '; // Extra padding after 8 bytes
            }
        }
        *o++ = '\n';

        // Every 512 bytes, check if the payload page data is still valid; the
        // + 16 bias is to prevent checking the first iteration
        if ((line - payload_base + 16) % 512 == 0 &&
            !monad_event_payload_check(iter, event)) {
            break; // Escape to the end, which checks the final time
        }
    }

    if (!monad_event_payload_check(iter, event)) {
        std::fprintf(stderr, "ERROR: event %lu payload lost!\n", event->seqno);
    }
    else {
        std::fwrite(
            hexdump_buf.get(),
            static_cast<size_t>(o - hexdump_buf.get()),
            1,
            out);
    }
}

static void print_event(
    monad_event_iterator *iter, monad_event_descriptor const *event,
    std::span<monad_event_metadata const> metadata_entries,
    monad_exec_block_header const *blocks, bool hexdump_payload,
    bool decode_payload, std::FILE *out)
{
    using std::chrono::seconds, std::chrono::nanoseconds;
    static std::chrono::sys_time<seconds> last_second{};
    static std::chrono::sys_time<nanoseconds> last_second_nanos;

    char event_buf[256];
    char time_buf[32];

    monad_event_metadata const &event_md = metadata_entries[event->event_type];
    std::chrono::sys_time<nanoseconds> const event_time{
        nanoseconds{event->record_epoch_nanos}};

    // An optimization to only do the string formatting of the %H:%M:%S part
    // of the time each second when it changes; this is a slow operation
    if (auto const cur_second = std::chrono::floor<seconds>(event_time);
        cur_second != last_second) {
        // The below should, but std::format formats the local time in the
        // UTC zone
        std::chrono::zoned_time const event_time_tz{
            std::chrono::current_zone(), cur_second};
        *std::format_to(time_buf, "{:%T}", event_time_tz) = '\0';
        last_second = cur_second;
        last_second_nanos =
            std::chrono::time_point_cast<nanoseconds>(last_second);
    }

    // Print a summary line of this event
    // <HH:MM::SS.nanos> <event-c-name> [<event-type> <event-type-hex>]
    //     SEQ: <sequence-no> LEN: <payload-length>
    char *o = std::format_to(
        event_buf,
        "{}.{:09}: {} [{} {:#x}] SEQ: {} LEN: {} BUF_OFF: {}",
        time_buf,
        (event_time - last_second_nanos).count(),
        event_md.c_name,
        event->event_type,
        event->event_type,
        event->seqno,
        event->payload_size,
        event->payload_buf_offset);
    if (blocks != nullptr) {
        auto exec_flow_info =
            std::bit_cast<monad_exec_flow_info>(event->user[0]);
        if (uint16_t const block_flow_id = exec_flow_info.block_flow_id) {
            monad_exec_block_header const &b = blocks[block_flow_id];
            o = std::format_to(o, " BLK: {}", b.exec_input.number);
        }
        if (uint32_t const id = exec_flow_info.txn_id) {
            o = std::format_to(o, " TXN: {}", id - 1);
        }
    }
    *o++ = '\n';
    std::fwrite(event_buf, static_cast<size_t>(o - event_buf), 1, out);

    if (hexdump_payload) {
        hexdump_event_payload(iter, event, out);
    }
    if (decode_payload && blocks != nullptr) {
        fmt::memory_buffer mb;
        std::back_insert_iterator o{mb};

        auto const *const payload_base = monad_event_payload_peek(iter, event);
        auto const event_type =
            static_cast<monad_exec_event_type>(event->event_type);
        o = monad::format_as(o, payload_base, event_type);
        if (monad_event_payload_check(iter, event)) {
            *o++ = '\n';
            std::fwrite(data(mb), size(mb), 1, out);
        }
        else {
            std::fprintf(
                stderr, "ERROR: event %lu payload lost!\n", event->seqno);
        }
    }
}

// The "follow thread" behaves like `tail -f`: it pulls events from the ring
// and writes them to a std::FILE* as fast as possible
static void follow_thread_main(
    std::span<mapped_event_ring const> mapped_event_rings, bool hexdump_payload,
    bool decode_payload, std::FILE *out)
{
    monad_event_descriptor event;
    monad_event_iterator *iter_bufs = static_cast<monad_event_iterator *>(
        alloca(sizeof(monad_event_iterator) * size(mapped_event_rings)));
    std::span<monad_event_iterator> const iters =
        std::span{iter_bufs, size(mapped_event_rings)};
    size_t not_ready_count = 0;

    for (size_t i = 0; mapped_event_ring const &mr : mapped_event_rings) {
        monad_event_ring_init_iterator(&mr.event_ring, &iters[i++]);
        if (mr.start_seqno) {
            iters.back().read_last_seqno = *mr.start_seqno;
        }
    }
    while (g_should_exit == 0) {
        for (size_t i = 0; auto &iter : iters) {
            mapped_event_ring const &mr = mapped_event_rings[i++];
            auto const event_metadata = mr.metadata_entries;
            switch (monad_event_iterator_try_next(&iter, &event)) {
            case MONAD_EVENT_NOT_READY:
                if ((not_ready_count++ & ((1U << 20) - 1)) == 0) {
                    std::fflush(out);
                    if (event_ring_is_abandoned(mr.ring_fd)) {
                        g_should_exit = 1;
                    }
                }
                continue; // Nothing produced yet

            case MONAD_EVENT_GAP:
                std::fprintf(
                    stderr,
                    "ERROR: event gap from %lu -> %lu, resetting\n",
                    iter.read_last_seqno,
                    __atomic_load_n(
                        &iter.control->last_seqno, __ATOMIC_ACQUIRE));
                monad_event_iterator_reset(&iter);
                not_ready_count = 0;
                continue;

            case MONAD_EVENT_SUCCESS:
                not_ready_count = 0;
                break; // Handled in the main loop body
            }
            print_event(
                &iter,
                &event,
                event_metadata,
                mr.blocks,
                hexdump_payload,
                decode_payload,
                out);
        }
    }
}

static void kill_thread_main(
    mapped_event_ring const &mr, uint64_t kill_seqno, std::vector<int> pidfds)
{
    monad_event_descriptor event;
    monad_event_iterator iter;
    size_t not_ready_count = 0;

    monad_event_ring_init_iterator(&mr.event_ring, &iter);
    while (g_should_exit == 0 && iter.read_last_seqno < kill_seqno) {
        switch (monad_event_iterator_try_next(&iter, &event)) {
        case MONAD_EVENT_NOT_READY:
            if ((not_ready_count++ & ((1U << 20) - 1)) == 0) {
                if (all_writers_have_exited(pidfds)) {
                    g_should_exit = 1;
                }
            }
            break;

        case MONAD_EVENT_GAP:
            std::fprintf(
                stderr,
                "ERROR: event gap from %lu -> %lu, resetting\n",
                iter.read_last_seqno,
                __atomic_load_n(&iter.control->last_seqno, __ATOMIC_ACQUIRE));
            monad_event_iterator_reset(&iter);
            not_ready_count = 0;
            break;

        case MONAD_EVENT_SUCCESS:
            not_ready_count = 0;
            break;
        }
    }
    for (int fd : pidfds) {
        long const rc = syscall(SYS_pidfd_send_signal, fd, SIGINT, nullptr, 0);
        if (rc == -1) {
            warnx("pidfd_send_signal failed for %d", fd);
        }
    }
    if (iter.read_last_seqno == kill_seqno) {
        std::fprintf(
            stderr,
            "saw seqno: %lu, sent signal %d to %lu pids\n",
            iter.read_last_seqno,
            SIGINT,
            size(pidfds));
    }
    else {
        errx(
            EX_SOFTWARE,
            "signaled to exit before seeing seqno %lu",
            kill_seqno);
    }

    // Now that the event ring is not being written to, traverse it again,
    // computing the SHA256 hash of all the events until the kill sequence
    // number
    iter.read_last_seqno = 0;
    EVP_MD_CTX *const hash_ctx = EVP_MD_CTX_create();
    if (hash_ctx == nullptr) {
        ERR_print_errors_fp(stderr);
        errx(EX_SOFTWARE, "EVP_MD_CTX_create failed");
    }
    EVP_MD const *const sha256_md = EVP_sha256();
    if (EVP_DigestInit_ex(hash_ctx, sha256_md, nullptr) != 1) {
        ERR_print_errors_fp(stderr);
        errx(EX_SOFTWARE, "EVP_DigestInit_ex failed");
    }
    while (iter.read_last_seqno < kill_seqno) {
        auto const nr = monad_event_iterator_try_next(&iter, &event);
        MONAD_ASSERT(nr == MONAD_EVENT_SUCCESS);
        EVP_DigestUpdate(hash_ctx, &event, sizeof event);
        EVP_DigestUpdate(
            hash_ctx,
            monad_event_payload_peek(&iter, &event),
            event.payload_size);
    }
    uint8_t event_digest[32];
    EVP_DigestFinal_ex(hash_ctx, event_digest, nullptr);
    EVP_MD_CTX_destroy(hash_ctx);

    // It can take a long time for the daemon to finish running its graceful
    // cleanup routines upon receiving SIGINT. During this time, it can still
    // be record some final events; wait until the daemon is completely dead
    // before we write out the event ring file
    while (!all_writers_have_exited(pidfds))
        /* empty */;

    // mmap(2) the event ring file as a contiguous mapping, for write(2); we
    // do this because splice(2) and sendfile(2), don't appear to accept a
    // ring_fd backed by huge pages
    size_t const map_len =
        monad_event_ring_calc_storage(&mr.event_ring.header->size);
    auto *const map_base = std::bit_cast<std::byte const *>(
        mmap(nullptr, map_len, PROT_READ, MAP_SHARED, mr.ring_fd, 0));
    auto *const map_end = map_base + map_len;
    if (map_base == MAP_FAILED) {
        err(EX_OSERR, "mmap failed");
    }
    ssize_t n_write;
    auto *map_next = map_base;
    do {
        n_write = write(
            STDOUT_FILENO, map_next, static_cast<size_t>(map_end - map_next));
        if (n_write > 0) {
            map_next += n_write;
        }
    }
    while (n_write > 0 && map_next != map_end);
    if (n_write == -1) {
        err(EX_OSERR, "dump of event ring file to STDOUT failed");
    }
    fmt::println(stderr, "{} bytes transferred", map_len);
    fmt::println(
        stderr, "SHA256 message digest: {:02x}", fmt::join(event_digest, ""));
    munmap(const_cast<std::byte *>(map_base), map_len);
}

int main(int argc, char **argv)
{
    std::thread follow_thread;
    std::thread kill_thread;
    bool print_header = false;
    bool follow = false;
    bool hexdump = false;
    bool decode = false;
    std::vector<std::string> event_ring_paths;
    std::optional<uint64_t> start_seqno;
    std::optional<uint64_t> kill_seqno;

    CLI::App cli{"monad event capture tool"};
    cli.add_flag("--header", print_header, "print event ring file header");
    cli.add_flag(
        "-f,--follow", follow, "stream events to stdout, as in tail -f");
    cli.add_flag("-H,--hex", hexdump, "hexdump event payloads in follow mode");
    cli.add_flag("-d,--decode", decode, "decode event payloads in follow mode");
    cli.add_option(
        "--start-seqno",
        start_seqno,
        "force the starting sequence number to a particular value (for debug)");
    cli.add_option(
        "-k,--kill",
        kill_seqno,
        "kill the writing process after this sequence number, and dump ring "
        "file contents to stdout");
    cli.add_option(
           "event-ring-path",
           event_ring_paths,
           "path to an event ring shared memory file")
        ->default_val(
            g_monad_event_ring_type_names[MONAD_EVENT_RING_TYPE_EXEC]);

    try {
        cli.parse(argc, argv);
    }
    catch (CLI::CallForHelp const &e) {
        std::exit(cli.exit(e));
    }
    catch (CLI::ParseError const &e) {
        std::exit(cli.exit(e));
    }

    std::vector<mapped_event_ring> mapped_event_rings;
    for (auto const &path : event_ring_paths) {
        mapped_event_ring &mr = mapped_event_rings.emplace_back();

        // The "path" might actually be a standard event ring name; if it maps
        // to a default path, we'll use that instead, otherwise we'll open(2) it
        if (auto const *p = get_default_path_for_event_ring_name(path)) {
            mr.origin_path = p;
        }
        else {
            mr.origin_path = path;
        }
        mr.ring_fd = open_event_ring_file_or_exit(mr.origin_path.c_str());

        bool fs_supports_hugetlb;
        if (monad_check_path_supports_map_hugetlb(
                mr.origin_path.c_str(), &fs_supports_hugetlb) != 0) {
            errx(
                EX_SOFTWARE,
                "event library error -- %s",
                monad_event_ring_get_last_error());
        }
        int const mmap_extra_flags =
            fs_supports_hugetlb ? MAP_POPULATE | MAP_HUGETLB : MAP_POPULATE;

        // Map this event ring into our address space
        if (monad_event_ring_mmap(
                &mr.event_ring,
                PROT_READ,
                mmap_extra_flags,
                mr.ring_fd,
                0,
                mr.origin_path.c_str()) != 0) {
            errx(
                EX_SOFTWARE,
                "event library error -- %s",
                monad_event_ring_get_last_error());
        }

        // Ensure it's safe to dereference `MetadataTable[ring_type]`
        monad_event_ring_type const ring_type = mr.event_ring.header->type;
        if (std::to_underlying(ring_type) >= std::size(MetadataTable)) {
            errx(
                EX_CONFIG,
                "do not have the metadata mapping for event ring `%s` type %hu",
                mr.origin_path.c_str(),
                ring_type);
        }

        // Get the metadata hash we're compiled with, or substitute the zero
        // hash if the command line told us to
        if (MetadataTable[ring_type].hash == nullptr) {
            errx(
                EX_CONFIG,
                "event ring `%s` has type %hu, but we don't know its metadata "
                "hash",
                mr.origin_path.c_str(),
                ring_type);
        }
        uint8_t const(&hash)[32] = *MetadataTable[ring_type].hash;

        // Unlike simpler tools, we should be able to work with any type
        if (monad_event_ring_check_type(&mr.event_ring, ring_type, hash) != 0) {
            errx(
                EX_SOFTWARE,
                "event library error -- %s",
                monad_event_ring_get_last_error());
        }
        mr.metadata_entries = MetadataTable[ring_type].entries;
        // TODO(ken): if we actually had more than one ring, we would need a
        //   way of specifying to set this on the right one. In practice it's
        //   only used for debugging tasks starting from zero.
        mr.start_seqno = start_seqno;
        mr.blocks = ring_type == MONAD_EVENT_RING_TYPE_EXEC
                        ? static_cast<monad_exec_block_header const *>(
                              mr.event_ring.context_area)
                        : nullptr;
        if (print_header) {
            print_event_ring_header(
                mr.origin_path.c_str(), mr.event_ring.header, stdout);
        }
    }

    // -k <seqno> will send SIGINT to all writer processes as soon as the given
    // sequence number is encountered, then dump the event ring file to stdout;
    // stdout is typically a pipe connected to zstd for compression. This is
    // used for creating event ring test case files, e.g.:
    //
    //    eventcap -k 10000 | zstd -19 > /tmp/ring_test_case.zst
    if (kill_seqno) {
        if (isatty(STDOUT_FILENO)) {
            errx(EX_USAGE, "--kill specified but stdout is a terminal");
        }
        if (size(mapped_event_rings) > 1) {
            errx(EX_USAGE, "--kill specified with multiple event ring inputs");
        }
        pid_t writer_pids[32];
        size_t n_pids = std::size(writer_pids);
        mapped_event_ring const &mr = mapped_event_rings[0];
        if (monad_event_ring_find_writer_pids(
                mr.ring_fd, writer_pids, &n_pids) != 0) {
            errx(
                EX_SOFTWARE,
                "event library error -- %s",
                monad_event_ring_get_last_error());
        }
        if (n_pids == 0) {
            errx(EX_SOFTWARE, "--kill specified but no attached processes");
        }
        std::vector<int> pidfds;
        for (pid_t p : std::span{writer_pids, n_pids}) {
            long const fd = syscall(SYS_pidfd_open, p, 0);
            if (fd == -1) {
                errx(EX_OSERR, "pidfd_open failed for pid %d", p);
            }
            pidfds.push_back(static_cast<int>(fd));
        }
        kill_thread = std::thread{kill_thread_main, mr, *kill_seqno, pidfds};
    }

    if (follow) {
        follow_thread = std::thread{
            follow_thread_main,
            std::span{mapped_event_rings},
            hexdump,
            decode,
            stdout};
    }

    if (kill_thread.joinable()) {
        kill_thread.join();
    }
    if (follow_thread.joinable()) {
        follow_thread.join();
    }

    for (auto &mr : mapped_event_rings) {
        monad_event_ring_unmap(&mr.event_ring);
        (void)close(mr.ring_fd);
    }
    return 0;
}
