#pragma once

#include <stddef.h>
#include <sys/stat.h>
#include <sys/types.h> // For off_t
#include <monad-c/support/result.h>

#ifdef __cplusplus
extern "C" {
#endif

/// Parameters passed to mmap(2) when @ref mcl_map_file is called
struct mcl_mmap_params {
    void *addr;
    size_t length;
    int prot;
    int flags;
    off_t offset;
};

/// Behavior flags passed to the @ref mcl_map_file routine in the extra_flags
/// parameter
enum mcl_extra_map_flags : int {
    MCL_MAP_ENTIRE_FILE = 0b001, ///< Ignore length, use st_size from stat(2)
    MCL_MAP_NO_CLOSE_FD = 0b010, ///< Don't close file descriptor after mmap(2)
    MCL_MAP_NO_STAT = 0b100,     ///< Don't stat(2); can't use MMF_ENTIRE_FILE
};

/// Info about the mapped file opened with @ref mcl_map_file. Call
/// @ref mcl_unmap_file, to remove the mapping.
struct mcl_file_mapping {
    const char *file_path; ///< Path originally opened
    struct stat map_stat;  ///< stat of mapped file
    int fd;                ///< fd of mapped file; -1 unless MMF_NO_CLOSE_FD
    void *map_base;        ///< Base address of mapping, if successful
    size_t map_length;     ///< Length of mapping (as passed, not page rounded)
};

/// Convenience function to call open(2), stat(2), and mmap(2) as a single
/// operation.
monad_result mcl_map_file(const char *file_path,
                          const struct mcl_mmap_params *params,
                          int extra_flags,
                          struct mcl_file_mapping *fm);

/// Convenience function to call stat(2) and mmap(2) as a single operation.
monad_result mcl_map_fd(int fd, const struct mcl_mmap_params *params,
                        int extra_flags, struct mcl_file_mapping *fm);

/// Removes the mapping created by @ref mcl_map_file
monad_result mcl_unmap_file(struct mcl_file_mapping *fm);

#ifdef __cplusplus
} // extern "C"
#endif