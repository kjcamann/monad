#include <errno.h>
#include <fcntl.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include <sys/mman.h>

#include <monad-c/support/mapped_file.h>
#include <monad-c/support/result.h>

monad_result mcl_map_file(const char *file_path,
                          const struct mcl_mmap_params *params,
                          int extra_flags,
                          struct mcl_file_mapping *fm)
{
    mode_t mode = 0;
    monad_result mr;
    int fd;

    if (file_path == nullptr || fm == nullptr)
        return monad_make_sys_error(EFAULT);

    if (params->prot == PROT_READ)
        mode = O_RDONLY;
    else if (params->prot == PROT_WRITE)
        mode = O_WRONLY;
    else
        mode = O_RDWR;

    fd = open(file_path, mode);
    if (fd == -1)
        return monad_make_sys_error(errno);
    mr = mcl_map_fd(fd, params, extra_flags, fm);
    if (monad_is_error(mr))
        return mr;
    fm->file_path = strdup(file_path);
    return mr;
}

monad_result mcl_map_fd(int fd, const struct mcl_mmap_params *params,
                        int extra_flags, struct mcl_file_mapping *fm) {
    int saved_errno;

    if (params == nullptr || fm == nullptr)
        return monad_make_sys_error(EFAULT);
    if (extra_flags & MCL_MAP_ENTIRE_FILE && extra_flags & MCL_MAP_NO_STAT)
        return monad_make_sys_error(EINVAL);
    if (fd < 0)
        return monad_make_sys_error(EINVAL);

    fm->map_length = 0;
    fm->fd = fd;

    if (!(extra_flags & MCL_MAP_NO_STAT)) {
        if (fstat(fm->fd, &fm->map_stat) == -1)
            goto Error;
        if (extra_flags & MCL_MAP_ENTIRE_FILE)
            fm->map_length = fm->map_stat.st_size;
    }

    fm->map_base = mmap(params->addr, fm->map_length, params->prot,
                        params->flags, fm->fd, params->offset);
    if (fm->map_base == MAP_FAILED)
        goto Error;

    if (!(extra_flags & MCL_MAP_NO_CLOSE_FD)) {
        (void)close(fm->fd);
        fm->fd = -1;
    }
    return monad_ok(fm->map_length);

Error:
    saved_errno = errno;
    if (!(extra_flags & MCL_MAP_NO_CLOSE_FD))
        (void)close(fm->fd);
    return monad_make_sys_error(saved_errno);
}

monad_result mcl_unmap_file(struct mcl_file_mapping *fm) {
    if (fm == nullptr)
        return monad_make_sys_error(EFAULT);
    if (fm->file_path)
        free((void *)fm->file_path);
    if (munmap(fm->map_base, fm->map_length) == -1)
        return monad_make_sys_error(errno);
    if (fm->fd != -1)
        (void)close(fm->fd);
    return monad_ok(0);
}