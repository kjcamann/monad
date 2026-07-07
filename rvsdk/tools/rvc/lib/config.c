#include <errno.h>
#include <stdarg.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <alloca.h>
#include <fcntl.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <unistd.h>

#include <ucl.h>

#include <category/core/address.h>
#include <category/core/assert.h>
#include <category/core/byteview.h>
#include <category/core/srcloc.h>

#include "rvc_impl.h"

thread_local static char s_parse_err_buf[4096];
thread_local static char s_path_buf[1024];

struct parse_ctx
{
    struct rvc_log_interface const *log_if;
    void *log_ctx;
    ucl_object_t const *err_obj;
    struct parse_ctx const *prev;
};

struct parse_ctx push_parse_ctx(struct parse_ctx const *const prev)
{
    return (struct parse_ctx){
        .log_if = prev->log_if,
        .log_ctx = prev->log_ctx,
        .err_obj = nullptr,
        .prev = prev,
    };
}

static char const *
format_reversed_path(char const **const path_names, size_t path_length)
{
    char *p = s_path_buf;
    char const *const path_buf_end = s_path_buf + sizeof s_path_buf;

    for (size_t i = path_length; i-- > 0;) {
        char const *const path_segment = path_names[i];
        size_t const path_segment_len = strlen(path_segment);
        size_t const required = path_segment_len + (p != s_path_buf ? 1 : 0);

        if (required >= (size_t)(path_buf_end - p)) {
            break; // Overflow will truncate; this is for logging so don't care
        }
        if (p != s_path_buf) {
            *p++ = '.';
        }
        p = mempcpy(p, path_segment, path_segment_len);
    }
    *p = '\0';
    return s_path_buf;
}

// Write a log entry about a parse event, including the path in the
// configuration document to where this log occurred, in dot notation
static int write_parse_log(
    struct parse_ctx const ctx, unsigned level,
    monad_source_location_t const *srcloc, int err, char const *format, ...)
{
    struct parse_ctx const *path_walk;
    size_t path_length;
    va_list ap;
    int rc;
    char const **path_names;

    if (ctx.log_if == nullptr) {
        return err;
    }
    MONAD_ASSERT(level <= LOG_DEBUG);
    if (level > ctx.log_if->max_level(ctx.log_ctx)) {
        return err;
    }
    va_start(ap, format);
    rc = vsnprintf(s_parse_err_buf, sizeof s_parse_err_buf, format, ap);
    MONAD_ASSERT(rc >= 0);
    va_end(ap);

    // Walk the path backwards to the root, via the links formed in each parse
    // context; we'll do this once to count the path length, then alloca(3)
    // space to hold the `const char **path_names`, then walk again to capture
    // those names
    path_walk = &ctx;
    path_length = 0;
    while (path_walk->prev != nullptr) {
        ++path_length;
        path_walk = path_walk->prev;
    }
    if (path_length == 0) {
        // The error is at the root node
        return write_log(
            ctx.log_if,
            ctx.log_ctx,
            level,
            srcloc,
            err,
            "%s [path: <root>]",
            s_parse_err_buf);
    }
    path_names = (char const **)alloca(path_length * sizeof(char const *));

    path_walk = &ctx;
    for (size_t i = 0; path_walk->prev != nullptr;
         path_walk = path_walk->prev) {
        char const *const path_segment = ucl_object_key(path_walk->err_obj);
        path_names[i++] = path_segment != nullptr ? path_segment : "<unnamed>";
    }

    return write_log(
        ctx.log_if,
        ctx.log_ctx,
        level,
        srcloc,
        err,
        "%s [path: %s]",
        s_parse_err_buf,
        format_reversed_path(path_names, path_length));
}

#define WRITE_PARSE_LOG(CTX, LEVEL, ...)                                       \
    write_parse_log(                                                           \
        (CTX), (LEVEL), &MONAD_SOURCE_LOCATION_CURRENT(), __VA_ARGS__)

#define PARSE_ERR(...) WRITE_PARSE_LOG(ctx, LOG_ERR, __VA_ARGS__)
#define PARSE_ERRX(...) WRITE_PARSE_LOG(ctx, LOG_ERR, 0, __VA_ARGS__)

#define PARSE_ERRX_P(...) WRITE_PARSE_LOG(*ctx, LOG_ERR, 0, __VA_ARGS__)

enum expect_flags
{
    EF_DEFAULT = 0,
    EF_REQUIRED = 0x1,
    EF_ALLOW_ARRAY = 0x2,
    EF_ANY_TYPE = 0x4,
};

static int expect_object_key(
    ucl_object_t const **obj_p, struct parse_ctx *const ctx,
    ucl_object_t const *const parent, char const *const key,
    ucl_type_t const expected_type, unsigned const flags)
{
    ucl_type_t obj_type;
    ucl_object_t const *obj;
    bool skip_type_check;

    *obj_p = nullptr;
    ctx->err_obj = obj = ucl_object_lookup(parent, key);
    if (obj == nullptr) {
        if (flags & EF_REQUIRED) {
            PARSE_ERRX_P("object is missing required key `%s`", key);
            return EINVAL;
        }
        return 0;
    }
    obj_type = ucl_object_type(obj);
    skip_type_check =
        flags & EF_ANY_TYPE || obj_type == UCL_ARRAY && flags & EF_ALLOW_ARRAY;
    if (obj_type != expected_type && !skip_type_check) {
        PARSE_ERRX_P(
            "expected object to have type %s, found %s",
            ucl_object_type_to_string(expected_type),
            ucl_object_type_to_string(obj_type));
        return EINVAL;
    }
    *obj_p = obj;
    return 0;
}

static int expect_object_type(
    struct parse_ctx const ctx, ucl_object_t const *obj,
    ucl_type_t const expected_type, unsigned const flags)
{
    ucl_type_t const obj_type = ucl_object_type(obj);
    bool const skip_type_check =
        obj_type == UCL_ARRAY && flags & EF_ALLOW_ARRAY;
    if (obj_type != expected_type && !skip_type_check) {
        PARSE_ERRX(
            "expected object to have type %s, found %s",
            ucl_object_type_to_string(expected_type),
            ucl_object_type_to_string(obj_type));
        return EINVAL;
    }
    return 0;
}

#if 0
static int expect_array_elt(
    ucl_object_t const **elt_p, struct parse_ctx *const ctx,
    ucl_object_t const *const array, size_t const i,
    ucl_type_t const expected_type, unsigned const flags)
{
    ucl_type_t elt_type;
    ucl_object_t const *elt;
    bool skip_type_check;

    *elt_p = nullptr;
    ctx->err_obj = elt = ucl_array_find_index(array, i);
    if (elt == nullptr) {
        if (flags & EF_REQUIRED) {
            PARSE_ERRX_P(
                "expected array `%s` to have item at index %zu, but max is %zu",
                ucl_object_key(array),
                i,
                ucl_array_size(array));
            return EINVAL;
        }
        return 0;
    }
    elt_type = ucl_object_type(elt);
    skip_type_check =
        flags & EF_ANY_TYPE || elt_type == UCL_ARRAY && flags & EF_ALLOW_ARRAY;
    if (elt_type != expected_type && !skip_type_check) {
        PARSE_ERRX_P(
            "expected array `%s` element %zu to have type %s, found %s",
            ucl_object_key(array),
            i,
            ucl_object_type_to_string(expected_type),
            ucl_object_type_to_string(elt_type));
        return EINVAL;
    }
    *elt_p = elt;
    return 0;
}
#endif

static int parse_monad_address_key(
    struct monad_address *const addr, struct parse_ctx const ctx,
    ucl_object_t const *const obj_with_addr_key)
{
    char const *bytes;
    size_t len;
    int rc;

    bytes = ucl_object_keyl(obj_with_addr_key, &len);
    rc = monad_address_from_hex(bytes, len, addr);
    if (rc != 0) {
        PARSE_ERR(rc, "could not parse object key as monad_address");
    }
    return rc;
}

static int mmap_system_archive(
    struct parse_ctx ctx, char const *const path, struct monad_bv *mapping)
{
    struct stat tar_stat;
    int tar_fd;
    void *map_base;

    tar_fd = open(path, O_RDONLY);
    if (tar_fd == -1) {
        return PARSE_ERR(
            errno, "open(2) of system archive file `%s` failed", path);
    }
    if (fstat(tar_fd, &tar_stat) != 0) {
        return PARSE_ERR(
            errno, "fstat(2) on system archive file `%s` failed", path);
    }
    map_base = mmap(
        nullptr, (size_t)tar_stat.st_size, PROT_READ, MAP_SHARED, tar_fd, 0);
    if (map_base == MAP_FAILED) {
        return PARSE_ERR(
            errno, "mmap(2) of system archive file `%s` failed", path);
    }
    (void)close(tar_fd);
    *mapping = monad_bv_from_size(map_base, (size_t)tar_stat.st_size);
    return 0;
}

// "code_cache_size_shift" = <path-string>;
static int parse_int64(
    struct monad_rv_vm_config *const conf, struct parse_ctx *prev_ctx,
    ucl_object_t const *const obj_parent, char const *key, int64_t min_value,
    int64_t max_value, int64_t *value, bool *found)
{
    int rc;
    ucl_object_t const *obj_int;
    struct parse_ctx ctx = push_parse_ctx(prev_ctx);

    rc =
        expect_object_key(&obj_int, &ctx, obj_parent, key, UCL_INT, EF_DEFAULT);
    if (rc != 0 || obj_int == nullptr) {
        if (found != nullptr) {
            *found = false;
        }
        return rc; // Error or no key present
    }
    *value = ucl_object_toint(obj_int);
    if (*value < min_value || *value > max_value) {
        return PARSE_ERR(
            ERANGE,
            "%s %ld outside of allowed range [%ld, %ld]",
            key,
            *value,
            min_value,
            max_value);
    }
    if (found != nullptr) {
        *found = true;
    }
    return 0;
}

// "system_archive" = <path-string>;
static int parse_system_archive(
    struct monad_rv_vm_config *const conf, struct parse_ctx *prev_ctx,
    ucl_object_t const *const obj_riscv_vm)
{
    int rc;
    ucl_object_t const *obj_system_archive;
    struct parse_ctx ctx = push_parse_ctx(prev_ctx);

    rc = expect_object_key(
        &obj_system_archive,
        &ctx,
        obj_riscv_vm,
        "system_archive",
        UCL_STRING,
        EF_DEFAULT);
    if (rc != 0 || obj_system_archive == nullptr) {
        return rc; // Error or no system_archive key present
    }
    return mmap_system_archive(
        ctx, ucl_object_tostring(obj_system_archive), &conf->sys_archive);
}

// Parse the top-level `riscv_vm` object
static int parse_riscv_vm_config(
    struct monad_rv_vm_config *const conf, struct parse_ctx const *prev_ctx,
    ucl_object_t const *const root)
{
    int rc;
    int64_t raw_int;
    bool found;
    ucl_object_t const *obj_riscv_vm;
    struct parse_ctx ctx = push_parse_ctx(prev_ctx);

    rc = expect_object_key(
        &obj_riscv_vm, &ctx, root, "riscv_vm", UCL_OBJECT, EF_DEFAULT);
    if (rc != 0 || obj_riscv_vm == nullptr) {
        return rc; // Error or no riscv_vm section present
    }

    // code_cache_size_shift
    rc = parse_int64(
        conf,
        &ctx,
        obj_riscv_vm,
        "code_cache_size_shift",
        0,
        31,
        &raw_int,
        &found);
    if (rc != 0) {
        return rc;
    }
    if (found) {
        conf->code_cache_size_shift = (uint8_t)raw_int;
    }

    // vm_ctx_count_shift
    rc = parse_int64(
        conf,
        &ctx,
        obj_riscv_vm,
        "ctx_pool_size_shift",
        0,
        31,
        &raw_int,
        &found);
    if (rc != 0) {
        return rc;
    }
    if (found) {
        conf->ctx_pool_size_shift = (uint8_t)raw_int;
    }

    return parse_system_archive(conf, &ctx, obj_riscv_vm);
}

static int parse_dso_override(
    struct host_exec_config *const conf, struct parse_ctx const *prev_ctx,
    ucl_object_t const *const obj_dso_override)
{
    int rc;
    struct monad_address addr;
    struct dso_override *override;
    struct parse_ctx ctx = push_parse_ctx(prev_ctx);

    ctx.err_obj = obj_dso_override;
    rc = parse_monad_address_key(&addr, ctx, obj_dso_override);
    if (rc != 0) {
        return rc;
    }
    rc = expect_object_type(ctx, obj_dso_override, UCL_STRING, EF_DEFAULT);
    if (rc != 0) {
        return rc;
    }
    override = realloc(
        conf->dso_overrides,
        sizeof(struct dso_override) * (conf->dso_override_count + 1));
    if (override == nullptr) {
        return PARSE_ERR(
            errno,
            "realloc(3) of dso_overrides to %zu failed",
            conf->dso_override_count + 1);
    }
    conf->dso_overrides = override;
    override = &conf->dso_overrides[conf->dso_override_count++];
    override->addr = addr;
    override->dso_path = strdup(ucl_object_tostring(obj_dso_override));
    return 0;
}

// dso_overrides { [<contract-addr> = <dso-path>]* }
static int parse_dso_overrides_section(
    struct host_exec_config *const conf, struct parse_ctx const *prev_ctx,
    ucl_object_t const *const obj_host_exec)
{
    int rc;
    ucl_object_t const *obj_dso_overrides;
    ucl_object_t const *obj_override;
    ucl_object_iter_t iter_overrides = nullptr;
    struct parse_ctx ctx = push_parse_ctx(prev_ctx);

    rc = expect_object_key(
        &obj_dso_overrides,
        &ctx,
        obj_host_exec,
        "dso_overrides",
        UCL_OBJECT,
        EF_DEFAULT);
    if (rc != 0) {
        return rc;
    }
    while ((obj_override = ucl_iterate_object(
                obj_dso_overrides, &iter_overrides, /*expand_values=*/true)) !=
           nullptr) {
        rc = parse_dso_override(conf, &ctx, obj_override);
        if (rc != 0) {
            return rc;
        }
    }
    return 0;
}

// Parse the top-level `host_exec` object
static int parse_host_exec(
    struct host_exec_config *const conf, struct parse_ctx const *const prev_ctx,
    ucl_object_t const *const root)
{
    int rc;
    ucl_object_t const *obj_host_exec;
    struct parse_ctx ctx = push_parse_ctx(prev_ctx);

    rc = expect_object_key(
        &obj_host_exec, &ctx, root, "host_exec", UCL_OBJECT, EF_DEFAULT);
    if (rc != 0 || obj_host_exec == nullptr) {
        return rc; // Error or no host_exec section present
    }

    rc = parse_dso_overrides_section(conf, prev_ctx, obj_host_exec);
    if (rc != 0) {
        return rc;
    }

    return 0;
}

static int parse_top_level(
    struct rvc_config *const conf, ucl_object_t const *const root,
    struct rvc_log_interface const *log_if, void *log_ctx)
{
    int rc;
    struct parse_ctx const ctx = {log_if, log_ctx, root, nullptr};

    rc = parse_riscv_vm_config(&conf->riscv_vm_config, &ctx, root);
    if (rc != 0) {
        return rc;
    }
    return parse_host_exec(&conf->host_exec_config, &ctx, root);
}

int rvc_config_parse(
    struct rvc_config *const conf, char const *const ucl_config,
    struct rvc_log_interface const *const log_if, void *const log_ctx)
{
    int rc;
    ucl_object_t *root;
    struct ucl_parser *parser;

    memset(conf, 0, sizeof *conf);
    parser = ucl_parser_new(UCL_PARSER_KEY_LOWERCASE);
    if (parser == nullptr) {
        return WRITE_LOG(
            log_if, log_ctx, LOG_ERR, errno, "ucl_parser_new failed");
    }
    if (!ucl_parser_add_string(parser, ucl_config, 0)) {
        WRITE_LOG(
            log_if,
            log_ctx,
            LOG_ERR,
            0,
            "error in ucl_parser_add_string: %s",
            ucl_parser_get_error(parser));
        ucl_parser_free(parser);
        return EINVAL;
    }
    root = ucl_parser_get_object(parser);
    rc = parse_top_level(conf, root, log_if, log_ctx);
    ucl_object_unref(root);
    ucl_parser_free(parser);
    return rc;
}

void rvc_config_free(struct rvc_config *const conf)
{
    munmap(
        (void *)conf->riscv_vm_config.sys_archive.begin,
        monad_bv_len(conf->riscv_vm_config.sys_archive));

    for (size_t i = 0; i < conf->host_exec_config.dso_override_count; ++i) {
        struct dso_override *const override =
            &conf->host_exec_config.dso_overrides[i];
        free((void *) override->dso_path);
    }
    free(conf->host_exec_config.dso_overrides);
}
