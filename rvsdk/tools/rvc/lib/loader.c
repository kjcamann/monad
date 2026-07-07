#include <stdarg.h>
#include <stddef.h>
#include <string.h>

#include <dlfcn.h>

#include <rvc/loader.h>
#include <rvc/rvc.h>

thread_local static char s_error_buf[1024];

constexpr char CREATE_SYMBOL[] = "rvc_vm_create";

static void *set_loader_error(
    enum rvc_loader_error_code *const err_p, enum rvc_loader_error_code code,
    char const *format, ...)
{
    va_list ap;

    va_start(ap, format);
    vsnprintf(s_error_buf, sizeof s_error_buf, format, ap);
    va_end(ap);
    if (err_p != nullptr) {
        *err_p = code;
    }
    return nullptr;
}

struct rvc_vm *rvc_load_and_configure(
    char const *const config, struct rvc_log_interface const *log_if,
    void *const log_ctx, enum rvc_loader_error_code *const err, void **dso_out)
{
    struct rvc_vm *vm;
    rvc_vm_create_fn *create_func;
    char const *ucl_config;
    char dso_pathbuf[1024];
    size_t dso_end;
    void *dso;

    if (dso_out != nullptr) {
        *dso_out = nullptr;
    }

    // Everything up until the first ',' or ';' character is the path to the
    // shared library
    dso_end = strcspn(config, ",;");

    // Copy just the shared library name into its own buffer and null terminate
    // it, for dlopen(3)
    if (dso_end >= sizeof dso_pathbuf) {
        return set_loader_error(
            err,
            RVC_LOADER_DSO_PATH_TOO_LONG,
            "dso path has length %zu, buffer is %zu",
            dso_end,
            sizeof dso_pathbuf);
    }
    *stpncpy(dso_pathbuf, config, dso_end) = '\0';

    // If anything follows the first ',' or ';' character, it's a UCL-style
    // configuration string, skip over the separator character and point
    // directly at it, otherwise point at the null character
    ucl_config =
        config[dso_end] != '\0' ? config + dso_end + 1 : config + dso_end;

    // Open the shared library and find the address of the
    // create function
    dso = dlopen(dso_pathbuf, RTLD_LAZY | RTLD_GLOBAL);
    if (dso == nullptr) {
        return set_loader_error(
            err,
            RVC_LOADER_NO_SHARED_LIBRARY,
            "dlopen(3) failed: %s",
            dlerror());
    }
    if (dso_out != nullptr) {
        *dso_out = dso;
    }
    create_func = (rvc_vm_create_fn *)dlsym(dso, CREATE_SYMBOL);
    if (create_func == nullptr) {
        set_loader_error(
            err,
            RVC_LOADER_MISSING_CREATE_FN,
            "shared library `%s` did not contain VM constructor "
            "symbol `%s`",
            dso_pathbuf,
            CREATE_SYMBOL);
        goto CloseLibraryAndExit;
    }

    // Create the VM
    vm = (*create_func)(ucl_config, log_if, log_ctx);
    if (vm == nullptr) {
        set_loader_error(
            err,
            RVC_LOADER_CREATE_FAILED,
            "VM create function %s returned nullptr",
            CREATE_SYMBOL);
        goto CloseLibraryAndExit;
    }
    if (err != nullptr) {
        *err = RVC_LOADER_SUCCESS;
    }
    return vm;

CloseLibraryAndExit:
    // We failed to create the VM; drop the reference we took on the shared
    // object
    (void)dlclose(dso);
    if (dso_out != nullptr) {
        *dso_out = nullptr;
    }
    return nullptr;
}

char const *rvc_describe_last_loader_error()
{
    return s_error_buf;
}
