#pragma once

#include <rvc/log.h>

struct rvc_vm;

enum rvc_loader_error_code
{
    RVC_LOADER_SUCCESS,
    RVC_LOADER_DSO_PATH_TOO_LONG,
    RVC_LOADER_NO_SHARED_LIBRARY,
    RVC_LOADER_MISSING_CREATE_FN,
    RVC_LOADER_CREATE_FAILED,
};

struct rvc_vm *rvc_load_and_configure(
    char const *config, struct rvc_log_interface const *, void *log_ctx,
    enum rvc_loader_error_code *err, void **dso_out);

char const *rvc_describe_last_loader_error();
