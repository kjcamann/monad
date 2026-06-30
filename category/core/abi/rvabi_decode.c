#include <alloca.h>
#include <stdarg.h>
#include <stddef.h>

#include <category/core/abi/abi.h>
#include <category/core/abi/error.h>
#include <category/core/abi/rvabi_decode.h>
#include <category/core/byteview.h>

monad_abi_err_t monad_rvabi_unpack_valist(
    struct monad_bv bytes, size_t count, struct monad_bv *resid, va_list ap)
{
    struct monad_abi_output *outputs =
        (struct monad_abi_output *)alloca(count * sizeof *outputs);
    for (size_t i = 0; i < count; ++i) {
        struct monad_abi_output *const outbuf = &outputs[i];

        outbuf->type = va_arg(ap, monad_abi_type_t);
        switch (outbuf->type) {
        case MONAD_ABI_TYPE_ADDRESS:
            outbuf->ptr.view = va_arg(ap, void const **);
            break;

        case MONAD_ABI_TYPE_UINT_HE:
            outbuf->ptr.view = va_arg(ap, void const **);
            outbuf->size = va_arg(ap, size_t);
            break;

        case MONAD_ABI_TYPE_BOOL:
            [[fallthrough]];
        case MONAD_ABI_TYPE_STRING:
            [[fallthrough]];
        case MONAD_ABI_TYPE_BYTES:
            outbuf->ptr.buf = va_arg(ap, void *);
            break;

        case MONAD_ABI_TYPE_UINT_BE:
            [[fallthrough]];
        case MONAD_ABI_TYPE_DYNAMIC_TUPLE:
            [[fallthrough]];
        case MONAD_ABI_TYPE_DYNAMIC_ARRAY:
            return MONAD_ABIERR_ILLEGAL_ABI_TYPE;

        default:
            return MONAD_ABIERR_UNKNOWN_ABI_TYPE;
        }
    }

    return monad_rvabi_unpack(bytes, outputs, count, resid);
}
