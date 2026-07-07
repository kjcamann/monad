#include <stddef.h>
#include <stdint.h>

#include <openssl/evp.h>
#include <pthread.h>

#include <category/core/assert.h>
#include <category/core/keccak.h>

static EVP_MD *s_keccak256_md = nullptr;
static pthread_once_t s_keccak256_once = PTHREAD_ONCE_INIT;

static void keccak256_init()
{
    s_keccak256_md = EVP_MD_fetch(nullptr, "KECCAK-256", nullptr);
    MONAD_ASSERT(s_keccak256_md != nullptr);
}

void keccak256(
    void const *const in, size_t const len, uint8_t out[KECCAK256_SIZE])
{
    pthread_once(&s_keccak256_once, keccak256_init);

    EVP_MD_CTX *ctx = EVP_MD_CTX_new();
    EVP_DigestInit_ex2(ctx, s_keccak256_md, nullptr);
    EVP_DigestUpdate(ctx, in, len);
    EVP_DigestFinal_ex(ctx, out, nullptr);
    EVP_MD_CTX_free(ctx);
}
