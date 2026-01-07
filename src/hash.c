#include "hash.h"
#include <openssl/evp.h>

void sha256(const uint8_t *msg, size_t len, uint8_t out[HASH_LEN]) {
    EVP_MD_CTX *ctx = EVP_MD_CTX_new();
    EVP_DigestInit_ex(ctx, EVP_sha256(), NULL);
    EVP_DigestUpdate(ctx, msg, len);
    EVP_DigestFinal_ex(ctx, out, NULL);
    EVP_MD_CTX_free(ctx);
}
