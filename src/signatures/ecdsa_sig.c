#include <openssl/evp.h>
#include <openssl/ec.h>
#include <stdlib.h>
#include <openssl/x509.h>


static EVP_PKEY *g_ecdsa_key = NULL;

int ecdsa_keygen(void)
{
    EVP_PKEY_CTX *ctx = EVP_PKEY_CTX_new_id(EVP_PKEY_EC, NULL);
    if (!ctx) return 0;
    EVP_PKEY_keygen_init(ctx);
    EVP_PKEY_CTX_set_ec_paramgen_curve_nid(ctx, NID_X9_62_prime256v1);
    EVP_PKEY_keygen(ctx, &g_ecdsa_key);
    EVP_PKEY_CTX_free(ctx);
    return 1;
}

int ecdsa_sign(const uint8_t *msg, size_t msg_len, uint8_t **sig, size_t *sig_len)
{
    EVP_MD_CTX *ctx = EVP_MD_CTX_new();
    EVP_DigestSignInit(ctx, NULL, EVP_sha256(), NULL, g_ecdsa_key);
    EVP_DigestSign(ctx, NULL, sig_len, msg, msg_len);
    *sig = malloc(*sig_len);
    EVP_DigestSign(ctx, *sig, sig_len, msg, msg_len);
    EVP_MD_CTX_free(ctx);
    return 1;
}

int ecdsa_verify(const uint8_t *hash, size_t hash_len, const uint8_t *sig, size_t sig_len, const uint8_t *pubkey, size_t pubkey_len)
{
    const uint8_t *p = pubkey;
    EVP_PKEY *pk = d2i_PUBKEY(NULL, &p, pubkey_len);
    if (!pk) return -1;

    EVP_MD_CTX *ctx = EVP_MD_CTX_new();
    EVP_DigestVerifyInit(ctx, NULL, EVP_sha256(), NULL, pk);
    int ok = EVP_DigestVerify(ctx, sig, sig_len, hash, hash_len);

    EVP_MD_CTX_free(ctx);
    EVP_PKEY_free(pk);
    return (ok == 1) ? 0 : -1;
}

int ecdsa_get_public_key(uint8_t **out, size_t *out_len)
{
    int len = i2d_PUBKEY(g_ecdsa_key, NULL);
    *out = malloc(len);
    uint8_t *p = *out;
    i2d_PUBKEY(g_ecdsa_key, &p);
    *out_len = len;
    return 1;
}
