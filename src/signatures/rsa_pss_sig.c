#include <openssl/evp.h>
#include <stdlib.h>
#include <openssl/x509.h>

static EVP_PKEY *g_rsa_key = NULL;

int rsa_pss_keygen(void)
{
    EVP_PKEY_CTX *ctx = EVP_PKEY_CTX_new_id(EVP_PKEY_RSA, NULL);
    EVP_PKEY_keygen_init(ctx);
    EVP_PKEY_CTX_set_rsa_keygen_bits(ctx, 3072);
    EVP_PKEY_keygen(ctx, &g_rsa_key);
    EVP_PKEY_CTX_free(ctx);
    return 1;
}

int rsa_pss_sign(const uint8_t *msg, size_t msg_len, uint8_t **sig, size_t *sig_len)
{
    EVP_MD_CTX *ctx = EVP_MD_CTX_new();
    EVP_PKEY_CTX *pctx;
    EVP_DigestSignInit(ctx, &pctx, EVP_sha256(), NULL, g_rsa_key);
    EVP_PKEY_CTX_set_rsa_padding(pctx, RSA_PKCS1_PSS_PADDING);
    EVP_DigestSign(ctx, NULL, sig_len, msg, msg_len);
    *sig = malloc(*sig_len);
    EVP_DigestSign(ctx, *sig, sig_len, msg, msg_len);
    EVP_MD_CTX_free(ctx);
    return 1;
}

int rsa_pss_verify(const uint8_t *msg, size_t msg_len, const uint8_t *sig, size_t sig_len, EVP_PKEY *pubkey)
{
    EVP_MD_CTX *ctx = EVP_MD_CTX_new();
    EVP_PKEY_CTX *pctx;
    EVP_DigestVerifyInit(ctx, &pctx, EVP_sha256(), NULL, pubkey);
    EVP_PKEY_CTX_set_rsa_padding(pctx, RSA_PKCS1_PSS_PADDING);
    int ok = EVP_DigestVerify(ctx, sig, sig_len, msg, msg_len);
    EVP_MD_CTX_free(ctx);
    return ok == 1;
}

int rsa_pss_get_public_key(uint8_t **out, size_t *out_len)
{
    int len = i2d_PUBKEY(g_rsa_key, NULL);
    *out = malloc(len);
    uint8_t *p = *out;
    i2d_PUBKEY(g_rsa_key, &p);
    *out_len = len;
    return 1;
}
