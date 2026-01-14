#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#include <openssl/evp.h>
#include <openssl/x509.h>
#include <openssl/rsa.h>

static EVP_PKEY *g_rsa_key = NULL;

static void rsa_pss_set_params(EVP_PKEY_CTX *pctx)
{
    EVP_PKEY_CTX_set_rsa_padding(pctx, RSA_PKCS1_PSS_PADDING);
    EVP_PKEY_CTX_set_rsa_mgf1_md(pctx, EVP_sha256());
    EVP_PKEY_CTX_set_rsa_pss_saltlen(pctx, -1);
}

int rsa_pss_keygen(void)
{
    EVP_PKEY_CTX *ctx = EVP_PKEY_CTX_new_id(EVP_PKEY_RSA, NULL);
    if (!ctx) return -1;

    if (EVP_PKEY_keygen_init(ctx) <= 0) {
        EVP_PKEY_CTX_free(ctx);
        return -1;
    }

    if (EVP_PKEY_CTX_set_rsa_keygen_bits(ctx, 3072) <= 0) {
        EVP_PKEY_CTX_free(ctx);
        return -1;
    }

    EVP_PKEY *newkey = NULL;
    if (EVP_PKEY_keygen(ctx, &newkey) <= 0 || !newkey) {
        EVP_PKEY_CTX_free(ctx);
        return -1;
    }

    /* Replace old key safely */
    if (g_rsa_key) EVP_PKEY_free(g_rsa_key);
    g_rsa_key = newkey;

    EVP_PKEY_CTX_free(ctx);
    return 0;
}

int rsa_pss_sign(const uint8_t *msg, size_t msg_len, uint8_t **sig, size_t *sig_len)
{
    if (!msg || !sig || !sig_len || !g_rsa_key) return -1;

    EVP_MD_CTX *ctx = EVP_MD_CTX_new();
    if (!ctx) return -1;

    EVP_PKEY_CTX *pctx = NULL;
    if (EVP_DigestSignInit(ctx, &pctx, EVP_sha256(), NULL, g_rsa_key) <= 0 || !pctx) {
        EVP_MD_CTX_free(ctx);
        return -1;
    }

    rsa_pss_set_params(pctx);

    size_t needed = 0;
    if (EVP_DigestSign(ctx, NULL, &needed, msg, msg_len) <= 0 || needed == 0) {
        EVP_MD_CTX_free(ctx);
        return -1;
    }

    uint8_t *buf = (uint8_t *)malloc(needed);
    if (!buf) {
        EVP_MD_CTX_free(ctx);
        return -1;
    }

    if (EVP_DigestSign(ctx, buf, &needed, msg, msg_len) <= 0) {
        free(buf);
        EVP_MD_CTX_free(ctx);
        return -1;
    }

    *sig = buf;
    *sig_len = needed;

    EVP_MD_CTX_free(ctx);
    return 0;
}

int rsa_pss_verify(const uint8_t *msg, size_t msg_len,
                   const uint8_t *sig, size_t sig_len,
                   const uint8_t *pubkey, size_t pubkey_len)
{
    if (!msg || !sig || !pubkey) return -1;

    const uint8_t *p = pubkey;
    EVP_PKEY *pk = d2i_PUBKEY(NULL, &p, (long)pubkey_len);
    if (!pk) return -1;

    EVP_MD_CTX *ctx = EVP_MD_CTX_new();
    if (!ctx) {
        EVP_PKEY_free(pk);
        return -1;
    }

    EVP_PKEY_CTX *pctx = NULL;
    if (EVP_DigestVerifyInit(ctx, &pctx, EVP_sha256(), NULL, pk) <= 0 || !pctx) {
        EVP_MD_CTX_free(ctx);
        EVP_PKEY_free(pk);
        return -1;
    }

    rsa_pss_set_params(pctx);

    int ok = EVP_DigestVerify(ctx, sig, sig_len, msg, msg_len);

    EVP_MD_CTX_free(ctx);
    EVP_PKEY_free(pk);

    return (ok == 1) ? 0 : -1;
}

int rsa_pss_get_public_key(uint8_t **out, size_t *out_len)
{
    if (!out || !out_len || !g_rsa_key) return -1;

    int len = i2d_PUBKEY(g_rsa_key, NULL);
    if (len <= 0) return -1;

    uint8_t *buf = (uint8_t *)malloc((size_t)len);
    if (!buf) return -1;

    uint8_t *p = buf;
    if (i2d_PUBKEY(g_rsa_key, &p) != len) {
        free(buf);
        return -1;
    }

    *out = buf;
    *out_len = (size_t)len;
    return 0;
}
