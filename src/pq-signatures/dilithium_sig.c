#include "dilithium_sig.h"

#include <oqs/oqs.h>
#include <stdlib.h>
#include <string.h>

static OQS_SIG *g_sig = NULL;
static uint8_t *g_pk = NULL;
static uint8_t *g_sk = NULL;

int dilithium_keygen(void) {
    if (g_sig && g_pk && g_sk) return 0;

    const char *alg = OQS_SIG_alg_ml_dsa_44;

    if (!OQS_SIG_alg_is_enabled(alg)) return -1;

    g_sig = OQS_SIG_new(alg);
    if (!g_sig) return -1;

    g_pk = (uint8_t *)malloc(g_sig->length_public_key);
    g_sk = (uint8_t *)malloc(g_sig->length_secret_key);
    if (!g_pk || !g_sk) return -1;

    if (OQS_SIG_keypair(g_sig, g_pk, g_sk) != OQS_SUCCESS) return -1;

    return 0;
}

int dilithium_sign_hash(const uint8_t *hash, size_t hash_len, uint8_t **sig, size_t *sig_len) {
    if (!hash || !sig || !sig_len) return -1;
    if (!g_sig && dilithium_keygen() != 0) return -1;

    uint8_t *out = (uint8_t *)malloc(g_sig->length_signature);
    if (!out) return -1;

    size_t out_len = 0;
    if (OQS_SIG_sign(g_sig, out, &out_len, hash, hash_len, g_sk) != OQS_SUCCESS) {
        free(out);
        return -1;
    }

    /* shrink to exact length */
    uint8_t *exact = (uint8_t *)realloc(out, out_len);
    if (exact) out = exact;

    *sig = out;
    *sig_len = out_len;
    return 0;
}

int dilithium_verify_hash(const uint8_t *hash, size_t hash_len, const uint8_t *sig, size_t sig_len) {
    if (!hash || !sig) return -1;
    if (!g_sig || !g_pk) return -1;

    return (OQS_SIG_verify(g_sig, hash, hash_len, sig, sig_len, g_pk) == OQS_SUCCESS) ? 0 : -1;
}

void dilithium_cleanup(void) {
    if (g_sig) OQS_SIG_free(g_sig);
    g_sig = NULL;

    free(g_pk); g_pk = NULL;
    free(g_sk); g_sk = NULL;
}
