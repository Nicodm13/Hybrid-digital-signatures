#include "falcon_sig.h"

#include <oqs/oqs.h>
#include <oqs/sig.h>
#include <stdlib.h>
#include <string.h>

static OQS_SIG *g_sig = NULL;
static uint8_t *g_pk = NULL;
static uint8_t *g_sk = NULL;
static char g_alg[128] = {0};

static int pick_falcon_algorithm(char out_alg[128]) {
    /* Prefer Falcon-512 if available; otherwise fall back to the first enabled Falcon variant. */
    const size_t n = OQS_SIG_alg_count();

    /* First pass: explicit preference for Falcon-512 string match. */
    for (size_t i = 0; i < n; i++) {
        const char *id = OQS_SIG_alg_identifier(i);
        if (!id) continue;
        if (strncmp(id, "Falcon-512", 10) == 0 && OQS_SIG_alg_is_enabled(id)) {
            strncpy(out_alg, id, 127);
            out_alg[127] = '\0';
            return 0;
        }
    }

    /* Second pass: any Falcon. */
    for (size_t i = 0; i < n; i++) {
        const char *id = OQS_SIG_alg_identifier(i);
        if (!id) continue;
        if (strncmp(id, "Falcon", 6) == 0 && OQS_SIG_alg_is_enabled(id)) {
            strncpy(out_alg, id, 127);
            out_alg[127] = '\0';
            return 0;
        }
    }

    return -1;
}

int falcon_keygen(void) {
    if (g_sig && g_pk && g_sk) return 0;

    if (g_sig || g_pk || g_sk) falcon_cleanup();

    if (pick_falcon_algorithm(g_alg) != 0) return -1;

    g_sig = OQS_SIG_new(g_alg);
    if (!g_sig) return -1;

    g_pk = (uint8_t *)malloc(g_sig->length_public_key);
    g_sk = (uint8_t *)malloc(g_sig->length_secret_key);
    if (!g_pk || !g_sk) return -1;

    if (OQS_SIG_keypair(g_sig, g_pk, g_sk) != OQS_SUCCESS) return -1;

    return 0;
}

int falcon_sign_hash(const uint8_t *hash, size_t hash_len, uint8_t **sig, size_t *sig_len) {
    if (!hash || !sig || !sig_len) return -1;
    if (!g_sig && falcon_keygen() != 0) return -1;

    uint8_t *out = (uint8_t *)malloc(g_sig->length_signature);
    if (!out) return -1;

    size_t out_len = 0;
    if (OQS_SIG_sign(g_sig, out, &out_len, hash, hash_len, g_sk) != OQS_SUCCESS) {
        free(out);
        return -1;
    }

    uint8_t *exact = (uint8_t *)realloc(out, out_len);
    if (exact) out = exact;

    *sig = out;
    *sig_len = out_len;
    return 0;
}

int falcon_verify_hash(const uint8_t *hash, size_t hash_len, const uint8_t *sig, size_t sig_len) {
    if (!hash || !sig) return -1;
    if (!g_sig || !g_pk) return -1;

    return (OQS_SIG_verify(g_sig, hash, hash_len, sig, sig_len, g_pk) == OQS_SUCCESS) ? 0 : -1;
}

void falcon_cleanup(void) {
    if (g_sig) OQS_SIG_free(g_sig);
    g_sig = NULL;

    free(g_pk); g_pk = NULL;
    free(g_sk); g_sk = NULL;

    g_alg[0] = '\0';
}
