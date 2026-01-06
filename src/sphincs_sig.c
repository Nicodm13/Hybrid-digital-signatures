#include "sphincs_sig.h"

#include <oqs/oqs.h>
#include <oqs/sig.h>
#include <stdlib.h>
#include <string.h>

static OQS_SIG *g_sig = NULL;
static uint8_t *g_pk = NULL;
static uint8_t *g_sk = NULL;
static char g_alg[128] = {0};

static int pick_sphincs_algorithm(char out_alg[128]) {
    const size_t n = OQS_SIG_alg_count();

    /* Prefer a small-ish SPHINCS+ parameter set if present (commonly used in benchmarks). */
    const char *preferred[] = {
        "SPHINCS+-SHA2-128s-simple",
        "SPHINCS+-SHA2-128f-simple",
        "SPHINCS+-SHAKE-128s-simple",
        "SPHINCS+-SHAKE-128f-simple",
        /* If the build uses the standardized family name, try SLH-DSA too. */
        "SLH-DSA-SHA2-128s",
        "SLH-DSA-SHA2-128f",
        "SLH-DSA-SHAKE-128s",
        "SLH-DSA-SHAKE-128f",
        NULL
    };

    for (int p = 0; preferred[p] != NULL; p++) {
        if (OQS_SIG_alg_is_enabled(preferred[p])) {
            strncpy(out_alg, preferred[p], 127);
            out_alg[127] = '\0';
            return 0;
        }
    }

    /* Fallback: first enabled algorithm that starts with SPHINCS+ or SLH-DSA. */
    for (size_t i = 0; i < n; i++) {
        const char *id = OQS_SIG_alg_identifier(i);
        if (!id) continue;
        if ((strncmp(id, "SPHINCS+", 8) == 0 || strncmp(id, "SLH-DSA", 7) == 0) &&
            OQS_SIG_alg_is_enabled(id)) {
            strncpy(out_alg, id, 127);
            out_alg[127] = '\0';
            return 0;
        }
    }

    return -1;
}

int sphincs_keygen(void) {
    if (g_sig && g_pk && g_sk) return 0;

    if (g_sig || g_pk || g_sk) sphincs_cleanup();

    if (pick_sphincs_algorithm(g_alg) != 0) return -1;

    g_sig = OQS_SIG_new(g_alg);
    if (!g_sig) return -1;

    g_pk = (uint8_t *)malloc(g_sig->length_public_key);
    g_sk = (uint8_t *)malloc(g_sig->length_secret_key);
    if (!g_pk || !g_sk) return -1;

    if (OQS_SIG_keypair(g_sig, g_pk, g_sk) != OQS_SUCCESS) return -1;

    return 0;
}

int sphincs_sign_hash(const uint8_t *hash, size_t hash_len, uint8_t **sig, size_t *sig_len) {
    if (!hash || !sig || !sig_len) return -1;
    if (!g_sig && sphincs_keygen() != 0) return -1;

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

int sphincs_verify_hash(const uint8_t *hash, size_t hash_len, const uint8_t *sig, size_t sig_len) {
    if (!hash || !sig) return -1;
    if (!g_sig || !g_pk) return -1;

    return (OQS_SIG_verify(g_sig, hash, hash_len, sig, sig_len, g_pk) == OQS_SUCCESS) ? 0 : -1;
}

void sphincs_cleanup(void) {
    if (g_sig) OQS_SIG_free(g_sig);
    g_sig = NULL;

    free(g_pk); g_pk = NULL;
    free(g_sk); g_sk = NULL;

    g_alg[0] = '\0';
}
