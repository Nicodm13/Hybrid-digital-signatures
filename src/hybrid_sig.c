#include "hybrid_sig.h"
#include "ecdsa_sig.h"
#include "dilithium_sig.h"

#include <openssl/evp.h>
#include <string.h>
#include <stdlib.h>

static int sha256(const uint8_t *msg, size_t msg_len, uint8_t out[32]) {
    int rc = -1;
    EVP_MD_CTX *ctx = EVP_MD_CTX_new();
    if (!ctx) return -1;

    if (EVP_DigestInit_ex(ctx, EVP_sha256(), NULL) != 1) goto done;
    if (EVP_DigestUpdate(ctx, msg, msg_len) != 1) goto done;

    unsigned int out_len = 0;
    if (EVP_DigestFinal_ex(ctx, out, &out_len) != 1) goto done;
    if (out_len != 32) goto done;

    rc = 0;
    done:
        EVP_MD_CTX_free(ctx);
    return rc;
}

int hybrid_init(void) {
    if (ecdsa_keygen() != 0) return -1;
    if (dilithium_keygen() != 0) return -1;
    return 0;
}

int hybrid_sign(const uint8_t *msg, size_t msg_len, hybrid_signature_t *out) {
    if (!msg || !out) return -1;
    memset(out, 0, sizeof(*out));

    uint8_t h[32];
    if (sha256(msg, msg_len, h) != 0) return -1;

    if (ecdsa_sign_hash(h, sizeof(h), &out->ecdsa_sig, &out->ecdsa_sig_len) != 0) {
        hybrid_signature_free(out);
        return -1;
    }

    if (dilithium_sign_hash(h, sizeof(h), &out->pq_sig, &out->pq_sig_len) != 0) {
        hybrid_signature_free(out);
        return -1;
    }

    return 0;
}

int hybrid_verify(const uint8_t *msg, size_t msg_len, const hybrid_signature_t *sig) {
    if (!msg || !sig) return -1;

    uint8_t h[32];
    if (sha256(msg, msg_len, h) != 0) return -1;

    if (ecdsa_verify_hash(h, sizeof(h), sig->ecdsa_sig, sig->ecdsa_sig_len) != 0) return -1;
    if (dilithium_verify_hash(h, sizeof(h), sig->pq_sig, sig->pq_sig_len) != 0) return -1;

    return 0; /* AND-verified */
}

void hybrid_signature_free(hybrid_signature_t *sig) {
    if (!sig) return;
    free(sig->ecdsa_sig);
    free(sig->pq_sig);
    sig->ecdsa_sig = NULL;
    sig->pq_sig = NULL;
    sig->ecdsa_sig_len = 0;
    sig->pq_sig_len = 0;
}

void hybrid_cleanup(void) {
    ecdsa_cleanup();
    dilithium_cleanup();
}
