#include "scheme.h"

#include "ecdsa_sig.h"
#include "rsa_pss_sig.h"
#include "dilithium_sig.h"
#include "falcon_sig.h"
#include "sphincs_sig.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <openssl/evp.h>

/* ===================== Utilities ===================== */
int load_file(const char *path, unsigned char **buf, size_t *len) {
    FILE *f = fopen(path, "rb");
    if (!f) return -1;

    if (fseek(f, 0, SEEK_END) != 0) {
        fclose(f);
        return -1;
    }

    long size = ftell(f);
    if (size < 0) {
        fclose(f);
        return -1;
    }
    rewind(f);

    unsigned char *data = malloc((size_t)size);
    if (!data) {
        fclose(f);
        return -1;
    }

    size_t read = fread(data, 1, (size_t)size, f);
    fclose(f);

    if (read != (size_t)size) {
        free(data);
        return -1;
    }

    *buf = data;
    *len = (size_t)size;
    return 0;
}

void sha256(const uint8_t *msg, size_t len, uint8_t out[32]) {
    EVP_MD_CTX *ctx = EVP_MD_CTX_new();
    EVP_DigestInit_ex(ctx, EVP_sha256(), NULL);
    EVP_DigestUpdate(ctx, msg, len);
    EVP_DigestFinal_ex(ctx, out, NULL);
    EVP_MD_CTX_free(ctx);
}

/* ===================== Abstractions ===================== */

typedef struct {
    int (*keygen)(void);
    int (*sign)(const uint8_t *, size_t, uint8_t **, size_t *);
    int (*verify)(const uint8_t *, size_t, const uint8_t *, size_t);
    void (*cleanup)(void);
    const char *name;
} sig_ops_t;

typedef struct {
    scheme_t id;
    const char *name;
    sig_ops_t *classical;
    sig_ops_t *pq;
} scheme_def_t;

/* ===================== Algorithm Instances ===================== */

sig_ops_t ECDSA = {
    ecdsa_keygen, ecdsa_sign_hash, ecdsa_verify_hash, ecdsa_cleanup, "ECDSA"
};

sig_ops_t RSA_PSS = {
    rsa_pss_keygen, rsa_pss_sign_hash, rsa_pss_verify_hash, rsa_pss_cleanup, "RSA-PSS"
};

sig_ops_t ML_DSA = {
    dilithium_keygen, dilithium_sign_hash, dilithium_verify_hash, dilithium_cleanup, "ML-DSA"
};

sig_ops_t FALCON = {
    falcon_keygen, falcon_sign_hash, falcon_verify_hash, falcon_cleanup, "Falcon"
};

sig_ops_t SPHINCS = {
    sphincs_keygen, sphincs_sign_hash, sphincs_verify_hash, sphincs_cleanup, "SPHINCS+"
};

/* ===================== Scheme Definitions ===================== */

scheme_def_t schemes[] = {
    { SCHEME_ECDSA_ONLY,        "ECDSA",              &ECDSA,   NULL },
    { SCHEME_RSA_PSS_ONLY,     "RSA-PSS",            &RSA_PSS, NULL },
    { SCHEME_ML_DSA_ONLY,      "ML-DSA",              NULL,    &ML_DSA },
    { SCHEME_FALCON_ONLY,      "Falcon",              NULL,    &FALCON },
    { SCHEME_SPHINCS_ONLY,     "SPHINCS+",            NULL,    &SPHINCS },

    { SCHEME_ECDSA_ML_DSA,     "ECDSA + ML-DSA",      &ECDSA,   &ML_DSA },
    { SCHEME_ECDSA_FALCON,     "ECDSA + Falcon",      &ECDSA,   &FALCON },
    { SCHEME_ECDSA_SPHINCS,    "ECDSA + SPHINCS+",    &ECDSA,   &SPHINCS },

    { SCHEME_RSA_PSS_ML_DSA,   "RSA-PSS + ML-DSA",    &RSA_PSS, &ML_DSA },
    { SCHEME_RSA_PSS_FALCON,   "RSA-PSS + Falcon",    &RSA_PSS, &FALCON },
    { SCHEME_RSA_PSS_SPHINCS,  "RSA-PSS + SPHINCS+",  &RSA_PSS, &SPHINCS }
};

const scheme_def_t *get_scheme_def(scheme_t id) {
    size_t count = sizeof(schemes) / sizeof(schemes[0]);
    for (size_t i = 0; i < count; i++) {
        if (schemes[i].id == id) {
            return &schemes[i];
        }
    }
    return NULL;
}

/* ===================== Evaluation ===================== */

void evaluate_scheme(const scheme_def_t *s, const uint8_t hash[32]) {
    uint8_t *sig1 = NULL, *sig2 = NULL;
    size_t len1 = 0, len2 = 0;
    int ok = 0;

    printf("\nScheme: %s\n", s->name);

    if (s->classical) {
        s->classical->keygen();
        s->classical->sign(hash, 32, &sig1, &len1);
    }

    if (s->pq) {
        s->pq->keygen();
        s->pq->sign(hash, 32, &sig2, &len2);
    }

    if (s->classical)
        ok |= s->classical->verify(hash, 32, sig1, len1);

    if (s->pq)
        ok |= s->pq->verify(hash, 32, sig2, len2);

    printf("Signature size: %zu bytes\n", len1 + len2);
    printf("Verification: %s\n", ok == 0 ? "OK" : "FAIL");

    free(sig1);
    free(sig2);

    if (s->classical) s->classical->cleanup();
    if (s->pq) s->pq->cleanup();
}

/* ===================== Main ===================== */

scheme_t select_scheme_from_terminal(void) {
    int choice = 0;

    printf("\nSelect signature scheme:\n\n");
    printf(" 1  - ECDSA only\n");
    printf(" 2  - RSA-PSS only\n");
    printf(" 3  - ML-DSA only\n");
    printf(" 4  - Falcon only\n");
    printf(" 5  - SPHINCS+ only\n");
    printf("\n Hybrid (ECDSA + PQ):\n");
    printf(" 6  - ECDSA + ML-DSA\n");
    printf(" 7  - ECDSA + Falcon\n");
    printf(" 8  - ECDSA + SPHINCS+\n");
    printf("\n Hybrid (RSA-PSS + PQ):\n");
    printf(" 9  - RSA-PSS + ML-DSA\n");
    printf("10  - RSA-PSS + Falcon\n");
    printf("11  - RSA-PSS + SPHINCS+\n\n");

    printf("Enter choice (1–11): ");
    if (scanf("%d", &choice) != 1) {
        return -1;
    }

    switch (choice) {
        case 1:  return SCHEME_ECDSA_ONLY;
        case 2:  return SCHEME_RSA_PSS_ONLY;
        case 3:  return SCHEME_ML_DSA_ONLY;
        case 4:  return SCHEME_FALCON_ONLY;
        case 5:  return SCHEME_SPHINCS_ONLY;
        case 6:  return SCHEME_ECDSA_ML_DSA;
        case 7:  return SCHEME_ECDSA_FALCON;
        case 8:  return SCHEME_ECDSA_SPHINCS;
        case 9:  return SCHEME_RSA_PSS_ML_DSA;
        case 10: return SCHEME_RSA_PSS_FALCON;
        case 11: return SCHEME_RSA_PSS_SPHINCS;
        default: return -1;
    }
}

int main(void) {

    scheme_t selected_scheme = select_scheme_from_terminal();
    if (selected_scheme < 0) {
        printf("Invalid selection\n");
        return 1;
    }

    const scheme_def_t *scheme = get_scheme_def(selected_scheme);
    if (!scheme) {
        printf("Scheme not found\n");
        return 1;
    }

    unsigned char *manifest = NULL;
    size_t manifest_len = 0;

    if (load_file("../manifest.txt", &manifest, &manifest_len) != 0) {
        printf("Failed to load manifest.txt\n");
        return 1;
    }

    uint8_t hash[32];
    sha256(manifest, manifest_len, hash);

    evaluate_scheme(scheme, hash);

    free(manifest);
    return 0;
}

