#include "scheme.h"
#include "hash.h"

#include "ecdsa_sig.h"
#include "rsa_pss_sig.h"
#include "dilithium_sig.h"
#include "falcon_sig.h"
#include "sphincs_sig.h"

#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <time.h>

#include <sys/wait.h>
#include <unistd.h>

#define NUM_ITERATIONS 1000
#define HASH_LEN 32 // 256 bits, SHA-256

/* ===================== Utilities ===================== */

static double now_seconds(void)
{
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (double)ts.tv_sec + (double)ts.tv_nsec * 1e-9;
}

static int load_file(const char *path, uint8_t **buf, size_t *len)
{
    FILE *f = fopen(path, "rb");
    if (!f) return -1;

    if (fseek(f, 0, SEEK_END) != 0) { fclose(f); return -1; }
    long sz = ftell(f);
    if (sz <= 0) { fclose(f); return -1; }
    rewind(f);

    uint8_t *data = (uint8_t *)malloc((size_t)sz);
    if (!data) { fclose(f); return -1; }

    size_t rd = fread(data, 1, (size_t)sz, f);
    fclose(f);

    if (rd != (size_t)sz) { free(data); return -1; }

    *buf = data;
    *len = (size_t)sz;
    return 0;
}

/* ===================== Scheme Table ===================== */

typedef struct {
    scheme_t id;
    const char *name;
    int is_hybrid;
} scheme_def_t;

static const scheme_def_t schemes[] = {
    { SCHEME_ECDSA_ONLY,        "ECDSA",               0 },
    { SCHEME_RSA_PSS_ONLY,      "RSA-PSS",             0 },
    { SCHEME_ML_DSA_ONLY,       "Dilithium",           0 },
    { SCHEME_FALCON_ONLY,       "Falcon",              0 },
    { SCHEME_SPHINCS_ONLY,      "SPHINCS+",            0 },

    { SCHEME_ECDSA_ML_DSA,      "ECDSA+Dilithium",     1 },
    { SCHEME_ECDSA_FALCON,      "ECDSA+Falcon",        1 },
    { SCHEME_ECDSA_SPHINCS,     "ECDSA+SPHINCS+",      1 },

    { SCHEME_RSA_PSS_ML_DSA,    "RSA-PSS+Dilithium",   1 },
    { SCHEME_RSA_PSS_FALCON,    "RSA-PSS+Falcon",      1 },
    { SCHEME_RSA_PSS_SPHINCS,   "RSA-PSS+SPHINCS+",    1 }
};

#define NUM_SCHEMES (sizeof(schemes) / sizeof(schemes[0]))

/* ===================== Dispatch Helpers ===================== */

static void keygen_for_scheme(scheme_t s)
{
    switch (s) {
        case SCHEME_ECDSA_ONLY:        ecdsa_keygen(); break;
        case SCHEME_RSA_PSS_ONLY:      rsa_pss_keygen(); break;
        case SCHEME_ML_DSA_ONLY:       dilithium_keygen(); break;
        case SCHEME_FALCON_ONLY:       falcon_keygen(); break;
        case SCHEME_SPHINCS_ONLY:      sphincs_keygen(); break;

        case SCHEME_ECDSA_ML_DSA:      ecdsa_keygen(); dilithium_keygen(); break;
        case SCHEME_ECDSA_FALCON:      ecdsa_keygen(); falcon_keygen(); break;
        case SCHEME_ECDSA_SPHINCS:     ecdsa_keygen(); sphincs_keygen(); break;

        case SCHEME_RSA_PSS_ML_DSA:    rsa_pss_keygen(); dilithium_keygen(); break;
        case SCHEME_RSA_PSS_FALCON:    rsa_pss_keygen(); falcon_keygen(); break;
        case SCHEME_RSA_PSS_SPHINCS:   rsa_pss_keygen(); sphincs_keygen(); break;
    }
}

static void get_pks_for_scheme(scheme_t s,
                              uint8_t **pk1, size_t *pk1_len,
                              uint8_t **pk2, size_t *pk2_len)
{
    *pk1 = *pk2 = NULL;
    *pk1_len = *pk2_len = 0;

    switch (s) {
        case SCHEME_ECDSA_ONLY:        ecdsa_get_public_key(pk1, pk1_len); break;
        case SCHEME_RSA_PSS_ONLY:      rsa_pss_get_public_key(pk1, pk1_len); break;
        case SCHEME_ML_DSA_ONLY:       dilithium_get_public_key(pk1, pk1_len); break;
        case SCHEME_FALCON_ONLY:       falcon_get_public_key(pk1, pk1_len); break;
        case SCHEME_SPHINCS_ONLY:      sphincs_get_public_key(pk1, pk1_len); break;

        case SCHEME_ECDSA_ML_DSA:      ecdsa_get_public_key(pk1, pk1_len); dilithium_get_public_key(pk2, pk2_len); break;
        case SCHEME_ECDSA_FALCON:      ecdsa_get_public_key(pk1, pk1_len); falcon_get_public_key(pk2, pk2_len); break;
        case SCHEME_ECDSA_SPHINCS:     ecdsa_get_public_key(pk1, pk1_len); sphincs_get_public_key(pk2, pk2_len); break;

        case SCHEME_RSA_PSS_ML_DSA:    rsa_pss_get_public_key(pk1, pk1_len); dilithium_get_public_key(pk2, pk2_len); break;
        case SCHEME_RSA_PSS_FALCON:    rsa_pss_get_public_key(pk1, pk1_len); falcon_get_public_key(pk2, pk2_len); break;
        case SCHEME_RSA_PSS_SPHINCS:   rsa_pss_get_public_key(pk1, pk1_len); sphincs_get_public_key(pk2, pk2_len); break;
    }
}

static void sign_for_scheme(scheme_t s,
                            const uint8_t *msg, size_t msg_len,
                            uint8_t **sig1, size_t *sig1_len,
                            uint8_t **sig2, size_t *sig2_len)
{
    *sig1 = *sig2 = NULL;
    *sig1_len = *sig2_len = 0;

    switch (s) {
        case SCHEME_ECDSA_ONLY:        ecdsa_sign(msg, msg_len, sig1, sig1_len); break;
        case SCHEME_RSA_PSS_ONLY:      rsa_pss_sign(msg, msg_len, sig1, sig1_len); break;
        case SCHEME_ML_DSA_ONLY:       dilithium_sign(msg, msg_len, sig1, sig1_len); break;
        case SCHEME_FALCON_ONLY:       falcon_sign(msg, msg_len, sig1, sig1_len); break;
        case SCHEME_SPHINCS_ONLY:      sphincs_sign(msg, msg_len, sig1, sig1_len); break;

        case SCHEME_ECDSA_ML_DSA:      ecdsa_sign(msg, msg_len, sig1, sig1_len); dilithium_sign(msg, msg_len, sig2, sig2_len); break;
        case SCHEME_ECDSA_FALCON:      ecdsa_sign(msg, msg_len, sig1, sig1_len); falcon_sign(msg, msg_len, sig2, sig2_len); break;
        case SCHEME_ECDSA_SPHINCS:     ecdsa_sign(msg, msg_len, sig1, sig1_len); sphincs_sign(msg, msg_len, sig2, sig2_len); break;

        case SCHEME_RSA_PSS_ML_DSA:    rsa_pss_sign(msg, msg_len, sig1, sig1_len); dilithium_sign(msg, msg_len, sig2, sig2_len); break;
        case SCHEME_RSA_PSS_FALCON:    rsa_pss_sign(msg, msg_len, sig1, sig1_len); falcon_sign(msg, msg_len, sig2, sig2_len); break;
        case SCHEME_RSA_PSS_SPHINCS:   rsa_pss_sign(msg, msg_len, sig1, sig1_len); sphincs_sign(msg, msg_len, sig2, sig2_len); break;
    }
}

static void verify_for_scheme(scheme_t s,
                              const uint8_t *msg, size_t msg_len,
                              const uint8_t *sig1, size_t sig1_len,
                              const uint8_t *sig2, size_t sig2_len,
                              const uint8_t *pk1, size_t pk1_len,
                              const uint8_t *pk2, size_t pk2_len)
{
    switch (s) {
        case SCHEME_ECDSA_ONLY:        (void)ecdsa_verify(msg, msg_len, sig1, sig1_len, pk1, pk1_len); break;
        case SCHEME_RSA_PSS_ONLY:      (void)rsa_pss_verify(msg, msg_len, sig1, sig1_len, pk1, pk1_len); break;
        case SCHEME_ML_DSA_ONLY:       (void)dilithium_verify(msg, msg_len, sig1, sig1_len, pk1, pk1_len); break;
        case SCHEME_FALCON_ONLY:       (void)falcon_verify(msg, msg_len, sig1, sig1_len, pk1, pk1_len); break;
        case SCHEME_SPHINCS_ONLY:      (void)sphincs_verify(msg, msg_len, sig1, sig1_len, pk1, pk1_len); break;

        case SCHEME_ECDSA_ML_DSA:
            (void)ecdsa_verify(msg, msg_len, sig1, sig1_len, pk1, pk1_len);
            (void)dilithium_verify(msg, msg_len, sig2, sig2_len, pk2, pk2_len);
            break;
        case SCHEME_ECDSA_FALCON:
            (void)ecdsa_verify(msg, msg_len, sig1, sig1_len, pk1, pk1_len);
            (void)falcon_verify(msg, msg_len, sig2, sig2_len, pk2, pk2_len);
            break;
        case SCHEME_ECDSA_SPHINCS:
            (void)ecdsa_verify(msg, msg_len, sig1, sig1_len, pk1, pk1_len);
            (void)sphincs_verify(msg, msg_len, sig2, sig2_len, pk2, pk2_len);
            break;

        case SCHEME_RSA_PSS_ML_DSA:
            (void)rsa_pss_verify(msg, msg_len, sig1, sig1_len, pk1, pk1_len);
            (void)dilithium_verify(msg, msg_len, sig2, sig2_len, pk2, pk2_len);
            break;
        case SCHEME_RSA_PSS_FALCON:
            (void)rsa_pss_verify(msg, msg_len, sig1, sig1_len, pk1, pk1_len);
            (void)falcon_verify(msg, msg_len, sig2, sig2_len, pk2, pk2_len);
            break;
        case SCHEME_RSA_PSS_SPHINCS:
            (void)rsa_pss_verify(msg, msg_len, sig1, sig1_len, pk1, pk1_len);
            (void)sphincs_verify(msg, msg_len, sig2, sig2_len, pk2, pk2_len);
            break;
    }
}

/* ===================== Per-scheme benchmark (child) ===================== */

static void run_one_scheme(const scheme_def_t *def, const uint8_t *image, size_t image_len)
{
    uint8_t hash[HASH_LEN];
    sha256(image, image_len, hash);

    double t_keygen = 0.0;
    double t_sign = 0.0;
    double t_verify = 0.0;

    uint8_t *pk1 = NULL, *pk2 = NULL;
    size_t pk1_len = 0, pk2_len = 0;

    double t0 = now_seconds();
    keygen_for_scheme(def->id);
    t_keygen = (now_seconds() - t0) * 1000.0;

    get_pks_for_scheme(def->id, &pk1, &pk1_len, &pk2, &pk2_len);

    size_t last_sig_size = 0;

    for (int i = 0; i < NUM_ITERATIONS; i++) {
        uint8_t *sig1 = NULL, *sig2 = NULL;
        size_t sig1_len = 0, sig2_len = 0;

        t0 = now_seconds();
        sign_for_scheme(def->id, hash, sizeof(hash), &sig1, &sig1_len, &sig2, &sig2_len);
        t_sign += (now_seconds() - t0) * 1000.0;

        t0 = now_seconds();
        verify_for_scheme(def->id, hash, sizeof(hash),
                          sig1, sig1_len, sig2, sig2_len,
                          pk1, pk1_len, pk2, pk2_len);
        t_verify += (now_seconds() - t0) * 1000.0;

        last_sig_size = sig1_len + sig2_len;
        free(sig1);
        free(sig2);
    }

    printf("%-22s | %9.2f | %8.2f | %9.2f | %6zu | %6zu\n",
           def->name,
           t_keygen,
           t_sign / NUM_ITERATIONS,
           t_verify / NUM_ITERATIONS,
           last_sig_size,
           pk1_len + pk2_len);

    free(pk1);
    free(pk2);
}

/* ===================== Main ===================== */

int main(void)
{
    uint8_t *image = NULL;
    size_t image_len = 0;

    if (load_file("../test.png", &image, &image_len) != 0) {
        fprintf(stderr, "Failed to load test.png\n");
        return 1;
    }

    printf("Scheme                  | KeyGen(ms) | Sign(ms) | Verify(ms) | Sig(B) | PK(B)\n");
    printf("--------------------------------------------------------------------------------\n");

    for (size_t i = 0; i < NUM_SCHEMES; i++) {

        pid_t pid = fork();
        if (pid == 0) {
            run_one_scheme(&schemes[i], image, image_len);
            _exit(0);
        }

        int status = 0;
        waitpid(pid, &status, 0);

        if (WIFSIGNALED(status)) {
            int sig = WTERMSIG(status);
            printf("%-22s |    CRASH   |    CRASH |    CRASH  |   n/a  |   n/a  (signal %d)\n",
                   schemes[i].name, sig);
        } else if (WIFEXITED(status) && WEXITSTATUS(status) != 0) {
            printf("%-22s |    FAIL    |    FAIL  |    FAIL   |   n/a  |   n/a  (exit %d)\n",
                   schemes[i].name, WEXITSTATUS(status));
        }
    }

    free(image);
    return 0;
}
