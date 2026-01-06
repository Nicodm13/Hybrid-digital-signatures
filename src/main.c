#include "hybrid_sig.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>

int load_file(const char *path, unsigned char **buf, size_t *len) {
    FILE *f = fopen(path, "rb");
    if (!f) return -1;

    fseek(f, 0, SEEK_END);
    long size = ftell(f);
    rewind(f);

    unsigned char *data = malloc(size);
    if (!data) {
        fclose(f);
        return -1;
    }

    if (fread(data, 1, size, f) != (size_t)size) {
        free(data);
        fclose(f);
        return -1;
    }

    fclose(f);
    *buf = data;
    *len = size;
    return 0;
}

int main(void) {
    if (hybrid_init() != 0) {
        printf("ERROR: hybrid_init failed\n");
        return 1;
    }

    unsigned char *manifest = NULL;
    size_t manifest_len = 0;

    if (load_file("../manifest.txt", &manifest, &manifest_len) != 0) {
        printf("Failed to load manifest file\n");
        hybrid_cleanup();
        return 1;
    }

    hybrid_signature_t sig;

    /* Sign */
    if (hybrid_sign(manifest, manifest_len, &sig) != 0) {
        printf("ERROR: hybrid_sign failed\n");
        free(manifest);
        hybrid_cleanup();
        return 1;
    }

    printf("ECDSA signature size: %zu bytes\n", sig.ecdsa_sig_len);
    printf("Dilithium signature size: %zu bytes\n", sig.pq_sig_len);
    printf("Hybrid signature size: %zu bytes\n",
           sig.ecdsa_sig_len + sig.pq_sig_len);

    /* Verify (expected: OK) */
    if (hybrid_verify(manifest, manifest_len, &sig) == 0) {
        printf("Verification: OK\n");
    } else {
        printf("Verification: FAIL\n");
    }

    /* Tamper test */
    unsigned char *tampered = malloc(manifest_len);
    memcpy(tampered, manifest, manifest_len);
    tampered[0] ^= 0x01;

    if (hybrid_verify(tampered, manifest_len, &sig) == 0) {
        printf("Tampered verification: OK (ERROR)\n");
    } else {
        printf("Tampered verification: FAIL (expected)\n");
    }

    free(tampered);
    free(manifest);
    hybrid_signature_free(&sig);
    hybrid_cleanup();
    return 0;
}
