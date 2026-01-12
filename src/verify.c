#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>

#include "config.h"
#include "hybrid_signature.h"

int main(void)
{
    const char *path = SERVER_STORAGE_PATH SERVER_STORAGE_NAME;
    FILE *f = fopen(path, "rb");
    if (!f) {
        perror("fopen");
        return 1;
    }

    /* Determine total file size */
    if (fseek(f, 0, SEEK_END) != 0) {
        perror("fseek");
        fclose(f);
        return 1;
    }

    long file_size = ftell(f);
    if (file_size < 12) { /* header alone is 12 bytes */
        fprintf(stderr, "Invalid file\n");
        fclose(f);
        return 1;
    }
    rewind(f);

    /* Read entire file into memory */
    uint8_t *buffer = malloc((size_t)file_size);
    if (!buffer) {
        perror("malloc");
        fclose(f);
        return 1;
    }

    if (fread(buffer, 1, (size_t)file_size, f) != (size_t)file_size) {
        perror("fread");
        free(buffer);
        fclose(f);
        return 1;
    }
    fclose(f);

    /* Parse the fixed-size header */
    const uint8_t *p = buffer;

    uint32_t image_len;
    uint32_t sig_len;
    uint32_t pubkeys_len;

    memcpy(&image_len,   p, 4); p += 4;
    memcpy(&sig_len,     p, 4); p += 4;
    memcpy(&pubkeys_len, p, 4); p += 4;

    /* File length must match declared lengths */
    size_t expected_size = 12 + image_len + sig_len + pubkeys_len;

    if (expected_size != (size_t)file_size) {
        fprintf(stderr, "Corrupt file (length mismatch)\n");
        free(buffer);
        return 1;
    }

    /* Split payload into its three logical components */

    /* Raw image bytes (used for hashing) */
    const uint8_t *image = p;
    p += image_len;

    /* Hybrid signature structure + signature data */
    const hybrid_signature_t *sig = (const hybrid_signature_t *)p;
    p += sig_len;

    /* Public keys corresponding to the selected hybrid scheme */
    const uint8_t *pubkeys = p;

    /*  Verify the signature */
    int ok = hybrid_verify_image(
        image,
        image_len,
        sig,
        pubkeys,
        pubkeys_len
    );

    free(buffer);

    if (ok == 1) {
        printf("Signature verification SUCCESS\n");
        return 0;
    } else {
        printf("Signature verification FAILED\n");
        return 1;
    }
}
