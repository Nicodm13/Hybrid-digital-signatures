#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <arpa/inet.h>

#include "config.h"
#include "hybrid_signature.h"

static int read_u32_be(const uint8_t **p, const uint8_t *end, uint32_t *out)
{
    if ((size_t)(end - *p) < 4) return 0;
    uint32_t tmp;
    memcpy(&tmp, *p, 4);
    *p += 4;
    *out = ntohl(tmp);
    return 1;
}

int main(void)
{
    const char *path = SERVER_STORAGE_PATH SERVER_STORAGE_NAME;
    FILE *f = fopen(path, "rb");
    if (!f) {
        perror("fopen");
        return 1;
    }

    if (fseek(f, 0, SEEK_END) != 0) {
        perror("fseek");
        fclose(f);
        return 1;
    }

    long file_size = ftell(f);
    if (file_size <= 0) {
        fprintf(stderr, "Invalid file\n");
        fclose(f);
        return 1;
    }
    rewind(f);

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

    const uint8_t *p = buffer;
    const uint8_t *end = buffer + (size_t)file_size;

    uint32_t image_len = 0, sig_len = 0, pubkeys_len = 0;

    /* Parse: [u32 image_len][image][u32 sig_len][sig_bytes][u32 pubkeys_len][pubkeys] */
    if (!read_u32_be(&p, end, &image_len)) {
        fprintf(stderr, "Corrupt file (missing image_len)\n");
        free(buffer);
        return 1;
    }
    if ((size_t)(end - p) < image_len) {
        fprintf(stderr, "Corrupt file (truncated image)\n");
        free(buffer);
        return 1;
    }
    const uint8_t *image = p;
    p += image_len;

    if (!read_u32_be(&p, end, &sig_len)) {
        fprintf(stderr, "Corrupt file (missing sig_len)\n");
        free(buffer);
        return 1;
    }
    if ((size_t)(end - p) < sig_len) {
        fprintf(stderr, "Corrupt file (truncated signature)\n");
        free(buffer);
        return 1;
    }

    /* Reconstruct hybrid_signature_t from raw signature bytes */
    hybrid_signature_t sig;

    if (sig_len > sizeof(sig.data)) {
        fprintf(stderr, "Signature too large\n");
        free(buffer);
        return 1;
    }

    memcpy(sig.data, p, sig_len);
    sig.len = sig_len;
    p += sig_len;

    if (!read_u32_be(&p, end, &pubkeys_len)) {
        fprintf(stderr, "Corrupt file (missing pubkeys_len)\n");
        free(buffer);
        return 1;
    }
    if ((size_t)(end - p) < pubkeys_len) {
        fprintf(stderr, "Corrupt file (truncated pubkeys)\n");
        free(buffer);
        return 1;
    }
    const uint8_t *pubkeys = p;
    p += pubkeys_len;

    if (p != end) {
        fprintf(stderr, "Corrupt file (extra trailing bytes)\n");
        free(buffer);
        return 1;
    }

    int ok = hybrid_verify_image(
        image,
        (size_t)image_len,
        &sig,
        pubkeys,
        (size_t)pubkeys_len
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
