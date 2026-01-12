#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>

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

    /* Get file size */
    if (fseek(f, 0, SEEK_END) != 0) {
        perror("fseek");
        fclose(f);
        return 1;
    }

    long file_size = ftell(f);
    if (file_size < 0) {
        perror("ftell");
        fclose(f);
        return 1;
    }
    rewind(f);

    if ((size_t)file_size <= sizeof(hybrid_signature_t)) {
        fprintf(stderr, "Invalid file: too small to contain signature\n");
        fclose(f);
        return 1;
    }

    /* Read full file */
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

    /* Split image and signature */
    size_t image_len = (size_t)file_size - sizeof(hybrid_signature_t);
    uint8_t *image = buffer;
    hybrid_signature_t *sig =
        (hybrid_signature_t *)(buffer + image_len);

    /* Sanity check */
    if (sig->len == 0 || sig->len > sizeof(sig->data)) {
        fprintf(stderr, "Invalid signature structure\n");
        free(buffer);
        return 1;
    }

    /* Verify */
    int ok = hybrid_verify_image(image, image_len, sig);

    free(buffer);

    if (ok == 1) {
        printf("Signature verification SUCCESS\n");
        return 0;
    } else {
        printf("Signature verification FAILED\n");
        return 1;
    }
}
