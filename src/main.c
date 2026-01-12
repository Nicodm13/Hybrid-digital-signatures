#include <stdio.h>
#include <stdlib.h>

#include "config.h"
#include "image_buffer.h"
#include "image_uploader.h"
#include "hybrid_signature.h"

#include "ecdsa_sig.h"
#include "rsa_pss_sig.h"
#include "dilithium_sig.h"
#include "falcon_sig.h"
#include "sphincs_sig.h"

static int init_all_keys(void)
{
    if (!ecdsa_keygen()) return 0;
    if (!rsa_pss_keygen()) return 0;
    if (!dilithium_keygen()) return 0;
    if (!falcon_keygen()) return 0;
    if (!sphincs_keygen()) return 0;
    return 1;
}

int main(void) {
    image_buffer_t img;
    hybrid_signature_t sig;

    if (!init_all_keys()) {
        fprintf(stderr, "Key initialization failed\n");
        return 1;
    }

    if (image_buffer_init(&img, IMAGE_MAX_SIZE) != 0) {
        fprintf(stderr, "Failed to init image buffer\n");
        return 1;
    }

    /* Capture image directly from camera */
    if (image_capture(&img) != 0) {
        fprintf(stderr, "Failed to capture image\n");
        image_buffer_free(&img);
        return 1;
    }

    printf("Captured image: %zu bytes\n", img.len);

    if (hybrid_sign_image(img.data, img.len, &sig) != 0) {
        fprintf(stderr, "Hybrid signing failed\n");
        image_buffer_free(&img);
        return 1;
    }

    printf("Hybrid signature size: %zu bytes\n", sig.len);

    uint8_t *pubkeys = NULL;
    size_t pubkeys_len = 0;

    if (!hybrid_get_public_keys(&pubkeys, &pubkeys_len)) {
        fprintf(stderr, "Failed to get public keys\n");
        image_buffer_free(&img);
        return 1;
    }

    if (upload_signed_image(img.data, img.len, &sig, pubkeys, pubkeys_len) != 0) {
        fprintf(stderr, "Failed to send signed image\n");
        free(pubkeys);
        image_buffer_free(&img);
        return 1;
    }

    free(pubkeys);
    image_buffer_free(&img);

    printf("Hybrid signature sent\n");
    return 0;
}

