#include <stdio.h>

#include "config.h"
#include "image_buffer.h"
#include "image_uploader.h"
#include "hybrid_signature.h"

int main(void) {
    image_buffer_t img;
    hybrid_signature_t sig;

    /* Allocate image buffer */
    if (image_buffer_init(&img, IMAGE_MAX_SIZE) != 0) {
        fprintf(stderr, "Failed to init image buffer\n");
        return 1;
    }

    /* Load image from configured path */
    if (image_buffer_load_file(&img, IMAGE_INPUT_PATH IMAGE_INPUT_NAME) != 0) {
        fprintf(stderr, "Failed to load image\n");
        image_buffer_free(&img);
        return 1;
    }

    printf("Loaded image: %zu bytes\n", img.len);

    /* Hybrid sign image */
    if (hybrid_sign_image(img.data, img.len, &sig) != 0) {
        fprintf(stderr, "Hybrid signing failed\n");
        image_buffer_free(&img);
        return 1;
    }

    printf("Hybrid signature size: %zu bytes\n", sig.len);

    if (upload_signed_image(img.data, img.len, &sig) != 0) {
        fprintf(stderr, "Failed to send signed image\n");
        image_buffer_free(&img);
        return 1;
    }

    printf("Hybrid signature sent");

    image_buffer_free(&img);
    return 0;
}
