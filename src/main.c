#include <stdio.h>

#include "image_buffer.h"
#include "hybrid_signature.h"

int main(void) {
    image_buffer_t img;
    hybrid_signature_t sig;

    /* Initialize image buffer (host stand-in for camera DMA) */
    if (image_buffer_init(&img, IMAGE_MAX_SIZE) != 0) {
        fprintf(stderr, "Failed to init image buffer\n");
        return 1;
    }

    /* Load test image */
    /*if (image_buffer_load_file(&img, "../test.png") != 0) {
        fprintf(stderr, "Failed to load test.png\n");
        image_buffer_free(&img);
        return 1;
    }*/
    if (image_buffer_capture_mjpeg(&img, "/dev/video0", 1280, 720) != 0) {
        fprintf(stderr, "Failed to capture from webcam\n");
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

    /* Hybrid verify image */
    if (hybrid_verify_image(img.data, img.len, &sig) != 1) {
        fprintf(stderr, "Hybrid verification FAILED\n");
        image_buffer_free(&img);
        return 1;
    }

    printf("Hybrid verification SUCCESS\n");

    /* Tamper with the image */
    img.data[0] ^= 0x01;   // flip a single bit

    /* Hybrid verify image */
    if (hybrid_verify_image(img.data, img.len, &sig) != 1) {
        fprintf(stderr, "Hybrid verification FAILED (tampering detected, expected)\n");
        image_buffer_free(&img);
        return 0;
    }

    printf("Hybrid verification SUCCESS (this should NOT happen)\n");

    image_buffer_free(&img);
    return 0;
}
