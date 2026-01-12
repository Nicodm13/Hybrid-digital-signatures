#ifndef IMAGE_UPLOADER_H
#define IMAGE_UPLOADER_H

#include <stddef.h>
#include <stdint.h>
#include "hybrid_signature.h"

int upload_signed_image(
    const uint8_t *image,
    size_t image_len,
    const hybrid_signature_t *sig,
    const uint8_t *pubkeys,
    size_t pubkeys_len
);

#endif
