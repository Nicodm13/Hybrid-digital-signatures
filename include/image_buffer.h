#ifndef IMAGE_BUFFER_H
#define IMAGE_BUFFER_H

#include <stddef.h>
#include <stdint.h>

#define IMAGE_MAX_SIZE (5 * 1024 * 1024)  /* 5 MB safety cap */

typedef struct {
    uint8_t *data;
    size_t   len;
    size_t   cap;
} image_buffer_t;

int image_buffer_init(image_buffer_t *buf, size_t cap);
void image_buffer_free(image_buffer_t *buf);
void image_buffer_reset(image_buffer_t *buf);
int image_capture(image_buffer_t *buf);

#endif
