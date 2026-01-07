#ifndef IMAGE_BUFFER_H
#define IMAGE_BUFFER_H

#include <stddef.h>
#include <stdint.h>

#define IMAGE_MAX_SIZE (5u * 1024u * 1024u)  /* adjust as needed */

typedef struct {
    uint8_t *data;
    size_t   len;
    size_t   cap;
} image_buffer_t;

/* Allocate once at startup. */
int  image_buffer_init(image_buffer_t *buf, size_t cap);

/* Free at shutdown. */
void image_buffer_free(image_buffer_t *buf);

/* “Fill” the buffer from a file (host substitute for camera DMA). */
int  image_buffer_load_file(image_buffer_t *buf, const char *path);

/* Mark as ready / reset length (simulates capture lifecycle). */
void image_buffer_reset(image_buffer_t *buf);

#endif
