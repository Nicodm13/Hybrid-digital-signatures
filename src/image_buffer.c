#include "image_buffer.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

int image_buffer_init(image_buffer_t *buf, size_t cap) {
    if (!buf || cap == 0 || cap > IMAGE_MAX_SIZE) return -1;
    buf->data = (uint8_t *)malloc(cap);
    if (!buf->data) return -2;
    buf->len = 0;
    buf->cap = cap;
    return 0;
}

void image_buffer_free(image_buffer_t *buf) {
    if (!buf) return;
    free(buf->data);
    buf->data = NULL;
    buf->len = 0;
    buf->cap = 0;
}

void image_buffer_reset(image_buffer_t *buf) {
    if (!buf) return;
    buf->len = 0;
}

int image_buffer_load_file(image_buffer_t *buf, const char *path) {
    if (!buf || !buf->data || !path) return -1;

    FILE *f = fopen(path, "rb");
    if (!f) return -2;

    if (fseek(f, 0, SEEK_END) != 0) { fclose(f); return -3; }
    long sz = ftell(f);
    if (sz < 0) { fclose(f); return -4; }
    if (fseek(f, 0, SEEK_SET) != 0) { fclose(f); return -5; }

    if ((size_t)sz > buf->cap) { fclose(f); return -6; }

    size_t n = fread(buf->data, 1, (size_t)sz, f);
    fclose(f);

    if (n != (size_t)sz) return -7;

    buf->len = n;
    return 0;
}
