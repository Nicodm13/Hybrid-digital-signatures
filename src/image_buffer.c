#include "image_buffer.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
/*For webcam*/
#include <errno.h>
#include <fcntl.h>
#include <sys/ioctl.h>
#include <sys/mman.h>
#include <unistd.h>
#include <linux/videodev2.h>

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

int image_buffer_capture_mjpeg(image_buffer_t *buf, const char *device, int width, int height) {
    if (!buf || !buf->data) return -1;
    if (!device) device = "/dev/video0";

    int fd = open(device, O_RDWR);
    if (fd < 0) return -2;

    // Set format to MJPEG
    struct v4l2_format fmt;
    memset(&fmt, 0, sizeof(fmt));
    fmt.type = V4L2_BUF_TYPE_VIDEO_CAPTURE;
    fmt.fmt.pix.width = (width > 0 ? (unsigned)width : 1280);
    fmt.fmt.pix.height = (height > 0 ? (unsigned)height : 720);
    fmt.fmt.pix.pixelformat = V4L2_PIX_FMT_MJPEG;
    fmt.fmt.pix.field = V4L2_FIELD_ANY;

    if (ioctl(fd, VIDIOC_S_FMT, &fmt) < 0) {
        close(fd);
        return -3;
    }

    // Request buffers
    struct v4l2_requestbuffers req;
    memset(&req, 0, sizeof(req));
    req.count = 4;
    req.type = V4L2_BUF_TYPE_VIDEO_CAPTURE;
    req.memory = V4L2_MEMORY_MMAP;

    if (ioctl(fd, VIDIOC_REQBUFS, &req) < 0) {
        close(fd);
        return -4;
    }
    if (req.count < 2) {
        close(fd);
        return -5;
    }

    // mmap buffers
    struct mapped_buf { void *start; size_t len; };
    struct mapped_buf *mb = calloc(req.count, sizeof(*mb));
    if (!mb) { close(fd); return -6; }

    for (unsigned i = 0; i < req.count; i++) {
        struct v4l2_buffer b;
        memset(&b, 0, sizeof(b));
        b.type = V4L2_BUF_TYPE_VIDEO_CAPTURE;
        b.memory = V4L2_MEMORY_MMAP;
        b.index = i;

        if (ioctl(fd, VIDIOC_QUERYBUF, &b) < 0) {
            free(mb); close(fd);
            return -7;
        }

        mb[i].len = b.length;
        mb[i].start = mmap(NULL, b.length, PROT_READ | PROT_WRITE, MAP_SHARED, fd, b.m.offset);
        if (mb[i].start == MAP_FAILED) {
            free(mb); close(fd);
            return -8;
        }

        // Queue buffer
        if (ioctl(fd, VIDIOC_QBUF, &b) < 0) {
            free(mb); close(fd);
            return -9;
        }
    }

    // Start streaming
    enum v4l2_buf_type type = V4L2_BUF_TYPE_VIDEO_CAPTURE;
    if (ioctl(fd, VIDIOC_STREAMON, &type) < 0) {
        free(mb); close(fd);
        return -10;
    }

    // Dequeue one frame
    struct v4l2_buffer out;
    memset(&out, 0, sizeof(out));
    out.type = V4L2_BUF_TYPE_VIDEO_CAPTURE;
    out.memory = V4L2_MEMORY_MMAP;

    if (ioctl(fd, VIDIOC_DQBUF, &out) < 0) {
        ioctl(fd, VIDIOC_STREAMOFF, &type);
        free(mb); close(fd);
        return -11;
    }

    // Copy captured JPEG bytes into your buffer
    if (out.bytesused > buf->cap) {
        // Re-queue and stop
        ioctl(fd, VIDIOC_QBUF, &out);
        ioctl(fd, VIDIOC_STREAMOFF, &type);
        for (unsigned i = 0; i < req.count; i++) munmap(mb[i].start, mb[i].len);
        free(mb); close(fd);
        return -12;
    }

    memcpy(buf->data, mb[out.index].start, out.bytesused);
    buf->len = out.bytesused;

    // Re-queue (good practice)
    ioctl(fd, VIDIOC_QBUF, &out);

    // Stop streaming and cleanup
    ioctl(fd, VIDIOC_STREAMOFF, &type);
    for (unsigned i = 0; i < req.count; i++) munmap(mb[i].start, mb[i].len);
    free(mb);
    close(fd);

    return 0;
}
