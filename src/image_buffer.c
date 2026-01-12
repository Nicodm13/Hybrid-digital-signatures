#include "image_buffer.h"

#include <stdlib.h>
#include <stdio.h>
#include <string.h>

#include <fcntl.h>
#include <unistd.h>
#include <sys/ioctl.h>

#include <linux/videodev2.h>

int image_buffer_init(image_buffer_t *buf, size_t cap)
{
    if (!buf || cap == 0 || cap > IMAGE_MAX_SIZE)
        return -1;

    buf->data = (uint8_t *)malloc(cap);
    if (!buf->data)
        return -2;

    buf->len = 0;
    buf->cap = cap;
    return 0;
}

void image_buffer_free(image_buffer_t *buf)
{
    if (!buf)
        return;

    free(buf->data);
    buf->data = NULL;
    buf->len = 0;
    buf->cap = 0;
}

void image_buffer_reset(image_buffer_t *buf)
{
    if (!buf)
        return;
    buf->len = 0;
}

#include <errno.h>
#include <sys/mman.h>

int image_capture(image_buffer_t *buf)
{
    if (!buf || !buf->data)
        return -1;

    int fd = open("/dev/video0", O_RDWR);
    if (fd < 0)
        return -2;

    /* 1. Query capabilities */
    struct v4l2_capability cap;
    if (ioctl(fd, VIDIOC_QUERYCAP, &cap) < 0) {
        close(fd);
        return -3;
    }

    if (!(cap.capabilities & V4L2_CAP_VIDEO_CAPTURE) ||
        !(cap.capabilities & V4L2_CAP_STREAMING)) {
        close(fd);
        return -4;
    }

    /* 2. Set format */
    struct v4l2_format fmt = {0};
    fmt.type = V4L2_BUF_TYPE_VIDEO_CAPTURE;
    fmt.fmt.pix.width = 640;
    fmt.fmt.pix.height = 480;
    fmt.fmt.pix.pixelformat = V4L2_PIX_FMT_MJPEG;
    fmt.fmt.pix.field = V4L2_FIELD_NONE;

    if (ioctl(fd, VIDIOC_S_FMT, &fmt) < 0) {
        close(fd);
        return -5;
    }

    /* 3. Request buffers */
    struct v4l2_requestbuffers req = {0};
    req.count = 1;
    req.type = V4L2_BUF_TYPE_VIDEO_CAPTURE;
    req.memory = V4L2_MEMORY_MMAP;

    if (ioctl(fd, VIDIOC_REQBUFS, &req) < 0 || req.count < 1) {
        close(fd);
        return -6;
    }

    /* 4. Query buffer */
    struct v4l2_buffer vbuf = {0};
    vbuf.type = V4L2_BUF_TYPE_VIDEO_CAPTURE;
    vbuf.memory = V4L2_MEMORY_MMAP;
    vbuf.index = 0;

    if (ioctl(fd, VIDIOC_QUERYBUF, &vbuf) < 0) {
        close(fd);
        return -7;
    }

    void *mapped = mmap(NULL, vbuf.length,
                        PROT_READ | PROT_WRITE,
                        MAP_SHARED, fd, vbuf.m.offset);

    if (mapped == MAP_FAILED) {
        close(fd);
        return -8;
    }

    /* 5. Queue buffer */
    if (ioctl(fd, VIDIOC_QBUF, &vbuf) < 0) {
        munmap(mapped, vbuf.length);
        close(fd);
        return -9;
    }

    /* 6. Start streaming */
    enum v4l2_buf_type type = V4L2_BUF_TYPE_VIDEO_CAPTURE;
    if (ioctl(fd, VIDIOC_STREAMON, &type) < 0) {
        munmap(mapped, vbuf.length);
        close(fd);
        return -10;
    }

    /* 7. Dequeue filled buffer */
    if (ioctl(fd, VIDIOC_DQBUF, &vbuf) < 0) {
        ioctl(fd, VIDIOC_STREAMOFF, &type);
        munmap(mapped, vbuf.length);
        close(fd);
        return -11;
    }

    /* 8. Copy image */
    if (vbuf.bytesused > buf->cap) {
        ioctl(fd, VIDIOC_STREAMOFF, &type);
        munmap(mapped, vbuf.length);
        close(fd);
        return -12;
    }

    memcpy(buf->data, mapped, vbuf.bytesused);
    buf->len = vbuf.bytesused;

    /* 9. Stop streaming and cleanup */
    ioctl(fd, VIDIOC_STREAMOFF, &type);
    munmap(mapped, vbuf.length);
    close(fd);

    /* 10. JPEG sanity check */
    if (buf->len < 2 || buf->data[0] != 0xFF || buf->data[1] != 0xD8)
        return -13;

    return 0;
}

