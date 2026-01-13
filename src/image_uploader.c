#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <stdio.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include "hybrid_signature.h"
#include "config.h"

static int send_all(int sock, const uint8_t *buf, size_t len)
{
    size_t sent = 0;
    while (sent < len) {
        ssize_t n = send(sock, buf + sent, len - sent, 0);
        if (n <= 0)
            return -1;
        sent += (size_t)n;
    }
    return 0;
}

int upload_signed_image(const uint8_t *image,
                        size_t image_len,
                        const hybrid_signature_t *sig,
                        const uint8_t *pubkeys,
                        size_t pubkeys_len)
{
    int sock;
    struct sockaddr_in addr;

    size_t body_len =
        sizeof(uint32_t) + image_len +
        sizeof(uint32_t) + sig->len +
        sizeof(uint32_t) + pubkeys_len;

    uint8_t *body = malloc(body_len);
    if (!body)
        return -1;

    uint8_t *p = body;
    uint32_t n;

    n = htonl((uint32_t)image_len);
    memcpy(p, &n, 4); p += 4;
    memcpy(p, image, image_len); p += image_len;

    n = htonl((uint32_t)sig->len);
    memcpy(p, &n, 4); p += 4;
    memcpy(p, sig->data, sig->len); p += sig->len;

    n = htonl((uint32_t)pubkeys_len);
    memcpy(p, &n, 4); p += 4;
    memcpy(p, pubkeys, pubkeys_len);

    sock = socket(AF_INET, SOCK_STREAM, 0);
    if (sock < 0) {
        free(body);
        return -1;
    }

    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_port = htons(SERVER_PORT);

    if (inet_pton(AF_INET, SERVER_IP, &addr.sin_addr) != 1) {
        close(sock);
        free(body);
        return -1;
    }

    if (connect(sock, (struct sockaddr *)&addr, sizeof(addr)) < 0) {
        close(sock);
        free(body);
        return -1;
    }

    char header[256];
    int header_len = snprintf(
        header, sizeof(header),
        "POST / HTTP/1.1\r\n"
        "Host: %s:%d\r\n"
        "Content-Length: %zu\r\n"
        "\r\n",
        SERVER_IP, SERVER_PORT, body_len
    );

    if (header_len <= 0 ||
        send_all(sock, (const uint8_t *)header, (size_t)header_len) < 0 ||
        send_all(sock, body, body_len) < 0) {
        close(sock);
        free(body);
        return -1;
    }

    char response[128];
    recv(sock, response, sizeof(response), 0);

    close(sock);
    free(body);
    return 0;
}
