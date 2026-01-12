#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <arpa/inet.h>

#include "config.h"

#define LISTEN_PORT 8000
#define BUFFER_SIZE 4096

int main(void)
{
    int server_fd, client_fd;
    struct sockaddr_in addr;
    socklen_t addrlen = sizeof(addr);

    server_fd = socket(AF_INET, SOCK_STREAM, 0);
    if (server_fd < 0) {
        perror("socket");
        return 1;
    }

    int opt = 1;
    setsockopt(server_fd, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt));

    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = INADDR_ANY;
    addr.sin_port = htons(LISTEN_PORT);

    if (bind(server_fd, (struct sockaddr *)&addr, sizeof(addr)) < 0) {
        perror("bind");
        return 1;
    }

    if (listen(server_fd, 1) < 0) {
        perror("listen");
        return 1;
    }

    printf("Listening on port %d...\n", LISTEN_PORT);

    client_fd = accept(server_fd, (struct sockaddr *)&addr, &addrlen);
    if (client_fd < 0) {
        perror("accept");
        return 1;
    }

    char buffer[BUFFER_SIZE];
    int received = 0;
    int header_end = 0;
    int content_length = 0;

    /* Read HTTP headers */
    while (!header_end) {
        int r = recv(client_fd, buffer + received,
                     BUFFER_SIZE - received, 0);
        if (r <= 0) {
            perror("recv");
            close(client_fd);
            return 1;
        }
        received += r;

        char *end = strstr(buffer, "\r\n\r\n");
        if (end) {
            header_end = (end - buffer) + 4;

            char *cl = strstr(buffer, "Content-Length:");
            if (!cl) {
                fprintf(stderr, "No Content-Length header\n");
                close(client_fd);
                return 1;
            }
            sscanf(cl, "Content-Length: %d", &content_length);
        }
    }

    FILE *f = fopen(SERVER_STORAGE_PATH SERVER_STORAGE_NAME, "wb");

    if (!f) {
        perror("fopen");
        close(client_fd);
        return 1;
    }

    int body_received = received - header_end;
    fwrite(buffer + header_end, 1, body_received, f);

    while (body_received < content_length) {
        int r = recv(client_fd, buffer, BUFFER_SIZE, 0);
        if (r <= 0)
            break;
        fwrite(buffer, 1, r, f);
        body_received += r;
    }

    fclose(f);

    const char response[] =
        "HTTP/1.1 200 OK\r\n"
        "Content-Length: 2\r\n"
        "\r\n"
        "OK";

    send(client_fd, response, sizeof(response) - 1, 0);

    close(client_fd);
    close(server_fd);

    printf("Upload complete.\n");
    return 0;
}
