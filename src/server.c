#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#ifdef _WIN32
    #include <winsock2.h>
    #include <ws2tcpip.h>
    #pragma comment(lib, "ws2_32.lib")
    typedef SOCKET socket_t;
    #define close_socket closesocket
#else
    #include <unistd.h>
    #include <arpa/inet.h>
    #include <sys/socket.h>
    typedef int socket_t;
    #define close_socket close
#endif

#include "config.h"

#define BUFFER_SIZE 4096

int main(void)
{
#ifdef _WIN32
    WSADATA wsa;
    if (WSAStartup(MAKEWORD(2,2), &wsa) != 0) {
        fprintf(stderr, "WSAStartup failed\n");
        return 1;
    }
#endif

    socket_t server_fd;
    struct sockaddr_in addr;

#ifdef _WIN32
    int addrlen = sizeof(addr);
#else
    socklen_t addrlen = sizeof(addr);
#endif

    server_fd = socket(AF_INET, SOCK_STREAM, 0);
    if (server_fd == (socket_t)-1) {
        perror("socket");
        return 1;
    }

#ifndef _WIN32
    int opt = 1;
    setsockopt(server_fd, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt));
#endif

    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = htonl(INADDR_ANY);
    addr.sin_port = htons(SERVER_PORT);

    if (bind(server_fd, (struct sockaddr *)&addr, sizeof(addr)) < 0) {
        perror("bind");
        close_socket(server_fd);
        return 1;
    }

    if (listen(server_fd, 5) < 0) {
        perror("listen");
        close_socket(server_fd);
        return 1;
    }

    printf("Listening on port %d...\n", SERVER_PORT);

    while (1) {
        socket_t client_fd = accept(server_fd, (struct sockaddr *)&addr, &addrlen);
        if (client_fd == (socket_t)-1) {
            perror("accept");
            continue;
        }

        char buffer[BUFFER_SIZE];
        int received = 0;
        int header_end = 0;
        int content_length = 0;

        /* Read HTTP headers */
        while (!header_end) {
            int r = recv(client_fd,
                         buffer + received,
                         BUFFER_SIZE - received,
                         0);
            if (r <= 0) {
                perror("recv");
                close_socket(client_fd);
                goto next_client;
            }

            received += r;

            char *end = strstr(buffer, "\r\n\r\n");
            if (end) {
                header_end = (int)(end - buffer) + 4;

                char *cl = strstr(buffer, "Content-Length:");
                if (!cl) {
                    fprintf(stderr, "No Content-Length header\n");
                    close_socket(client_fd);
                    goto next_client;
                }

                sscanf(cl, "Content-Length: %d", &content_length);
            }
        }

        FILE *f = fopen(SERVER_STORAGE_PATH SERVER_STORAGE_NAME, "wb");
        if (!f) {
            perror("fopen");
            close_socket(client_fd);
            goto next_client;
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

        close_socket(client_fd);
        printf("Upload complete.\n");

next_client:
        ;
    }

#ifdef _WIN32
    WSACleanup();
#endif

    close_socket(server_fd);
    return 0;
}
