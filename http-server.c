#include <assert.h>
#include <fcntl.h>
#include <signal.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <pthread.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <openssl/ssl.h>
#include <openssl/err.h>
#include <sys/msg.h>
#include <sys/socket.h>

#define HTTP_PORT 80
#define HTTPS_PORT 443
#define MAX_LEN 2500

int init_socket(int port) {
    int fd = socket(AF_INET, SOCK_STREAM, 0);
    struct sockaddr_in saddr;
    saddr.sin_family = AF_INET;
    saddr.sin_port = htons(port);
    saddr.sin_addr.s_addr = INADDR_ANY;
    if (bind(fd, (struct sockaddr *)&saddr, sizeof(saddr)) < 0) printf("bind error of %d!\n", fd);
    if (listen(fd, 10) < 0) printf("listen error of socket %d!\n", fd);
    printf("successfully init socket %d!\n", fd);
    return fd;
}

void http_server() {
    int fd = init_socket(HTTP_PORT), connect = 0;
    while (1) {
        if ((connect = accept(fd, NULL, NULL)) == -1) continue;
        else {
            printf("successfully connect socket %d, %d!\n", fd, connect);
            /*
                todo: Receive and Parse Messages.
            */
            // char request[MAX_LEN];
            // int request_len = recv(connect, request, MAX_LEN, 0);
            // request[request_len] = '\0';
            // printf("request: (%d)\n", request_len);
            // printf("%s\n", request);
            // printf("%d\n", strlen(request));
            // char response[MAX_LEN] = "";
            // sprintf(response,"hello");
            // printf("send response\n");
            // send(connect, response, strlen(response), 0);
        }
        close(connect);
    }
    printf("close socket %d, %d!\n", fd, connect);
}

void https_server() {
    int fd = init_socket(HTTPS_PORT), connect = 0;
    SSL_library_init();
    OpenSSL_add_all_algorithms();
    SSL_load_error_strings();
    SSL_CTX *ctx = SSL_CTX_new(SSLv23_server_method());
    SSL_CTX_use_certificate_file(ctx, "keys/cnlab.cert", SSL_FILETYPE_PEM);
    SSL_CTX_use_PrivateKey_file(ctx, "keys/cnlab.prikey", SSL_FILETYPE_PEM);

    while (1) {
        if ((connect = accept(fd, NULL, NULL)) == -1) continue;
        else {
            printf("successfully connect socket %d, %d!\n", fd, connect);
            SSL *ssl = SSL_new(ctx);
            SSL_set_accept_state(ssl);
            SSL_set_fd(ssl, connect);
            if (SSL_accept(ssl) == -1) printf("ssl error!\n");
            /*
                todo: Receive and Parse Messages.
            */
            // char request[MAX_LEN];
            // int request_len = SSL_read(ssl, request, 2000);
            // request[request_len] = '\0';
            // printf("\nrequest: (%d)\n", request_len);
            // printf("%s", request);
            // char hdr[50] = "hello";
            SSL_write(ssl, hdr, strlen(hdr));
            SSL_shutdown(ssl);
            SSL_free(ssl);
        }
        close(connect);
    }
    printf("close socket %d, %d!\n", fd, connect);
}

int main () {
    pthread_t tid[2];
    pthread_create(&tid[0], NULL, (void *)http_server, NULL);
    pthread_create(&tid[1], NULL, (void *)https_server, NULL);
    pthread_join(tid[0], NULL);
    pthread_join(tid[1], NULL);
    return 0;
}
