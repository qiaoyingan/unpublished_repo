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
#define REQ_MAX_LEN 2500
#define METHOD_MAX_LEN 16
#define PATH_MAX_LEN 128
#define HOST_MAX_LEN 32

struct request {
    char method[METHOD_MAX_LEN];
    char path[PATH_MAX_LEN];
    char host[HOST_MAX_LEN];
    int start;
    int end;
};

struct request read_request(const char* buffer, int length) {
    struct request req;
    int _method = 1, _path = 0, _key = 0, _host = 0;
    int start = 0;
    for (int i = 0; i < length; i++) {
        if (buffer[i] == ' ' && _method) {
            memcpy(req.method, buffer, i - 1);
            req.method[i - 1] = '\0';
            _method = 0;
            _path = 1;
            start = i + 1;
        }
        else if (buffer[i] == ' ' && _path) {
            memcpy(req.path, buffer + start, i - 1 - start);
            req.path[i - 1] = '\0';
            _path = 0;
        } else {
            if (buffer[i] == '\n') {
                if (_host) {
                    memcpy(req.host, buffer + start, i - 1 - start);
                    if (req.host[i - 2 - start] == '\r')
                        req.host[i - 2 - start] = '\0';
                    else
                        req.host[i - 1 - start] = '\0';
                }
                start = i + 1;
                _key = 1;
            } else if (buffer[i] == ':' && _key) {
                char name[REQ_MAX_LEN];
                memcpy(name, buffer + start, i - 1 - start);
                name[i - 1 - start] = '\0';
                if (strcmp(name, "Host") == 0) _host = 1;
                start = i + 2;
            } 
        }
    }
    return req;
}

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
            char buffer[REQ_MAX_LEN];
            int length = recv(connect, buffer, REQ_MAX_LEN, 0);
            printf("request: (%d)\n", length);
            printf("%s\nParse Result:\n", buffer);
            struct request req = read_request(buffer, length);
            printf("method : %s\n", req.method);
            printf("path : %s\n", req.path);
            printf("host : %s\n", req.host);
            // printf("method : %s\n", req.method);

            

            
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
            char request[REQ_MAX_LEN];
            int request_len = recv(connect, request, REQ_MAX_LEN, 0);
            request[request_len] = '\0';
            printf("request: (%d)\n", request_len);
            printf("%s\n", request);
            // char request[MAX_LEN];
            // int request_len = SSL_read(ssl, request, 2000);
            // request[request_len] = '\0';
            // printf("\nrequest: (%d)\n", request_len);
            // printf("%s", request);
            // char hdr[50] = "hello";
            // SSL_write(ssl, hdr, strlen(hdr));
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
