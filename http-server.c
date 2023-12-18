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
#define REQ_MAX_LEN 2048
#define METHOD_MAX_LEN 16
#define PATH_MAX_LEN 128
#define NAME_MAX_LEN 128
#define HOST_MAX_LEN 32
#define RESP_MAX_LEN 2048
#define TYPE_MAX_LEN 32
#define HEAD_MAX_LEN 512
#define BLOCK_SIZE 1024
#define RANGE_MAX_LEN 32

struct request {
    char method[METHOD_MAX_LEN];
    char path[PATH_MAX_LEN];
    char host[HOST_MAX_LEN];
    long long start;
    long long end;
};

struct request read_request(const char* buffer, int length) {
    struct request req;
    int _method = 1, _path = 0, _key = 0, _host = 0, _range = 0;
    int start = 0;
    req.end = req.start = -1;
    for (int i = 0; i < length; i++) {
        if (buffer[i] == ' ' && _method) {
            memcpy(req.method, buffer, i);
            req.method[i] = '\0';
            _method = 0;
            _path = 1;
            start = i + 1;
        }
        else if (buffer[i] == ' ' && _path) {
            memcpy(req.path, buffer + start, i - start);
            req.path[i - start] = '\0';
            _path = 0;
        } else {
            if (buffer[i] == '\n') {
                if (_host) {
                    memcpy(req.host, buffer + start, i - start);
                    if (req.host[i - 1 - start] == '\r')
                        req.host[i - 1 - start] = '\0';
                    else
                        req.host[i - start] = '\0';
                    _host = 0;
                } else if (_range) {
                    char range[RANGE_MAX_LEN], c_start[RANGE_MAX_LEN], c_end[RANGE_MAX_LEN];
                    memcpy(range, buffer + start, i - start);
                    if (range[i - 1 - start] == '\r')
                        range[i - 1 - start] = '\0';
                    else
                        range[i - start] = '\0';
                    for (int i = 6; i < strlen(range); i++) {
                        if (range[i] == '-') {
                            memcpy(c_start, range + 6, i - 6);
                            c_start[i - 6] = '\0';
                            req.start = (long long) (atoi(c_start));
                            if (i != strlen(range) - 1) {
                                memcpy(c_end, range + i + 1, strlen(range) - (i + 1));
                                c_end[strlen(range) - (i + 1)] = '\0';
                                req.end = (long long) (atoi(c_end)); 
                            }
                        }
                    }
                }
                start = i + 1;
                _key = 1;
            } else if (buffer[i] == ':' && _key) {
                char name[NAME_MAX_LEN];
                memcpy(name, buffer + start, i - start);
                name[i - start] = '\0';
                if (strcmp(name, "Host") == 0) _host = 1; 
                if (strcmp(name, "Range") == 0) _range = 1;
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
            char buffer[REQ_MAX_LEN];
            int length = recv(connect, buffer, REQ_MAX_LEN, 0);
            // printf("request: (%d)\n", length);
            // printf("%s\nParse Result:\n", buffer);
            struct request req = read_request(buffer, length);
            // printf("method : %s\n", req.method);
            // printf("path : %s\n", req.path);
            // printf("host : %s\n", req.host);
            char message[RESP_MAX_LEN];
            sprintf(message, "HTTP/1.1 301 Moved Permanently\r\nContent-Length: 0\r\nLocation: https://%s%s\r\n\r\n", req.host, req.path);
            send(connect, message, strlen(message), 0);    
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

            char buffer[REQ_MAX_LEN];
            int length = SSL_read(ssl, buffer, 2000);
            // printf("request: (%d)\n", strlen(buffer));
            // printf("%s\n", buffer);
            struct request req = read_request(buffer, length);
            // printf("method : %s\n", req.method);
            // printf("path : %s\n", req.path);
            // printf("host : %s\n", req.host);
            // printf("start : %lld\n", req.start);
            // printf("end : %lld\n", req.end);

            char type[TYPE_MAX_LEN];
            for (int i = 0; i < PATH_MAX_LEN; i++)
                if (req.path[i] == '.') {
                    if (req.path[i + 1] == 'h') strcpy(type, "text/html");
                    else strcpy(type, "video/mpeg");
                }
            
            FILE *f = fopen(req.path + 1, "r");
            if (f == NULL) {
                char header[] = "HTTP/1.1 404 Not Found\r\nContent-type: text/html\r\n\r\n";
                SSL_write(ssl, header, strlen(header));
            } else if (req.start == -1) {
                char header[HEAD_MAX_LEN];
                char file_block[BLOCK_SIZE];
                sprintf(header, "HTTP/1.1 200 OK\r\nContent-type: %s\r\n\r\n", type);
                SSL_write(ssl, header, strlen(header));
                while (!feof(f)) {
                    long long _ = fread(file_block, 1, BLOCK_SIZE, f);
                    SSL_write(ssl, file_block, _);
                }
                fclose(f);
            } else {
                fseek(f, 0, SEEK_END);
                long long total_len = ftell(f);
                fseek(f, 0, SEEK_SET);
                fseek(f, req.start, SEEK_SET);
                long long end = req.end == -1 ? total_len - 1 : req.end >= total_len ? total_len - 1 : req.end;
                long long req_len = end - req.start + 1;
                char header[HEAD_MAX_LEN];
                char file_block[BLOCK_SIZE];
                sprintf(header, "HTTP/1.1 206 Partial Content\r\nAccept-Ranges: bytes\r\nContent-Length: %lld\r\nContent-Range: bytes %lld-%lld/%lld\r\nContent-type: %s\r\n\r\n", req_len, req.start, end, req_len, type);
                SSL_write(ssl, header, strlen(header));
                while (req_len > 0) {
                    long long _ = fread(file_block, 1, req_len >= BLOCK_SIZE ? BLOCK_SIZE : req_len, f);
                    req_len = req_len - BLOCK_SIZE;
                    SSL_write(ssl, file_block, _);
                }
            }
            
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
