#include <assert.h>
#include <fcntl.h>
#include <signal.h>
#include <stddef.h>
#include <stdio.h>
#include <string.h>
#include <pthread.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <openssl/ssl.h>
#include <openssl/err.h>
#include <sys/msg.h>
#include <sys/socket.h>
#include <pthread.h>
#include<stdlib.h>

SSL_CTX *ctx = NULL;
const static char http_error_hdr[] = "HTTP/1.1 404 Not Found\r\nContent-type: text/html\r\n\r\n";
#define FILE_BUF_SIZE 2048

typedef struct http_request{
	int valid;    // 0,1
	char method[10];    // "GET"
	char path[128];    // "/","/index.html"
	char host[30];    // 10.0.0.1:8080
	long range_start;   // 0,-1
	long range_end;    // 123456,-1
} http_request_t;

http_request_t parse_http_request(char buf[]){
	http_request_t http_request;
	http_request.range_start = -1;
	http_request.range_end = -1;
	http_request.valid = 1;
	char *ptr;
	char *saveptr;
	ptr = strtok_r(buf," ",&saveptr);
	if(ptr == NULL){
		printf("Method Invalid\n");
		http_request.valid = 0;
		return http_request;
	}
	strncpy(http_request.method,ptr,9);
	ptr = strtok_r(NULL," ",&saveptr);
		if(ptr == NULL){
		printf("Path Invalid\n");
		http_request.valid = 0;
		return http_request;
	}
	strncpy(http_request.path,ptr,127);
	printf("method:%s\n",http_request.method);
	printf("path:%s\n",http_request.path);
	ptr = strtok_r(NULL,"\n",&saveptr);    //HTTP/1.1
	while (ptr != NULL){
		// printf("new line:%s\n",ptr);
		ptr = strtok_r(NULL,":",&saveptr);
		char field_name[50] = "";
		char field_value[50] = "";
		if(ptr != NULL){
			strncpy(field_name,ptr,49);
			ptr = strtok_r(NULL,"\n",&saveptr);	
			if(ptr != NULL){
				strncpy(field_value,ptr+1,49);
				// printf("last char of value:%d",field_value[strlen(field_value)-1]);
				if(field_value[strlen(field_value)-1]=='\r'){
					field_value[strlen(field_value)-1]='\0';
				}
				printf("name:%s,value:%s\n",field_name,field_value);
				if(strcmp(field_name,"Host")==0){
					strncpy(http_request.host,field_value,29);
					// printf("host len:%d\n",strlen(http_request.host));
				}
				else if (strcmp(field_name,"Range")==0){
					char *ptr1;
					char *saveptr1;
					ptr1 = strtok_r(field_value,"-",&saveptr1);
					http_request.range_start = atol(ptr1+6);
					if(strlen(saveptr1)>0){
						http_request.range_end = atol(saveptr1);
					}
				}
			}
		}
	}
	printf("====parse end====\n");
	return http_request;
}

int socket_init(int port)
{
    int socketfd = socket(AF_INET, SOCK_STREAM, 0);
    if (socketfd < 0)
        printf("socket create error");
    struct sockaddr_in saddr;
    saddr.sin_family = AF_INET;
    saddr.sin_port = htons(port);
    saddr.sin_addr.s_addr = INADDR_ANY;

    if (bind(socketfd, (struct sockaddr *)&saddr, sizeof(saddr)) < 0)
        printf("bind error");

    if (listen(socketfd, 10) < 0)
        printf("listen error");

    return socketfd;
}

void fun80()
{
    int socket80fd = socket_init(80);
    int cfd80 = 0;
    while (1)
    {
        // printf("test80\n");
        if ((cfd80 = accept(socket80fd, NULL, NULL)) == -1)
            continue;
        else
        {
            printf("ok80\n");

            // receive
            char request[2000];
            int request_len = recv(cfd80, request, 2000, 0);
            request[request_len] = '\0';
            printf("\nrequest: (%d)\n", request_len);
            printf("%s", request);

            char buf_cpy[2000];
            strncpy(buf_cpy,request,2000);
            http_request_t req = parse_http_request(buf_cpy);

            // response
            char response[2000] = "";
            sprintf(response,"hello");
            printf("send response\n");
            send(connect, response, strlen(response), 0);
        };
        close(cfd80);
    }
}
void fun443()
{
    int socket443fd = socket_init(443);
    int cfd443 = 0;
    while (1)
    {
        // printf("test443\n");
        if ((cfd443 = accept(socket443fd, NULL, NULL)) == -1)
        {
            close(cfd443);
            continue;
        }
        else
        {
            printf("ok443\n");
            SSL *ssl;
            ssl = SSL_new(ctx);
            SSL_set_accept_state(ssl);
            SSL_set_fd(ssl, cfd443);
            if (SSL_accept(ssl) == -1)
            {
                close(cfd443);
                printf("ssl error\n");
                continue;
            }

            char request[2000];
            int request_len = SSL_read(ssl, request, 2000);
            request[request_len] = '\0';
            printf("\nrequest: (%d)\n", request_len);
            printf("%s", request);
            char hdr[50] = "hello";
            SSL_shutdown(ssl);
            SSL_free(ssl);
        };
        close(cfd443);
    }
}

int main()
{
    signal(SIGPIPE, SIG_IGN);

    // SSL
    SSL_library_init();
    OpenSSL_add_all_algorithms();
    SSL_load_error_strings();
    ERR_load_crypto_strings();
    ctx = SSL_CTX_new(SSLv23_server_method());
    SSL_CTX_use_certificate_file(ctx, "keys/cnlab.cert", SSL_FILETYPE_PEM);
    SSL_CTX_use_PrivateKey_file(ctx, "keys/cnlab.prikey", SSL_FILETYPE_PEM);

    // 2-pthread
    pthread_t id[2];
    pthread_create(&id[0], NULL, (void *)fun80, NULL);
    pthread_create(&id[1], NULL, (void *)fun443, NULL);

    while (1)
    {
    }

    return 0;
}
