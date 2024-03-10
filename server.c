#include <math.h>
#include <netdb.h>
#include <netinet/in.h>
#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <time.h>
#include <unistd.h>
#include "http.h"
#define MAX 1 << 16
#define PORT 8000

unsigned long *HTTP_parserange(char *range, unsigned long size)
{
    char *temp;
    unsigned long *ret;
    if (strncmp(range, "bytes=", 6) != 0) /* must begin with "bytes=" */
        return NULL;
    range += 6;
    temp = strstr(range, "-");               /* first and last pos should be separated by '-' */
    ret = malloc(2 * sizeof(unsigned long)); /* 2 longs for first and last pos */
    if (temp == NULL)                        /* there must be a separator */
        return NULL;
    if (temp - range == 0) /* the '-' is at the beginning meaning first pos is 0 */
        ret[0] = 0;
    else
    {                                                    /* first position is specified */
        if (strspn(range, "0123456789") != temp - range) /* first position must be an integer */
            return NULL;
        ret[0] = strtoul(range, NULL, 10);
    }
    range = temp + 1;
    if (range[0] == '\0') /* the '-' is at the end meaning last pos is SIZE */
        ret[1] = size;
    else
    {                                                     /* last position is specified */
        if (strspn(range, "0123456789") != strlen(range)) /* last position must be an integer */
            return NULL;
        ret[1] = strtoul(range, NULL, 10);
    }
    return ret;
}

void HTTP_filerequest(HTTP_response_t *response, char *path, char *content_type, hashmap_t *headers)
{
    response->protocol = "HTTP/1.1";
    if (response->headers == NULL)
    {
        response->headers = malloc(sizeof(hashmap_t));
        hashmap_init(response->headers);
    }
    hashmap_put(response->headers, "Accept-Ranges", "bytes");
    hashmap_put_if_absent(response->headers, "Cache-Control", "no-cache");
    hashmap_put(response->headers, "Content-Type", content_type);
    FILE *f = fopen(path, "r");
    fseek(f, 0L, SEEK_END);
    unsigned long size = ftell(f); /* file size */
    rewind(f);
    char *rangeh = hashmap_get(headers, "Range");
    if (rangeh != NULL)
    { /* range was specified */
        char *v;
        unsigned long *range = HTTP_parserange(rangeh, size);
        if (range == NULL || range[0] < 0 || range[0] >= size || range[1] < range[0])
        {                    /* invalid range */
            response->code = 416; /* Range Not Satisfiable */
            v = malloc((9 + numlenul(size)) * sizeof(char));
            v[0] = '\0';
            sprintf(v, "bytes */%ld", size);
        }
        else
        {
            if (range[1] > size - 1) /* last pos is capped at size - 1 */
                range[1] = size - 1;
            response->code = 206; /* Partial Content */
            v = malloc((9 + numlenul(range[0]) + numlenul(range[1]) + numlenul(size)) * sizeof(char));
            v[0] = '\0';
            sprintf(v, "bytes %ld-%ld/%ld", range[0], range[1], size);
            response->body = malloc(range[1] - range[0] + 1 * sizeof(char));
            fseek(f, range[0], SEEK_CUR);
            fread(response->body, range[1] - range[0] + 1, sizeof(char), f);
            response->content_length = range[1] - range[0] + 1;
        }
        if (range != NULL)
        {
            free(range);
        }
        hashmap_put(response->headers, "Content-Range", v);
        fclose(f);
    }
    else
    {
        response->code = 200; /* OK */
        response->body = malloc(size * sizeof(char));
        fread(response->body, size, sizeof(char), f);
        response->content_length = size;
    }
    response->reason = HTTP_reason(response->code);
}

void handle(int connfd)
{
    char buff[MAX];
    int n = recv(connfd, buff, sizeof(buff), 0);
    printf("================ REQUEST  ================\n\n");
    if (n < 0)
    {
        printf("RECV ERROR\n\n");
        return;
    }
    if (n == 0)
        printf("EMPTY REQUEST\n\n");
    else
        write(STDOUT_FILENO, buff, n);
    HTTP_response_t res;
    memset(&res, 0, sizeof(HTTP_response_t));
    res.protocol = "HTTP/1.1";
    HTTP_request_t req;
    if (HTTP_parserequest(buff, &req) == NULL)
    {
        res.code = 400; /* Bad Request */
        res.reason = HTTP_reason(res.code);
    }
    else if (strcmp(req.path, "/") == 0)
    {
        if (strcmp(req.method, "GET") == 0)
        {
            HTTP_filerequest(&res, "./index.html", "text/html", req.headers);
        }
        else
        {
            res.code = 405; /* Method Not Allowed */
            res.reason = HTTP_reason(res.code);
        }
    }
    else if (strcmp(req.path, "/favicon.ico") == 0)
    {
        if (strcmp(req.method, "GET") == 0)
        {
            HTTP_filerequest(&res, "./favicon.svg", "image/svg+xml", req.headers);
        }
        else
        {
            res.code = 405; /* Method Not Allowed */
            res.reason = HTTP_reason(res.code);
        }
    }
    else if (strcmp(req.path, "/innertube.js") == 0)
    {
        if (strcmp(req.method, "GET") == 0)
        {
            HTTP_filerequest(&res, "./innertube.js", "application/javascript", req.headers);
        }
        else
        {
            res.code = 405; /* Method Not Allowed */
            res.reason = HTTP_reason(res.code);
        }
    }
    else if (strcmp(req.path, "/audio.mp3") == 0)
    {
        if (strcmp(req.method, "GET") == 0)
        {
            HTTP_filerequest(&res, "./audio.mp3", "audio/mpeg", req.headers);
        }
        else
        {
            res.code = 405; /* Method Not Allowed */
            res.reason = HTTP_reason(res.code);
        }
    }
    else
    {
        res.code = 404; /* Not Found */
        res.reason = HTTP_reason(res.code);
        res.body = calloc(1, sizeof(char));
        res.content_length = 0;
    }
    HTTP_response(connfd, &res);
    printf("\r\n");
    /* cleanup */
    HTTP_request_destroy(&req);
    if (res.headers != NULL)
    {
        char *val;
        if ((val = hashmap_get(res.headers, "Content-Range")) != NULL)
            free(val);
    }
    HTTP_response_destroy(&res);
}

void *thread_main(void *arg)
{
    int connfd = *((int *)arg);
    handle(connfd);
    return NULL;
}

int main(int argc, char *argv)
{
    int sockfd, connfd, len, i;
    struct sockaddr_in serv, cli;

    /* create socket */
    sockfd = socket(AF_INET, SOCK_STREAM, 0);
    if (sockfd == -1)
    {
        printf("socket creation failed\n");
        exit(EXIT_FAILURE);
    }
    bzero(&serv, sizeof(serv));

    /* assign IP, PORT */
    serv.sin_family = AF_INET;
    serv.sin_addr.s_addr = htonl(INADDR_ANY);
    serv.sin_port = htons(PORT);

    /* binding newly created socket to given IP and verification */
    if ((bind(sockfd, (struct sockaddr *)&serv, sizeof(serv))) != 0)
    {
        printf("socket bind failed\n");
        exit(EXIT_FAILURE);
    }
    while (1)
    {
        int n = 16;
        /* now server is ready to listen and verification */
        if ((listen(sockfd, n)) != 0)
        {
            printf("Listen failed\n");
            // continue;
        }
        len = sizeof(cli);
        pthread_t threads[n];
        int conns[n];
        for (int i = 0; i < n; i++)
        {
            /* accept the data packet from client and verification */
            if ((connfd = accept(sockfd, (struct sockaddr *)&cli, &len)) < 0)
            {
                printf("server accept failed\n");
                continue;
            }
            conns[i] = connfd;
            pthread_attr_t attr;
            pthread_attr_init(&attr);
            pthread_create(&threads[i], &attr, &thread_main, &conns[i]);
        }
        for (int i = 0; i < n; i++)
        { /* cleanup threads */
            pthread_join(threads[i], NULL);
            close(conns[i]);
        }
    }
    close(sockfd);
    printf("socket closed\n");
}