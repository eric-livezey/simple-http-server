#include <netdb.h>
#include <pthread.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include "http.h"
#define PORT 8000

char debug = 0;

void HTTP_print_request(HTTP_request *req)
{
    printf("================ REQUEST  ================\r\n\r\n");

    printf("%s %s", req->method, req->target);
    struct entry **es = MAP_entry_set(req->query);
    int size = MAP_size(req->query);
    int i;
    for (i = 0; i < size; i++)
    {
        if (i == 0)
            printf("?");
        printf("%s=%s", es[i]->key, es[i]->value);
        if (i < size - 1)
            printf("&");
    }
    printf(" %s\r\n", req->protocol);

    es = MAP_entry_set(req->headers);
    size = MAP_size(req->headers);
    for (i = 0; i < size; i++)
    {
        printf("%s: %s\r\n", es[i]->key, es[i]->value);
    }
    printf("\r\n");
}

void HTTP_print_response(HTTP_response *res)
{
    unsigned long size = HTTP_ressize(res);
    char *resmsg = malloc(size);
    HTTP_resmsg(res, resmsg);
    resmsg[size - res->content_length - 1] = '\0';
    printf("---------------- RESPONSE ----------------\r\n\r\n%s\r\n", resmsg); /* print response (excluding body) */
    free(resmsg);
}

char HTTP_respond_file(HTTP_request *req, char *path, char *content_type, HTTP_response *res, int fd)
{
    MAP_put(res->headers, "Accept-Ranges", "bytes");
    MAP_put_if_absent(res->headers, "Cache-Control", "no-cache");
    MAP_put(res->headers, "Content-Type", content_type);
    FILE *fp = fopen(path, "r");
    fseek(fp, 0L, SEEK_END);
    unsigned long size = ftell(fp); /* file size */
    char *rangeh = MAP_get(req->headers, "Range");
    if (rangeh != NULL)
    { /* range was specified */
        unsigned long range[2];
        parse_range(rangeh, size, range);
        if (range == NULL || range[0] < 0 || range[0] >= size || range[1] < range[0])
        {
            res->code = 416; /* Range Not Satisfiable */
            res->reason = HTTP_reason(res->code);
            char content_range[9 + numlenul(size)];
            content_range[0] = '\0';
            sprintf(content_range, "bytes */%ld", size);
            MAP_put(res->headers, "Content-Range", content_range);
            HTTP_send_response(res, fd);
            if (debug)
                HTTP_print_response(res);
        }
        else
        {
            if (range[1] > size - 1) /* last pos is capped at size - 1 */
                range[1] = size - 1;
            res->code = 206; /* Partial Content */
            res->reason = HTTP_reason(res->code);
            /* content-range */
            char content_range[9 + numlenul(range[0]) + numlenul(range[1]) + numlenul(size)];
            content_range[0] = '\0';
            sprintf(content_range, "bytes %ld-%ld/%ld", range[0], range[1], size);
            MAP_put(res->headers, "Content-Range", content_range);
            /* size */
            size = range[1] - range[0] + 1;
            /* content-length */
            char content_length[numlenul(size)];
            content_length[0] = '\0';
            sprintf(content_length, "%lu", size);
            MAP_put(res->headers, "Content-Length", content_length);
            HTTP_send_response(res, fd);
            if (strcmp(req->method, "HEAD") != 0)
                /* body */
                send_file(fd, fp, range[0], range[1]);
            if (debug)
                HTTP_print_response(res);
        }
    }
    else
    {

        res->reason = HTTP_reason(res->code);
        /* content-length */
        char content_length[numlenul(size)];
        content_length[0] = '\0';
        sprintf(content_length, "%lu", size);
        MAP_put(res->headers, "Content-Length", content_length);
        HTTP_send_response(res, fd);
        /* body */
        if (strcmp(req->method, "HEAD") != 0)
            send_file(fd, fp, 0, size - 1);
        if (debug)
            HTTP_print_response(res);
    }
    fclose(fp);
    HTTP_request_free(req);
    HTTP_response_free(res);
}

/**
 * read an HTTP request from `fd` and place the parsed data in `result`. If the data read is invalid, will return `NULL` and set `result->flags` accordingly.
 * @param fd a file descriptor
 * @param result an HTTP request struct to put the parsed data
 */
HTTP_request *HTTP_readreq_ex(int fd, HTTP_request *result)
{
    char *data = NULL, *temp, *k, *v;
    long i = 0, saven, ret;
    struct entry e;
    result->method = NULL;
    result->target = NULL;
    result->query = MAP_new(1);
    result->protocol = NULL;
    result->headers = MAP_new(1);
    result->content = NULL;
    result->content_length = 0;
    result->trailers = MAP_new(1);
    result->stack = STACK_new();
    result->flags = 0;
    ret = recv_line(fd, &data);
    if (ret < 0)
    {
        if (ret == -1)
            result->flags |= CONNECTION_ERROR;
        if (ret == -2)
            result->flags |= CONTENT_TOO_LARGE;
        if (ret == -3)
            result->flags |= CONNECTION_CLOSED;
        return NULL;
    }
    STACK_push(result->stack, data);
    if (HTTP_parse_reqln(data, result) == NULL)
    {
        result->flags |= PARSE_ERROR;
        return NULL;
    }
    while (1)
    {
        ret = recv_line(fd, &data);
        if (ret < 0)
        {
            if (ret == -1)
                result->flags |= CONNECTION_ERROR;
            if (ret == -2)
                result->flags |= CONTENT_TOO_LARGE;
            if (ret == -3)
                result->flags |= CONNECTION_CLOSED;
            return NULL;
        }
        STACK_push(result->stack, data);
        if (ret == 0)
            break;
        /* field-lines */
        if (HTTP_parse_fieldln(data, &e) == NULL)
        {
            result->flags |= PARSE_ERROR;
            return NULL;
        }
        if ((k = MAP_get(result->headers, e.key)) != NULL && e.value != NULL)
        {
            k = buffcat(k, strlen(k), ", ", 3);
            e.key = buffcat(k, strlen(k), e.key, strlen(e.key) + 1);
            free(k);
            STACK_push(result->stack, e.key);
        }
        MAP_put(result->headers, e.key, e.value);
    }
    /* message body */
    if ((v = MAP_get(result->headers, "Transfer-Encoding")) != NULL && *v != '\0')
    {
        int len = 1;
        char *ptr = v;
        while (*ptr != '\0')
        {
            if (*ptr == ',')
                len++;
            ptr++;
        }
        char *encodings[len];
        int i = 0;
        encodings[0] = v;
        ptr = v;
        while (*ptr != '\0')
        {
            if (*ptr == ',')
            {
                *ptr = '\0';
                i++;
                encodings[i] = ptr + 1;
            }
            ptr++;
        }
        for (i = 0; i < len; i++)
            if (strcasecmp(encodings[i], "chunked") == 0)
                recv_chunks(fd, result);
    }
    else if (MAP_contains_key(result->headers, "Content-Length"))
    {
        char *ptr, *endptr;
        unsigned long content_length = strtoul(ptr = MAP_get(result->headers, "Content-Length"), &endptr, 10);
        if (*ptr == '\0' || *endptr != '\0')
        {
            result->flags |= BAD_CONTENT_LENGTH;
            return NULL;
        }
        if (content_length > 8UL * (1 << 30)) // 8 GB limit
        {
            /*
             * NOTE: if we don't read the request to completion, the client will likely not receive the response
             * but reading the whole request will take far too long with 8GB+ file sizes and thus waste resources
             * so even though the request may be valid, we reject it immediately and close the connection.
             */
            result->flags |= CONTENT_TOO_LARGE;
            return NULL;
        }
        result->content = malloc(content_length);
        unsigned short size = 65535;
        unsigned long bytes = 0;
        while (bytes < content_length)
        {
            ret = recv(fd, result->content + bytes, bytes + size > content_length ? content_length - bytes : size, 0);
            if (ret <= 0)
            {
                free(result->content);
                result->flags |= CONNECTION_ERROR;
                return NULL;
            }
            bytes += ret;
        }
        STACK_push(result->stack, result->content);
        result->content_length = content_length;
    }
    return result;
}

void handleconn(int fd)
{
    char persist = 1, *v, *ptr;
    unsigned long n;
    HTTP_request req;
    HTTP_response res;
    struct content_type content_type;
    struct multipart parts;
    struct stat path_stat;
    content_type.parameters = MAP_new(1);
    while (persist)
    {
        res.protocol = "HTTP/1.1";
        res.code = 200;
        res.reason = HTTP_reason(res.code);
        res.headers = MAP_new(1);
        res.content = NULL;
        res.content_length = 0;
        res.trailers = MAP_new(1);
        res.stack = STACK_new();
        if (HTTP_readreq_ex(fd, &req) == NULL)
        {
            if ((req.flags & CONNECTION_CLOSED) != 0)
                break;
            if ((req.flags & CONTENT_TOO_LARGE) != 0)
                res.code = 413; /* Content Too Large */
            else
                res.code = 400; /* Bad Request */
            MAP_put(res.headers, "Connection", "close");
            persist = 0;
        }
        else
        {
            if (debug)
                HTTP_print_request(&req);
            v = MAP_get(req.headers, "Connection");
            if (v != NULL && strcmp(v, "close") == 0 || strcmp(req.protocol, "HTTP/1.0") && (v == NULL || strcmp(v, "keep-alive") != 0))
            {
                MAP_put(res.headers, "Connection", "close");
                persist = 0;
            }
            else
            {
                MAP_put(res.headers, "Connection", "keep-alive");
                persist = 1;
            }
            if ((v = MAP_get(req.headers, "Content-Type")) != NULL)
            {
                if (req.content == NULL || parse_content_type(v, &content_type) == NULL)
                {
                    res.code = 400; /* Bad Request */
                    res.reason = HTTP_reason(res.code);
                    HTTP_send_response(&res, fd);
                    if (debug)
                        HTTP_print_response(&res);
                    HTTP_request_free(&req);
                    HTTP_response_free(&res);
                    MAP_clear(content_type.parameters);
                    continue;
                }
                if (strcasecmp(content_type.type, "multipart") == 0)
                {
                    if ((v = MAP_get(content_type.parameters, "boundary")) == NULL)
                    {
                        res.code = 400; /* Bad Request */
                        res.reason = HTTP_reason(res.code);
                        HTTP_send_response(&res, fd);
                        if (debug)
                            HTTP_print_response(&res);
                        HTTP_request_free(&req);
                        HTTP_response_free(&res);
                        MAP_clear(content_type.parameters);
                        continue;
                    }
                    parts.stack = STACK_new();
                    parse_multipart(req.content, req.content_length, v, &parts);
                    // Temporary implementation only takes the first part
                    // different parts might have different content types and thus storing it is somewhat cumbersome
                    if (parts.length == 1)
                    {
                        req.content = parts.parts[0].content;
                        req.content_length = parts.parts[0].content_length;
                        MAP_put_all(req.headers, parts.parts[0].headers);
                        MAP_free(parts.parts[0].headers);
                        while (!STACK_empty(parts.stack))
                            STACK_push(req.stack, STACK_pop(parts.stack));
                        STACK_free(parts.stack);
                    }
                    else
                    {
                        for (int i = 0; i < parts.length; i++)
                        {
                            MAP_free(parts.parts[i].headers);
                        }
                        STACK_free(parts.stack);
                    }
                }
                MAP_clear(content_type.parameters);
            }
            if (strcmp(req.method, "PUT") == 0 || strcmp(req.method, "DELETE") == 0 || strcmp(req.method, "CONNECT") == 0 || strcmp(req.method, "OPTIONS") == 0 || strcmp(req.method, "TRACE") == 0)
            {
                res.code = 501;
            }
            else if (strcmp(req.target, "/") == 0)
            {
                if (strcmp(req.method, "GET") == 0)
                {
                    HTTP_respond_file(&req, "./index.html", "text/html", &res, fd);
                    continue;
                }
                else
                {
                    res.code = 405; /* Method Not Allowed */
                    MAP_put(res.headers, "Content-Length", "0");
                }
            }
            else if (strcmp(req.target, "/favicon.ico") == 0)
            {
                if (strcmp(req.method, "GET") == 0)
                {
                    MAP_put(res.headers, "Cache-Control", "max-age=6000");
                    HTTP_respond_file(&req, "./favicon.svg", "image/svg+xml", &res, fd);
                    continue;
                }
                else
                {
                    res.code = 405; /* Method Not Allowed */
                    MAP_put(res.headers, "Content-Length", "0");
                }
            }
            else if (strcmp(req.target, "/video.mp4") == 0)
            {
                if (strcmp(req.method, "GET") == 0)
                {
                    if (access("./video.mp4", F_OK) == 0)
                    {

                        MAP_put(res.headers, "Cache-Control", "max-age=60");
                        HTTP_respond_file(&req, "./video.mp4", "video/mp4", &res, fd);
                        continue;
                    }
                    else
                    {
                        res.code = 404; /* Not Found */
                        MAP_put(res.headers, "Content-Length", "0");
                    }
                }
                else if (strcmp(req.method, "POST") == 0)
                {

                    FILE *fp = fopen("./video.mp4", "w");
                    fwrite(req.content, req.content_length, 1, fp);
                    fclose(fp);
                    res.code = 201; /* Created */
                    HTTP_respond_file(&req, "./video.mp4", "video/mp4", &res, fd);
                    continue;
                }
                else
                {
                    res.code = 405; /* Method Not Allowed */
                    MAP_put(res.headers, "Content-Length", "0");
                }
            }
            else
            {
                char path[strlen(req.target) + 2];
                path[0] = '.';
                strcpy(path + 1, req.target);
                if (access(path, F_OK) == 0 && stat(path, &path_stat) == 0 && S_ISREG(path_stat.st_mode))
                {
                    if (strcmp(req.method, "GET") == 0)
                    {
                        if (strncmp(req.target, "/assets/", 8) == 0)
                        {
                            MAP_put(res.headers, "Cache-Control", "max-age=31536000");
                        }
                        char *content_type = "*";
                        int index = strlastindexof(req.target, '.');
                        if (index >= 0)
                        {
                            content_type = HTTP_content_type(req.target + index + 1); // infer content type
                        }
                        HTTP_respond_file(&req, path, content_type, &res, fd);
                        continue;
                    }
                    else
                    {
                        res.code = 405; /* Method Not Allowed */
                        MAP_put(res.headers, "Content-Length", "0");
                    }
                }
                else
                {
                    res.code = 404; /* Not Found */
                    MAP_put(res.headers, "Content-Length", "0");
                }
            }
        }
        res.reason = HTTP_reason(res.code);
        HTTP_send_response(&res, fd);
        if (debug)
            HTTP_print_response(&res);
        HTTP_request_free(&req);
        HTTP_response_free(&res);
    }
    MAP_free(content_type.parameters);
    close(fd);
}

void *thread_main(void *arg)
{
    handleconn(*((int *)arg));
    return NULL;
}

int main(int argc, char **argv)
{
    char *ptr;
    unsigned short port = PORT;
    int sockfd, connfd, len, i;
    struct sockaddr_in server, client;

    int j = 0;
    for (i = 1; i < argc; i++)
    {
        ptr = argv[i];
        if (*ptr == '-')
        {
            if (strcmp(ptr, "--debug") == 0)
                debug = 1;
            else
            {
                printf("unrecognized flag: %s\n", ptr);
                return 1;
            }
        }
        else if (j == 0)
        {
            char *endptr = NULL;
            port = (unsigned short)strtol(ptr, &endptr, 10);
            if (*ptr == '\0' || *endptr != '\0')
            {
                printf("invalid port: %s\n", ptr);
                return 1;
            }
            j++;
        }
    }
    /* create socket */
    sockfd = socket(AF_INET, SOCK_STREAM, 0);
    if (sockfd == -1)
    {
        printf("socket creation failed\n");
        return 1;
    }
    bzero(&server, sizeof(server));

    /* assign IP, PORT */
    server.sin_family = AF_INET;
    server.sin_addr.s_addr = htonl(INADDR_ANY);
    server.sin_port = htons(port);

    /* bind newly created socket to given IP and verification */
    if ((bind(sockfd, (struct sockaddr *)&server, sizeof(server))) != 0)
    {
        printf("socket bind failed\n");
        return 1;
    }
    while (1)
    {
        int n = 100;
        /* now server is ready to listen and verification */
        if ((listen(sockfd, n)) != 0)
            printf("Listen failed\n");
        len = sizeof(client);
        pthread_t threads[n];
        int conns[n];
        for (int i = 0; i < n; i++)
        {
            /* accept the data packet from client and verification */
            if ((connfd = accept(sockfd, (struct sockaddr *)&client, &len)) < 0)
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
    return 0;
}
