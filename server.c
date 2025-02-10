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
    printf("================ REQUEST  ================\r\n\r\n%s %s", req->method, req->target);
    struct entry **es = MAP_entry_set(req->query);
    int size = MAP_size(req->query);
    int i;
    for (i = 0; i < size; i++)
    {
        if (i == 0)
            printf("?");
        printf("%s=%s", es[i]->key, (char *)es[i]->value);
        if (i < size - 1)
            printf("&");
    }
    printf(" %s\r\n", req->protocol);

    es = MAP_entry_set(req->headers);
    size = MAP_size(req->headers);
    for (i = 0; i < size; i++)
    {
        printf("%s: %s\r\n", es[i]->key, (char *)es[i]->value);
    }
    printf("\r\n");
}

void HTTP_print_response(HTTP_response *res)
{
    unsigned long size = HTTP_ressize(res, 1);
    char *resmsg = malloc(size);
    HTTP_resmsg(res, resmsg, 1);
    printf("---------------- RESPONSE ----------------\r\n\r\n%s\r\n", resmsg); /* print response head */
    free(resmsg);
}

char HTTP_respond_file(HTTP_request *req, char *path, HTTP_response *res, int fd)
{
    MAP_put(res->headers, "Accept-Ranges", "bytes");
    MAP_put_if_absent(res->headers, "Cache-Control", "no-cache");
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
            char *content_range = malloc(numlenul(size) + 9);
            STACK_push(res->stack, content_range);
            *content_range = '\0';
            sprintf(content_range, "bytes */%ld", size);
            MAP_put(res->headers, "Content-Range", content_range);
            HTTP_send_response(res, fd, 0);
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
            char *content_range = malloc(numlenul(range[0]) + numlenul(range[1]) + numlenul(size) + 9);
            STACK_push(res->stack, content_range);
            *content_range = '\0';
            sprintf(content_range, "bytes %ld-%ld/%ld", range[0], range[1], size);
            MAP_put(res->headers, "Content-Range", content_range);
            /* size */
            size = range[1] - range[0] + 1;
            /* content-length */
            char *content_length = malloc(numlenul(size) + 1);
            STACK_push(res->stack, content_length);
            *content_length = '\0';
            sprintf(content_length, "%lu", size);
            MAP_put(res->headers, "Content-Length", content_length);
            HTTP_send_response(res, fd, 1);
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
        char *content_length = malloc(numlenul(size) + 1);
        *content_length = '\0';
        sprintf(content_length, "%lu", size);
        MAP_put(res->headers, "Content-Length", content_length);
        HTTP_send_response(res, fd, 1);
        /* body */
        if (strcmp(req->method, "HEAD") != 0)
            send_file(fd, fp, 0, size - 1);
        if (debug)
            HTTP_print_response(res);
    }
    fclose(fp);
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

typedef void(request_handler)(HTTP_request *, HTTP_response *);

struct path_handler
{
    request_handler *get;
    request_handler *post;
    request_handler *put;
    request_handler *patch;
    request_handler *delete;
};

request_handler *default_handler = NULL;
MAP *handlers = NULL;

void set_default_handler(request_handler *handler)
{
    default_handler = handler;
}

void set_path_handler(char *target, char *method, request_handler *handler)
{
    if (handlers == NULL)
        handlers = MAP_new(0);
    struct path_handler *path_handler;
    if ((path_handler = MAP_get(handlers, target)) == NULL)
        MAP_put(handlers, target, path_handler = calloc(1, sizeof(struct path_handler)));
    if (strcmp(method, "GET") == 0)
        path_handler->get = handler;
    else if (strcmp(method, "POST") == 0)
        path_handler->post = handler;
    else if (strcmp(method, "PUT") == 0)
        path_handler->put = handler;
    else if (strcmp(method, "PATCH") == 0)
        path_handler->patch = handler;
    else if (strcmp(method, "DELETE") == 0)
        path_handler->delete = handler;
}

char *generate_allow(struct path_handler *handler)
{
    char *result = malloc(36);
    *result = '\0';
    if (handler->get != NULL)
        strcat(result, "GET, HEAD");
    if (handler->post != NULL)
    {
        if (*result != '\0')
            strcat(result, ", ");
        strcat(result, "POST");
    }
    if (handler->put != NULL)
    {
        if (*result != '\0')
            strcat(result, ", ");
        strcat(result, "PUT");
    }
    if (handler->patch != NULL)
    {
        if (*result != '\0')
            strcat(result, ", ");
        strcat(result, "PATCH");
    }
    if (handler->delete != NULL)
    {
        if (*result != '\0')
            strcat(result, ", ");
        strcat(result, "DELETE");
    }
    return result;
}

void handle_conn(int fd)
{
    char persist = 1, *ptr;
    HTTP_request req;
    HTTP_response res;
    struct path_handler *handler;
    while (persist)
    {
        res.protocol = "HTTP/1.1";
        res.code = 200; /* OK */
        res.reason = HTTP_reason(res.code);
        res.headers = MAP_new(1);
        res.file = NULL;
        res.content = NULL;
        res.content_length = 0;
        res.trailers = MAP_new(1);
        res.stack = STACK_new();
        /* read a request from the connection */
        if (HTTP_readreq_ex(fd, &req) == NULL)
        {
            if ((req.flags & (CONNECTION_CLOSED | CONNECTION_ERROR)) != 0)
            {
                /* connection closed or encountered an error (no response) */
                HTTP_request_free(&req);
                HTTP_response_free(&res);
                break;
            }
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
            ptr = MAP_get(req.headers, "Connection");
            if (ptr != NULL && strcmp(ptr, "close") == 0 || strcmp(req.protocol, "HTTP/1.0") == 0 && (ptr == NULL || strcmp(ptr, "keep-alive") != 0))
            {
                MAP_put(res.headers, "Connection", "close");
                persist = 0;
            }
            else
            {
                MAP_put(res.headers, "Connection", "keep-alive");
            }
            if (strcmp(req.method, "CONNECT") == 0 || strcmp(req.method, "TRACE") == 0)
            {
                res.code = 501; /* Not Implemented */
            }
            else if ((handler = (struct path_handler *)MAP_get(handlers, req.target)) != NULL)
            {
                /* call handler based on request method */
                if ((strcmp(req.method, "GET") == 0 || strcmp(req.method, "HEAD") == 0) && handler->get != NULL)
                {
                    handler->get(&req, &res);
                }
                else if (strcmp(req.method, "POST") == 0 && handler->post != NULL)
                {
                    handler->post(&req, &res);
                }
                else if (strcmp(req.method, "PUT") == 0 && handler->put != NULL)
                {
                    handler->put(&req, &res);
                }
                else if (strcmp(req.method, "PATCH") == 0 && handler->patch != NULL)
                {
                    handler->patch(&req, &res);
                }
                else if (strcmp(req.method, "DELETE") == 0 && handler->delete != NULL)
                {
                    handler->delete(&req, &res);
                }
                else
                {
                    /* OPTIONS request or method with no handler */
                    if (strcmp(req.method, "OPTIONS") == 0)
                        res.code = 204; /* No Content */
                    else
                        res.code = 405; /* Method Not Allowed */
                    /* generate allow header */
                    ptr = generate_allow(handler);
                    STACK_push(res.stack, ptr);
                    MAP_put(res.headers, "Allow", ptr);
                }
            }
            else if (default_handler != NULL)
            {
                default_handler(&req, &res);
            }
            else
            {
                res.code = 404; /* Not Found */
            }
        }
        /* infer reason from code */
        res.reason = HTTP_reason(res.code);
        /* send response */
        if (res.file != NULL)
            HTTP_respond_file(&req, res.file, &res, fd);
        else
            HTTP_send_response(&res, fd, strcmp(req.method, "HEAD") == 0);
        if (debug)
            HTTP_print_response(&res);
        /* free data */
        HTTP_request_free(&req);
        HTTP_response_free(&res);
    }
    close(fd);
}

void handle_default(HTTP_request *req, HTTP_response *res)
{
    struct stat path_stat;
    char *path = malloc(strlen(req->target) + 2);
    STACK_push(res->stack, path);
    *path = '.';
    strcpy(path + 1, req->target);
    if (access(path, F_OK) == 0 && stat(path, &path_stat) == 0 && S_ISREG(path_stat.st_mode))
    {
        if (strcmp(req->method, "GET") == 0 || strcmp(req->method, "HEAD") == 0)
        {
            /* assets are assumed to be immutable */
            if (strncmp(req->target, "/assets/", 8) == 0)
                MAP_put(res->headers, "Cache-Control", "max-age=31536000");
            char *content_type = "*";
            int index = strlastindexof(req->target, '.');
            if (index >= 0)
                /* infer content type from extension */
                content_type = HTTP_content_type(req->target + index + 1);
            MAP_put(res->headers, "Content-Type", content_type);
            res->file = path;
        }
        else
        {
            res->code = 405; /* Method Not Allowed */
        }
    }
    else
    {
        res->code = 404; /* Not Found */
    }
}

void handle_index_get(HTTP_request *req, HTTP_response *res)
{
    MAP_put(res->headers, "Content-Type", "text/html");
    res->file = "./index.html";
}

void handle_favicon_get(HTTP_request *req, HTTP_response *res)
{
    MAP_put(res->headers, "Cache-Control", "max-age=31536000");
    MAP_put(res->headers, "Content-Type", "image/svg+xml");
    res->file = "./favicon.svg";
}

void *thread_main(void *arg)
{
    handle_conn(*((int *)arg));
    return NULL;
}

char init(unsigned short port, int n)
{
    int sockfd, connfd, len, i;
    struct sockaddr_in server, client;
    pthread_t thread;
    pthread_attr_t attr;
    pthread_attr_init(&attr);
    /* open socket */
    sockfd = socket(AF_INET, SOCK_STREAM, 0);
    if (sockfd == -1)
    {
        printf("socket creation failed\n");
        return 0;
    }
    bzero(&server, sizeof(server));

    /* assign IP, PORT */
    server.sin_family = AF_INET;
    server.sin_addr.s_addr = htonl(INADDR_ANY);
    server.sin_port = htons(port);

    /* bind newly created socket to given IP and verification */
    if ((bind(sockfd, (struct sockaddr *)&server, sizeof(server))) < 0)
    {
        printf("socket bind failed\n");
        return 0;
    }
    while (1)
    {
        /* listen on socket */
        if ((listen(sockfd, n)) < 0)
            printf("listen failed\n");
        len = sizeof(client);
        while (1)
        {
            /* accept new connections */
            if ((connfd = accept(sockfd, (struct sockaddr *)&client, &len)) < 0)
            {
                printf("server accept failed\n");
                continue;
            }
            pthread_create(&thread, &attr, &thread_main, &connfd);
        }
    }
    close(sockfd);
    printf("socket closed\n");
}

int main(int argc, char **argv)
{
    char *ptr, *endptr;
    unsigned short port = PORT;
    int sockfd, connfd, len, i, j = 0;
    struct sockaddr_in server, client;

    for (i = 1; i < argc; i++)
    {
        ptr = argv[i];
        if (*ptr == '-')
        {
            if (strcmp(ptr, "--debug") == 0)
            {
                debug = 1;
            }
            else
            {
                printf("unrecognized flag: %s\n", ptr);
                return 1;
            }
        }
        else if (j == 0)
        {
            endptr = NULL;
            port = (unsigned short)strtol(ptr, &endptr, 10);
            if (*ptr == '\0' || *endptr != '\0')
            {
                printf("invalid port: %s\n", ptr);
                return 1;
            }
            j++;
        }
    }
    /* set handlers */
    set_default_handler(&handle_default);
    set_path_handler("/", "GET", &handle_index_get);
    set_path_handler("/favicon.ico", "GET", &handle_favicon_get);
    /* listen */
    if (!init(port, 100))
        return 1;
    return 0;
}
