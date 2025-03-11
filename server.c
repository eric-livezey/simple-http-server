#include <unistd.h>
#include <pthread.h>
#include <sys/stat.h>
#include <fcntl.h>
#include "http.h"
#define PORT 8000

char debug = 0;

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

char *generate_content_type(struct content_type *ct)
{
    struct entry *entry;
    int i;
    unsigned long size = 2;
    size += strlen(ct->type);
    size += strlen(ct->subtype);
    for (i = 0; i < MAP_size(ct->parameters); i++)
    {
        entry = MAP_entry_set(ct->parameters)[i];
        size += 5;
        size += strlen(entry->key);
        size += strlen(entry->value);
    }
    char *result = malloc(size);
    *result = '\0';
    size = 0;
    size += sprintf(result, "%s/%s", ct->type, ct->subtype);
    for (i = 0; i < MAP_size(ct->parameters); i++)
    {
        entry = MAP_entry_set(ct->parameters)[i];
        size += sprintf(result + size, "; %s=\"%s\"", entry->key, (char *)entry->value);
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
        HTTP_request_init(&req);
        HTTP_response_init(&res);
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
        else if (strcmp(req.protocol, "HTTP/1.0") != 0 && strcmp(req.protocol, "HTTP/1.1") != 0)
        {
            res.code = 505; /* HTTP Version Not Supported */
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
            /* OPTIONS request or method with no handler */
            if (strcmp(req->method, "OPTIONS") == 0)
                res->code = 204; /* No Content */
            else
                res->code = 405; /* Method Not Allowed */
            MAP_put(res->headers, "Allow", "GET, HEAD");
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
