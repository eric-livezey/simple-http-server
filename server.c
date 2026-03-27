#include <stdlib.h>
#include <stdbool.h>
#include <stdio.h>
#include <string.h>
#include <ctype.h>
#include <unistd.h>
#include <pthread.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <netinet/in.h>
#include "http.h"
#define PORT 8000

bool debug = false;

typedef void(request_handler)(struct http_request *, struct http_response *);

typedef struct path_handler_s
{
    request_handler *get;
    request_handler *post;
    request_handler *put;
    request_handler *patch;
    request_handler *delete;
} path_handler_t;

#define KEY_TYPE char *
#define KEY_HASH strcasehash_p
#define KEY_CMP strcasecmp_p
#define VALUE_TYPE path_handler_t *
#define LABEL HANDLER_MAP
#include "types/map/tmap.h"
#undef KEY_TYPE
#undef KEY_HASH
#undef KEY_CMP
#undef VALUE_TYPE
#undef VALUE_CMP
#undef LABEL

request_handler *default_handler = NULL;
HANDLER_MAP *handlers = NULL;

void set_default_handler(request_handler *handler)
{
    default_handler = handler;
}

void set_path_handler(char *target, char *method, request_handler *handler)
{
    if (handlers == NULL)
        handlers = HANDLER_MAP_new();
    path_handler_t *path_handler;
    if ((path_handler = HANDLER_MAP_get(handlers, target)) == NULL)
        HANDLER_MAP_put(handlers, target, path_handler = calloc(1, sizeof(path_handler_t)));
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

char *generate_allow(path_handler_t *handler)
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

char *generate_content_type(struct media_type *ct)
{
    STR_MAP_entry_t *entry;
    int i;
    unsigned long size = 2;
    size += strlen(ct->type);
    size += strlen(ct->subtype);
    for (i = 0; i < STR_MAP_size(ct->parameters); i++)
    {
        entry = STR_MAP_entry_set(ct->parameters)[i];
        size += 5;
        size += strlen(entry->key);
        size += strlen(entry->value);
    }
    char *result = malloc(size);
    *result = '\0';
    size = 0;
    size += sprintf(result, "%s/%s", ct->type, ct->subtype);
    for (i = 0; i < STR_MAP_size(ct->parameters); i++)
    {
        entry = STR_MAP_entry_set(ct->parameters)[i];
        size += sprintf(result + size, "; %s=\"%s\"", entry->key, (char *)entry->value);
    }
    return result;
}

void handle_conn(int fd)
{
    char persist = 1, *ptr;
    struct http_request req;
    struct http_response res;
    path_handler_t *handler;
    while (persist)
    {
        HTTP_request_init(&req);
        HTTP_response_init(&res);
        /* read a request from the connection */
        if (HTTP_recvreq(fd, &req) == NULL)
        {
            if ((req.flags & (CONNECTION_CLOSED | CONNECTION_ERROR)) != 0)
            {
                /* connection closed or encountered an error (no response) */
                HTTP_request_free(&req);
                HTTP_response_free(&res);
                break;
            }
            if (req.flags & CONTENT_TOO_LARGE)
                res.code = 413; // Content Too Large
            else if (req.flags & EXPECTATION_FAILED)
                res.code = 417; // Expectation Failed
            else if (req.flags & NOT_IMPLEMENTED)
                res.code = 501; // Not Implemented
            else
                res.code = 400; // Bad Request
            STRCASE_MAP_put(res.headers, "Connection", "close");
            persist = 0;
        }
        else if (strcmp(req.version, "HTTP/1.0") != 0 && strcmp(req.version, "HTTP/1.1") != 0)
        {
            res.code = 505; /* HTTP Version Not Supported */
        }
        else
        {
            if (debug)
                HTTP_print_request(&req);
            ptr = STRCASE_MAP_get(req.headers, "Connection");
            if (ptr != NULL && strcmp(ptr, "close") == 0 || strcmp(req.version, "HTTP/1.0") == 0 && (ptr == NULL || strcmp(ptr, "keep-alive") != 0))
            {
                STRCASE_MAP_put(res.headers, "Connection", "close");
                persist = 0;
            }
            else
            {
                STRCASE_MAP_put(res.headers, "Connection", "keep-alive");
            }
            if (strcmp(req.method, "CONNECT") == 0 || strcmp(req.method, "TRACE") == 0)
            {
                res.code = 501; /* Not Implemented */
            }
            else if (req.target->path == NULL)
            {
                res.code = 404; // Not Found
            }
            else if ((handler = HANDLER_MAP_get(handlers, req.target->path)) != NULL)
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
                    MEM_STACK_push(res.stack, ptr);
                    STRCASE_MAP_put(res.headers, "Allow", ptr);
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
            HTTP_send_response(&res, fd, req.method != NULL && strcmp(req.method, "HEAD") == 0);
        if (debug)
            HTTP_print_response(&res);
        /* free data */
        HTTP_request_free(&req);
        HTTP_response_free(&res);
    }
    close(fd);
}

void handle_default(struct http_request *req, struct http_response *res)
{
    struct stat path_stat;
    char *path = malloc(strlen(req->target->path) + 2);
    *path = '.';
    urldecode(path + 1, req->target->path);
    if (access(path, F_OK) == 0 && stat(path, &path_stat) == 0 && S_ISREG(path_stat.st_mode))
    {
        if (strcmp(req->method, "GET") == 0 || strcmp(req->method, "HEAD") == 0)
        {
            MEM_STACK_push(res->stack, path);
            // Cache-Control
            if (strncmp(req->target->path, "/assets/", 8) == 0)
                // assets are assumed to be immutable
                STRCASE_MAP_put(res->headers, "Cache-Control", "max-age=31536000");
            // Content-Type
            char *content_type = "*";
            int32_t index = strlastindexof(req->target->path, '.');
            if (index >= 0)
                // infer content type from extension */
                content_type = infer_media_type(req->target->path + index + 1);
            STRCASE_MAP_put(res->headers, "Content-Type", content_type);
            res->file = path;
        }
        else
        {
            free(path);
            /* OPTIONS request or method with no handler */
            if (strcmp(req->method, "OPTIONS") == 0)
                res->code = 204; /* No Content */
            else
                res->code = 405; /* Method Not Allowed */
            STRCASE_MAP_put(res->headers, "Allow", "GET, HEAD");
        }
    }
    else
    {
        free(path);
        res->code = 404; /* Not Found */
    }
}

void handle_index_get(struct http_request *req, struct http_response *res)
{
    STRCASE_MAP_put(res->headers, "Content-Type", "text/html");
    res->file = "./index.html";
}

void handle_favicon_get(struct http_request *req, struct http_response *res)
{
    STRCASE_MAP_put(res->headers, "Cache-Control", "max-age=31536000");
    STRCASE_MAP_put(res->headers, "Content-Type", "image/svg+xml");
    res->file = "./favicon.svg";
}

void *print_help()
{
    printf("Usage: server [OPTION]... [PORT]\nStart an HTTP server on the PORT (%d by default).\n\n  -d, --debug                prints debug messages to the console\n      --help                 display this help and exit\n", PORT);
}

void *thread_main(void *arg)
{
    handle_conn(*((int *)arg));
    return NULL;
}

bool init(unsigned short port, int n)
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
        return false;
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
        return false;
    }
    printf("listening on port %d\n", port);
    while (true)
    {
        /* listen on socket */
        if ((listen(sockfd, n)) < 0)
            printf("listen failed\n");
        len = sizeof(client);
        while (true)
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
    return true;
}

int main(int argc, char **argv)
{
    unsigned short port = PORT;

    for (int i = 1, j = 0; i < argc; i++)
    {
        char *ptr = argv[i];
        if (*ptr == '-' && ptr[1] != '\0')
        {
            ptr++;
            if (*ptr == '-')
            {
                ptr++;
                if (strcmp(ptr, "debug") == 0)
                {
                    debug = true;
                }
                else if (strcmp(ptr, "help") == 0)
                {
                    print_help();
                    return 0;
                }
                else
                {
                    fprintf(stderr, "unrecognized option '%s'\n", ptr - 2);
                    return 1;
                }
            }
            else
            {
                while (*ptr != '\0')
                {
                    char c = *ptr;
                    if (c == 'd')
                    {
                        debug = true;
                    }
                    else
                    {
                        fprintf(stderr, "invalid option -- '%c'\n", c);
                        return 1;
                    }
                    ptr++;
                }
            }
        }
        else if (j == 0)
        {
            char *endptr = NULL;
            port = strtous(ptr, &endptr, 10);
            if (*ptr == '\0' || *endptr != '\0')
            {
                fprintf(stderr, "invalid port '%s'\n", ptr);
                return 1;
            }
            j++;
        }
        else
        {
            fprintf(stderr, "too many arguments");
            return 1;
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
