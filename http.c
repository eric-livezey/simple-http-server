#include <time.h>
#include <stdio.h>
#include <unistd.h>
#include "hashmap.h"
#include "utils.h"

typedef struct HTTP_request_s
{
    char *method;
    char *path;
    hashmap_t *query;
    char *protocol;
    hashmap_t *headers;
    char *body;
    unsigned long content_length;
} HTTP_request_t;

typedef struct HTTP_response_s
{
    char *protocol;
    short code;
    char *reason;
    hashmap_t *headers;
    char *body;
    unsigned long content_length;
} HTTP_response_t;

int HTTP_request_destroy(HTTP_request_t *request)
{
    if (request->query != NULL)
    {
        hashmap_destroy(request->query);
        free(request->query);
    }
    if (request->headers != NULL)
    {
        hashmap_destroy(request->headers);
        free(request->headers);
    }
    return 0;
}

int HTTP_response_destroy(HTTP_response_t *response)
{
    if (response->headers != NULL)
    {
        hashmap_destroy(response->headers);
        free(response->headers);
    }
    if (response->body != NULL)
        free(response->body);
    return 0;
}

char *HTTP_reason(unsigned short code)
{
    switch (code)
    {
    case 100:
        return "Continue";
        break;
    case 101:
        return "Switching Protocols";
        break;
    case 200:
        return "OK";
        break;
    case 201:
        return "Created";
        break;
    case 202:
        return "Accepted";
        break;
    case 203:
        return "Non-Authoritative Information";
        break;
    case 204:
        return "No Content";
        break;
    case 205:
        return "Reset Content";
        break;
    case 206:
        return "Partial Content";
        break;
    case 300:
        return "Multiple Choices";
        break;
    case 301:
        return "Moved Permanently";
        break;
    case 302:
        return "Found";
        break;
    case 303:
        return "See Other";
        break;
    case 304:
        return "Not Modified";
        break;
    case 305:
        return "Use Proxy";
        break;
    case 307:
        return "Temporary Redirect";
        break;
    case 308:
        return "Permanent Redirect";
        break;
    case 400:
        return "Bad Request";
        break;
    case 401:
        return "Unauthorized";
        break;
    case 402:
        return "Payment Required";
        break;
    case 403:
        return "Forbidden";
        break;
    case 404:
        return "Not Found";
        break;
    case 405:
        return "Method Not Allowed";
        break;
    case 406:
        return "Not Acceptable";
        break;
    case 407:
        return "Proxy Authentication Required";
        break;
    case 408:
        return "Request Timeout";
        break;
    case 409:
        return "Conflict";
        break;
    case 410:
        return "Gone";
        break;
    case 411:
        return "Length Required";
        break;
    case 412:
        return "Precondition Failed";
        break;
    case 413:
        return "Content Too Large";
        break;
    case 414:
        return "URI Too Long";
        break;
    case 415:
        return "Unsupported Media Type";
        break;
    case 416:
        return "Range Not Satisfiable";
        break;
    case 417:
        return "Expectation Failed";
        break;
    case 421:
        return "Misdirected Request";
        break;
    case 422:
        return "Unprocessable Content";
        break;
    case 426:
        return "Upgrade Required";
        break;
    case 500:
        return "Internal Server Error";
        break;
    case 501:
        return "Not Implemented";
        break;
    case 502:
        return "Bad Gateway";
        break;
    case 503:
        return "Service Unavailable";
        break;
    case 504:
        return "Gateway Timeout";
        break;
    case 505:
        return "HTTP Version Not Supported";
        break;
    default:
        return NULL;
    }
}

char *HTTP_date_r(struct tm *tm, char *result)
{
    result[0] = '\0';
    strftime(result, 30, "%a, %d %b %Y %T GMT", tm);
    return result;
}

char *HTTP_date(struct tm *tm)
{
    char *result = malloc(29 * sizeof(char));
    return HTTP_date_r(tm, result);
}

HTTP_request_t *HTTP_parserequest(char *data, HTTP_request_t *result)
{
    /* method */
    if ((result->method = strtok(data, " ")) == NULL)
        return NULL;
    /* target */
    if ((result->path = strtok(NULL, " ")) == NULL)
        return NULL;
    char *ptr = result->path + strlen(result->path) + 1;
    if (strstr(result->path, "?") != NULL)
    { /* query exists */
        result->path = strtok(result->path, "?");
        result->query = malloc(sizeof(hashmap_t));
        hashmap_init(result->query);
        char *tok;
        while ((tok = strtok(NULL, "=")) != NULL)
            hashmap_put(result->query, tok, strtok(NULL, "&"));
    }
    /* protocol */
    if ((result->protocol = strtok(ptr, "\r\n")) == NULL)
    {
        HTTP_request_destroy(result);
        return NULL;
    }
    /* headers */
    result->headers = malloc(sizeof(hashmap_t));
    hashmap_init(result->headers);
    ptr += strlen(result->protocol) + 2;
    while (strncmp(ptr, "\r\n", 2) != 0)
    { /* fill headers with header data */
        ptr = strstr(ptr, "\r\n") + 2;
        char *k = strtok(NULL, ":") + 1;
        char *v = strtok(NULL, "\r\n");
        while (v[0] == ' ') /* ignore leading whitespace */
            v++;
        hashmap_put(result->headers, k, v);
        if (strcasecmp(k, "Content-Length") == 0)
            result->content_length = strtoul(v, NULL, 10);
    }
    /* body */
    if (hashmap_get(result->headers, "Content-Length") != NULL)
    {
        result->body = ptr + 2;
        result->body[result->content_length] = '\0';
    }
    else
    {
        result->body = NULL;
        result->content_length = 0;
    }
    return result;
}

long HTTP_ressize(HTTP_response_t *res)
{
    char *date;
    int i;
    long len = 9;
    len += strlen(res->protocol);
    len += strlen(res->reason);
    entry_t **es;
    if (res->headers != NULL)
    {
        es = hashmap_entry_set(res->headers);
        for (i = 0; i < res->headers->size; i++)
        {
            len += 4;
            len += strlen(es[i]->key);
            len += strlen(es[i]->value);
        }
    }
    if (res->body != NULL)
        len += res->content_length;
    return len;
}

char *HTTP_resmsg(HTTP_response_t *res, char *result)
{
    /* write message */
    result[0] = '\0';
    long len = 0;
    len += sprintf(result, "%s %d %s\r\n", res->protocol, res->code, res->reason); /* protocol code reason */
    if (res->headers != NULL)
    {
        entry_t **es = hashmap_entry_set(res->headers);
        for (int i = 0; i < res->headers->size; i++) /* headers */
            len += sprintf(result + len, "%s: %s\r\n", es[i]->key, es[i]->value);
    }
    strcat(result, "\r\n");

    printf("---------------- RESPONSE ----------------\r\n\r\n%s\r\n", result); /* print response (excluding body) */

    len += 2;
    if (res->body != NULL) /* body */
        memcpy(result + len, res->body, res->content_length);
    return result;
}

long HTTP_response(int fd, HTTP_response_t *res)
{
    hashmap_t headers;
    memset(&headers, 0, sizeof(hashmap_t));
    hashmap_init(&headers);
    if (res->headers != NULL)
        hashmap_put_all(&headers, res->headers);
    hashmap_put_if_absent(&headers, "Connection", "close");
    char date[29];
    if (!hashmap_contains_key(&headers, "Date"))
    { /* date */
        time_t timer;
        time(&timer);
        struct tm t;
        gmtime_r(&timer, &t);
        HTTP_date_r(&t, date);
        hashmap_put(&headers, "Date", date);
    }
    char content_length[numlenul(res->content_length)];
    if (res->body != NULL && !hashmap_contains_key(&headers, "Content-Length"))
    { /* content-length */
        content_length[0] = '\0';
        sprintf(content_length, "%lu", res->content_length);
        hashmap_put(&headers, "Content-Length", content_length);
    }
    void *temp = res->headers;
    res->headers = &headers;
    long len = HTTP_ressize(res);
    char msg[len];
    HTTP_resmsg(res, msg);
    res->headers = (hashmap_t *)temp;

    return write(fd, msg, len);
}
