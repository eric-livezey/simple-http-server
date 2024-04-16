#include <stdio.h>
#include <time.h>
#include <unistd.h>
#include "hashmap.h"

typedef struct HTTP_request_s
{
    char *method;
    char *path;
    hashmap *query;
    char *protocol;
    hashmap *headers;
    char *body;
    unsigned long content_length;
} HTTP_request;

typedef struct HTTP_response_s
{
    char *protocol;
    short code;
    char *reason;
    hashmap *headers;
    char *body;
    unsigned long content_length;
} HTTP_response;

void urldecode(char *dst, const char *src)
{
    char a, b;
    while (*src)
    {
        if ((*src == '%') &&
            ((a = src[1]) && (b = src[2])) &&
            (isxdigit(a) && isxdigit(b)))
        {
            if (a >= 'a')
                a -= 'a' - 'A';
            if (a >= 'A')
                a -= ('A' - 10);
            else
                a -= '0';
            if (b >= 'a')
                b -= 'a' - 'A';
            if (b >= 'A')
                b -= ('A' - 10);
            else
                b -= '0';
            *dst++ = 16 * a + b;
            src += 3;
        }
        else if (*src == '+')
        {
            *dst++ = ' ';
            src++;
        }
        else
        {
            *dst++ = *src++;
        }
    }
    *dst++ = '\0';
}

int HTTP_request_free(HTTP_request *request)
{
    if (request->query != NULL)
    {
        hashmap_free_all(request->query);
        free(request->query);
    }
    if (request->headers != NULL)
    {
        hashmap_free_all(request->headers);
        free(request->headers);
    }
    return 0;
}

int HTTP_response_free(HTTP_response *response)
{
    if (response->headers != NULL)
    {
        hashmap_free_all(response->headers);
        free(response->headers);
    }
    if (response->body != NULL)
        free(response->body);
    return 0;
}

char *HTTP_date_ex(struct tm *tm, char *result)
{
    result[0] = '\0';
    strftime(result, 30, "%a, %d %b %Y %T GMT", tm);
    return result;
}

char *HTTP_date(struct tm *tm)
{
    char *result = malloc(29 * sizeof(char));
    return HTTP_date_ex(tm, result);
}

char *HTTP_reason(unsigned short code)
{
    switch (code)
    {
    case 100:
        return "Continue";
    case 101:
        return "Switching Protocols";
    case 200:
        return "OK";
    case 201:
        return "Created";
    case 202:
        return "Accepted";
    case 203:
        return "Non-Authoritative Information";
    case 204:
        return "No Content";
    case 205:
        return "Reset Content";
    case 206:
        return "Partial Content";
    case 300:
        return "Multiple Choices";
    case 301:
        return "Moved Permanently";
    case 302:
        return "Found";
    case 303:
        return "See Other";
    case 304:
        return "Not Modified";
    case 305:
        return "Use Proxy";
    case 307:
        return "Temporary Redirect";
    case 308:
        return "Permanent Redirect";
    case 400:
        return "Bad Request";
    case 401:
        return "Unauthorized";
    case 402:
        return "Payment Required";
    case 403:
        return "Forbidden";
    case 404:
        return "Not Found";
    case 405:
        return "Method Not Allowed";
    case 406:
        return "Not Acceptable";
    case 407:
        return "Proxy Authentication Required";
    case 408:
        return "Request Timeout";
    case 409:
        return "Conflict";
    case 410:
        return "Gone";
    case 411:
        return "Length Required";
    case 412:
        return "Precondition Failed";
    case 413:
        return "Content Too Large";
    case 414:
        return "URI Too Long";
    case 415:
        return "Unsupported Media Type";
    case 416:
        return "Range Not Satisfiable";
    case 417:
        return "Expectation Failed";
    case 421:
        return "Misdirected Request";
    case 422:
        return "Unprocessable Content";
    case 426:
        return "Upgrade Required";
    case 500:
        return "Internal Server Error";
    case 501:
        return "Not Implemented";
    case 502:
        return "Bad Gateway";
    case 503:
        return "Service Unavailable";
    case 504:
        return "Gateway Timeout";
    case 505:
        return "HTTP Version Not Supported";
    default:
        return NULL;
    }
}

HTTP_request *HTTP_parserequest(char *data, HTTP_request *result)
{
    result->query = NULL;
    result->headers = NULL;
    char *saveptr = NULL;
    /* method */
    if (*data == ' ' || (result->method = strtok_r(data, " ", &saveptr)) == NULL || *saveptr == ' ' || *saveptr == '\0')
        return NULL;
    /* target */
    if ((result->path = strtok_r(NULL, " ", &saveptr)) == NULL || *saveptr == ' ' || *saveptr == '\0')
        return NULL;
    urldecode(result->path, result->path);
    char *ptr = saveptr + 1;
    if (strstr(result->path, "?") != NULL)
    { /* query exists */
        saveptr = NULL;
        result->path = strtok_r(result->path, "?", &saveptr);
        result->query = malloc(sizeof(hashmap));
        hashmap_init(result->query, 1);
        char *key;
        char *val;
        while ((key = strtok_r(NULL, "=", &saveptr)) != NULL) {
            if ((val = strtok_r(NULL, "&", &saveptr)) == NULL) {
                HTTP_request_free(result);
                return NULL;
            }
            hashmap_put(result->query, key, val);
        }
    }
    /* protocol */
    if ((result->protocol = strtok_r(ptr, "\r\n", &saveptr)) == NULL || saveptr[1] == '\0')
    {
        HTTP_request_free(result);
        return NULL;
    }
    /* headers */
    result->headers = malloc(sizeof(hashmap));
    hashmap_init(result->headers, 1);
    ptr += strlen(result->protocol) + 2;
    while (strncmp(ptr, "\r\n", 2) != 0)
    { /* fill headers with header data */
        ptr = strstr(ptr, "\r\n") + 2;
        char *k = strtok_r(NULL, ":", &saveptr) + 1;
        char *v = strtok_r(NULL, "\r\n", &saveptr);
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

long HTTP_reqsize(HTTP_request *req)
{
    char *date;
    int i;
    long len = 6;
    len += strlen(req->method);
    len += strlen(req->path);
    if (req->query != NULL)
    {
        entry **es = hashmap_entry_set(req->query);
        for (i = 0; i < req->query->size; i++)
        {
            len += 2;
            len += strlen(es[i]->key);
            len += strlen(es[i]->value);
        }
    }
    len += strlen(req->protocol);
    if (req->headers != NULL)
    {
        entry **es = hashmap_entry_set(req->headers);
        for (i = 0; i < req->headers->size; i++)
        {
            len += 4;
            len += strlen(es[i]->key);
            len += strlen(es[i]->value);
        }
    }
    if (req->body != NULL)
        len += req->content_length;
    return len;
}

char *HTTP_reqmsg(HTTP_request *req, char *result)
{
    int i;
    long len = 0;
    /* write message */
    result[0] = '\0';
    len += sprintf(result, "%s %s", req->method, req->path);
    if (req->query != NULL)
    {
        entry **es = hashmap_entry_set(req->query);
        for (i = 0; i < req->query->size; i++)
        {
            len += 1;
            if (i == 0)
                strcat(result + len, "?");
            else
                strcat(result + len, "&");
            len += sprintf(result + len, "%s=%s", es[i]->key, es[i]->value);
        }
    }
    len += sprintf(result + len, " %s\r\n", req->protocol);
    if (req->headers != NULL)
    {
        entry **es = hashmap_entry_set(req->headers);
        for (i = 0; i < req->headers->size; i++) /* headers */
            len += sprintf(result + len, "%s: %s\r\n", es[i]->key, es[i]->value);
    }
    strcat(result + len, "\r\n");

    len += 2;
    if (req->body != NULL) /* body */
        memcpy(result + len, req->body, req->content_length);
    return result;
}

unsigned long HTTP_ressize(HTTP_response *res)
{
    char *date;
    int i;
    unsigned long len = 9;
    len += strlen(res->protocol);
    len += strlen(res->reason);
    entry **es;
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

char *HTTP_resmsg(HTTP_response *res, char *result)
{
    long len = 0;
    /* write message */
    result[0] = '\0';
    len += sprintf(result, "%s %d %s\r\n", res->protocol, res->code, res->reason); /* protocol code reason */
    if (res->headers != NULL)
    {
        entry **es = hashmap_entry_set(res->headers);
        for (int i = 0; i < res->headers->size; i++) /* headers */
            len += sprintf(result + len, "%s: %s\r\n", es[i]->key, es[i]->value);
    }
    strcat(result + len, "\r\n");

    printf("---------------- RESPONSE ----------------\r\n\r\n%s\r\n", result); /* print response (excluding body) */

    len += 2;
    if (res->body != NULL) /* body */
        memcpy(result + len, res->body, res->content_length);
    return result;
}

long HTTP_send_response(HTTP_response *res, int connfd)
{
    hashmap headers;
    memset(&headers, 0, sizeof(hashmap));
    hashmap_init(&headers, 1);
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
        HTTP_date_ex(&t, date);
        hashmap_put(&headers, "Date", date);
    }
    char content_length[numlenul(res->content_length)];
    if (res->body != NULL && !hashmap_contains_key(&headers, "Content-Length"))
    { /* content-length */
        content_length[0] = '\0';
        sprintf(content_length, "%lu", res->content_length);
        hashmap_put(&headers, "Content-Length", content_length);
    }
    hashmap *temp = res->headers;
    res->headers = &headers;
    long len = HTTP_ressize(res);
    char msg[len];
    HTTP_resmsg(res, msg);
    res->headers = temp;
    return write(connfd, msg, len);
}
