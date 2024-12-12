#include <unistd.h>
#include "hashmap.h"

#define iswhitespace(c) (c == ' ' || c == '\t')
#define istchar(c) (c == '!' || c == '#' || c == '$' || c == '%' || c == '&' || c == '\'' || c == '*' || c == '+' || c == '-' || c == '.' || c == '^' || c == '_' || c == '`' || c == '|' || c == '~' || isdigit(c) || isalpha(c))
#define isobschar(c) (c >= 0x80 && c <= 0xFF)
#define isvchar(c) (c >= 0x21 && c <= 0x7E)
#define isunreserved(c) (isalpha(c) || isdigit(c) || c == '-' || c == '.' || c == '_' || c == '~')
#define issubdelim(c) (c == '!' || c == '$' || c == '&' || c == '\'' || c == '(' || c == ')' || c == '*' || c == '+' || c == ',' || c == ';' || c == '=')
#define isqpair(ptr) ((ptr)[0] == '\\' && (iswhitespace((ptr)[1]) || isvchar((ptr)[1]) || isobschar((ptr)[1])))
#define iscrlf(ptr) ((ptr)[0] == '\r' && (ptr)[1] == '\n')
#define ispctenc(ptr) ((ptr)[0] == '%' && isxdigit((ptr)[1]) && isxdigit((ptr)[2]))
#define ispchar(ptr) (isunreserved(*(ptr)) || ispctenc(ptr) || issubdelim(*(ptr)) || *(ptr) == ':' || *(ptr) == '@')

enum FLAGS
{
    CONNECTION_ERROR = 0b00000001,
    PARSE_ERROR = 0b00000010,
    BAD_CONTENT_LENGTH = 0b00000100,
    CONTENT_TOO_LARGE = 0b00001000
};

struct part
{
    MAP *headers;
    unsigned long content_length;
    char *content;
};

struct multipart
{
    struct part *parts;
    unsigned long length;
    STACK *stack;
};

struct content_type
{
    char *type;
    char *subtype;
    MAP *parameters;
};

struct chunk
{
    unsigned long size;
    char *content;
    MAP *extension;
};

typedef struct HTTP_request
{
    char *method;
    char *target;
    MAP *query;
    char *protocol;
    MAP *headers;
    char *content;
    unsigned long content_length;
    MAP *trailers;
    STACK *stack;
    short flags;
} HTTP_request;

typedef struct HTTP_response
{
    char *protocol;
    short code;
    char *reason;
    MAP *headers;
    char *content;
    unsigned long content_length;
    MAP *trailers;
    STACK *stack;
} HTTP_response;

/*
 * -------- UTILS --------
 */

void HTTP_request_free(HTTP_request *req)
{
    if (req->query != NULL)
        MAP_free(req->query);
    if (req->headers != NULL)
        MAP_free(req->headers);
    if (req->trailers != NULL)
        MAP_free(req->trailers);
    STACK_free(req->stack);
}

void HTTP_response_free(HTTP_response *res)
{
    if (res->headers != NULL)
        MAP_free(res->headers);
    if (res->trailers != NULL)
        MAP_free(res->trailers);
    STACK_free(res->stack);
}

char *HTTP_date_ex(struct tm *tm, char *result)
{
    result[0] = '\0';
    strftime(result, 30, "%a, %d %b %Y %T GMT", tm);
    return result;
}

char *HTTP_date(struct tm *tm)
{
    return HTTP_date_ex(tm, malloc(29 * sizeof(char)));
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

/*
 * -----------------
 * |    PARSING    |
 * -----------------
 */

char *qstring(char *ptr, char **endptr)
{
    long offset = 0;
    if (*ptr != '"')
        return NULL;
    ptr++;
    *endptr = ptr;
    while (*(*endptr) != '"' && !iscrlf(*endptr))
    {
        if (isqpair(*endptr))
        {
            (*endptr)++;
            offset--;
        }
        (*endptr)[offset] = *(*endptr);
        (*endptr)++;
    }
    if (iscrlf(*endptr))
        return NULL;
    (*endptr)[offset] = '\0';
    (*endptr)++;
    return ptr;
}

MAP *parse_parameters(char *ptr, MAP *result)
{
    char *endptr = ptr, *k, *v;
    while (*ptr != '\0')
    {
        // OWS
        while (iswhitespace(*ptr))
            ptr++;
        // ';'
        if (*ptr != ';')
            return NULL;
        ptr++;
        *endptr = '\0';
        // OWS
        while (iswhitespace(*ptr))
            ptr++;
        if (*ptr == '\0')
            break;
        // token
        k = endptr = ptr;
        while (istchar(*endptr))
            endptr++;
        if (endptr == ptr)
            return NULL;
        ptr = endptr;
        // '='
        if (*ptr != '=')
            return NULL;
        ptr++;
        *endptr = '\0';
        // token / quoted-string
        if (*ptr == '"')
        {
            // quoted-string
            if ((v = qstring(ptr, &endptr)) == NULL)
                return NULL;
        }
        else
        {
            // token
            v = endptr = ptr;
            while (istchar(*endptr))
                endptr++;
            if (endptr == ptr)
                return NULL;
        }
        ptr = endptr;
        MAP_put(result, k, v);
    }
    if (*endptr != '\0')
        return NULL;
    return result;
}

unsigned long *parse_range(char *ptr, unsigned long size, unsigned long *result)
{
    char firstpos = 1, *endptr;
    // "bytes" (only byte ranges are acceptable)
    if (strncmp(ptr, "bytes", 5) != 0)
        return NULL;
    ptr += 5;
    // '='
    if (*ptr != '=')
        return NULL;
    ptr++;
    // first-pos
    endptr = ptr;
    if (isdigit(*ptr))
        result[0] = strtoul(ptr, &endptr, 10);
    else
        result[0] = 0;
    if (*endptr != '-')
        return NULL;
    if (ptr == endptr)
        firstpos = 0; // false
    ptr = endptr;
    ptr++;
    // last-pos
    endptr = ptr;
    if (isdigit(*ptr))
        result[1] = strtoul(ptr, &endptr, 10);
    else
        result[1] = size - 1;
    if (*endptr != '\0' || !firstpos && ptr == endptr)
        return NULL;
    return result;
}

struct content_type *parse_content_type(char *ptr, struct content_type *result)
{
    char *endptr;
    // token
    result->type = endptr = ptr;
    while (istchar(*endptr))
        endptr++;
    if (endptr == ptr)
        return NULL;
    ptr = endptr;
    // '/'
    if (*ptr != '/')
        return NULL;
    ptr++;
    *endptr = '\0';
    // token
    result->subtype = endptr = ptr;
    while (istchar(*endptr))
        endptr++;
    if (endptr == ptr)
        return NULL;
    ptr = endptr;
    // parameters
    if (parse_parameters(ptr, result->parameters) == NULL)
        return NULL;
    *endptr = '\0';
    return result;
}

MAP *parse_query(char *ptr, char **eptr, MAP *result)
{
    char *endptr = ptr, *k, *v;
    // '?'
    if (*ptr != '?')
        return NULL;
    ptr++;
    while (1)
    {
        // pchar
        k = endptr = ptr;
        while (*endptr != '=' && ispchar(endptr))
            endptr++;
        ptr = endptr;
        // '='
        if (*ptr != '=')
        {
            v = endptr;
            MAP_put(result, k, v);
            break;
        }
        *endptr = '\0';
        ptr++;
        // pchar
        v = endptr = ptr;
        while (*endptr != '&' && ispchar(endptr))
            endptr++;
        ptr = endptr;
        MAP_put(result, k, v);
        // [ '&' ]
        if (*ptr != '&')
            break;
        *endptr = '\0';
        ptr++;
    }
    *endptr = '\0';
    for (int i = 0; i < MAP_size(result); i++)
    {
        urldecode(MAP_entry_set(result)[i]->key, MAP_entry_set(result)[i]->key);
        urldecode(MAP_entry_set(result)[i]->value, MAP_entry_set(result)[i]->value);
    }
    *eptr = endptr;
    return result;
}

struct HTTP_request *HTTP_parse_reqln(char *ptr, struct HTTP_request *result)
{
    char *endptr;
    // token
    result->method = endptr = ptr;
    while (istchar(*endptr))
        endptr++;
    if (endptr == ptr)
        return NULL;
    ptr = endptr;
    // SP
    if (*ptr != ' ')
        return NULL;
    ptr++;
    *endptr = '\0';
    // request-target
    // TODO: better validation
    result->target = endptr = ptr;
    while (*endptr != ' ' && !iscrlf(endptr))
        endptr++;
    ptr = endptr;
    // SP
    if (*ptr != ' ')
        return NULL;
    ptr++;
    *endptr = '\0';
    // "HTTP"
    result->protocol = endptr = ptr;
    if (strncmp(endptr, "HTTP", 4) != 0)
        return NULL;
    endptr += 4;
    // '/'
    if (*endptr != '/')
        return NULL;
    endptr++;
    // DIGIT
    if (!isdigit(*endptr))
        return NULL;
    endptr++;
    // '.'
    if (*endptr != '.')
        return NULL;
    endptr++;
    // DIGIT
    if (!isdigit(*endptr))
        return NULL;
    endptr++;
    // CRLF
    if (!iscrlf(endptr))
        return NULL;
    *endptr = '\0';
    ptr = result->target;
    while (*ptr != '\0')
        if (*ptr == '?')
            if (parse_query(ptr, &endptr, result->query) != NULL)
                break;
            else
                return NULL;
        else
            ptr++;
    *ptr = '\0';
    if (*endptr != '\0')
        return NULL;
    urldecode(result->target, result->target);
    return result;
}

struct HTTP_response *HTTP_parse_statusln(char *ptr, struct HTTP_response *result)
{
    char *temp, *endptr;
    // "HTTP"
    result->protocol = endptr = ptr;
    if (strncmp(endptr, "HTTP", 4) == 0)
        endptr += 4;
    else
        return NULL;
    // '/'
    if (*endptr == '/')
        endptr++;
    else
        return NULL;
    // DIGIT
    if (isdigit(*endptr))
        endptr++;
    else
        return NULL;
    // '.'
    if (*endptr == '.')
        endptr++;
    else
        return NULL;
    // DIGIT
    if (isdigit(*endptr))
        endptr++;
    else
        return NULL;
    ptr = endptr;
    // SP
    if (*ptr == ' ')
        ptr++;
    else
        return NULL;
    *endptr = '\0';
    // DIGIT
    temp = endptr = ptr;
    if (isdigit(*endptr))
        endptr++;
    else
        return NULL;
    // DIGIT
    if (isdigit(*endptr))
        endptr++;
    else
        return NULL;
    // DIGIT
    if (isdigit(*endptr))
        endptr++;
    else
        return NULL;
    ptr = endptr;
    // SP
    if (*ptr == ' ')
        ptr++;
    else
        return NULL;
    *endptr = '\0';
    result->code = strtous(temp, &endptr, 10);
    // token
    result->reason = endptr = ptr;
    while (istchar(*endptr))
        endptr++;
    if (endptr == ptr)
        return NULL;
    // CRLF
    if (iscrlf(endptr))
        *endptr = '\0';
    else
        return NULL;
    return result;
}

struct entry *HTTP_parse_fieldln(char *ptr, struct entry *result)
{
    char *endptr;
    // token
    result->key = endptr = ptr;
    while (istchar(*endptr))
        endptr++;
    if (endptr == ptr)
        return NULL;
    ptr = endptr;
    // ':'
    if (*ptr == ':')
        ptr++;
    else
        return NULL;
    *endptr = '\0';
    // OWS
    while (iswhitespace(*ptr))
        ptr++;
    if (iscrlf(ptr))
    {
        result->value = NULL;
        return 0;
    }
    // VCHAR / obs-text
    result->value = endptr = ptr;
    if (isvchar(*endptr) || isobschar(*endptr))
        endptr++;
    else
        return NULL;
    // [ 1*( SP / HTAB / field-vchar ) field-vchar ] OWS
    while (iswhitespace(*endptr) || isvchar(*endptr) || isobschar(*endptr))
        endptr++;
    ptr = endptr;
    endptr--;
    while (iswhitespace(*endptr))
        endptr--;
    endptr++;
    if (iscrlf(ptr))
        *endptr = '\0';
    else
        return NULL;
    return result;
}

struct chunk *HTTP_parse_chunk_size(char *ptr, struct chunk *result)
{
    char *endptr, *k, *v;
    // chunk-size
    result->size = strtoul(ptr, &endptr, 16);
    if (endptr == ptr)
        return NULL;
    ptr = endptr;
    // chunk-extension
    while (!iscrlf(ptr))
    {
        // BWS
        while (iswhitespace(*ptr))
            ptr++;
        // ';'
        if (*ptr == ';')
            ptr++;
        else
            return NULL;
        *endptr = '\0';
        // BWS
        while (iswhitespace(*ptr))
            ptr++;
        // token
        k = endptr = ptr;
        while (istchar(*endptr))
            endptr++;
        if (endptr == ptr)
            return NULL;
        ptr = endptr;
        if (*ptr == ';' || iscrlf(ptr))
        {
            MAP_put(result->extension, k, NULL);
            continue;
        }
        // BWS
        while (iswhitespace(*ptr))
            ptr++;
        // '='
        if (*ptr == '=')
            ptr++;
        else
            return NULL;
        *endptr = '\0';
        // BWS
        while (iswhitespace(*ptr))
            ptr++;
        // token / quoted-string
        if (*ptr == '"')
        {
            // quoted-string
            if ((v = qstring(ptr, &endptr)) == NULL)
                return NULL;
        }
        else
        {
            // token
            v = endptr = ptr;
            while (istchar(*endptr))
                endptr++;
            if (endptr == ptr)
                return NULL;
        }
        ptr = endptr;
        MAP_put(result->extension, k, v);
    }
    if (iscrlf(ptr))
        *endptr = '\0';
    else
        return NULL;
    return result;
}

struct multipart *parse_multipart(char *content, unsigned long content_length, char *boundary, struct multipart *result)
{
    struct entry e;
    struct part part, *temp;
    char *ptr = content, *endptr, *k;
    int blen = strlen(boundary);
    unsigned long len = content_length;
    result->parts = NULL;
    result->length = 0;
    // --boundary
    while (len > blen + 2)
    {
        if (strncmp("--", ptr, 2) == 0 && strncmp(boundary, ptr + 2, blen) == 0)
            break;
        ptr++;
        len--;
    }
    ptr += blen + 2;
    len -= blen + 2;
    if (len < 0)
        return NULL;
    while (len > 4 || strncmp("--\r\n", ptr, 4) != 0)
    {
        part.headers = MAP_new(1);
        // CRLF
        if (len >= 2 && iscrlf(ptr))
        {
            ptr += 2;
            len -= 2;
        }
        else
            return NULL;
        // headers
        while (!iscrlf(ptr))
        {
            // valid line
            endptr = ptr;
            while (len >= 2 && !iscrlf(endptr))
            {
                endptr++;
                len--;
            }
            endptr += 2;
            len -= 2;
            if (len < 0)
                return NULL;
            // field line
            if (HTTP_parse_fieldln(ptr, &e) == NULL)
                return NULL;
            if ((k = MAP_get(part.headers, e.key)) != NULL && e.value != NULL)
            {
                k = buffcat(k, strlen(k), ", ", 3);
                e.key = buffcat(k, strlen(k), e.key, strlen(e.key) + 1);
                free(k);
                STACK_push(result->stack, e.key);
            }
            MAP_put(part.headers, e.key, e.value);
            ptr = endptr;
        }
        // CRLF
        ptr += 2;
        len -= 2;
        if (len < 0)
            return NULL;
        part.content = ptr;
        part.content_length = 0;
        // --boundary CRLF
        while (len > blen + 4)
        {
            if (strncmp("\r\n--", ptr, 4) == 0 && strncmp(boundary, ptr + 4, blen) == 0)
                break;
            ptr++;
            len--;
            part.content_length++;
        }
        // append the new part
        result->length++;
        temp = result->parts;
        result->parts = malloc(sizeof(struct part) * result->length);
        if (temp != NULL)
        {
            memcpy(result->parts, temp, sizeof(struct part) * result->length - 1);
            free(temp);
        }
        result->parts[result->length - 1] = part;
        // next --boundary
        while (len > blen + 2)
        {
            if (strncmp("\r\n--", ptr, 4) == 0 && strncmp(boundary, ptr + 4, blen) == 0)
                break;
            ptr++;
            len--;
        }
        ptr += blen + 4;
        len -= blen + 4;
        if (len < 0)
            return NULL;
    }
    STACK_push(result->stack, result->parts);
    if (len < 4)
        return NULL;
    return result;
}

long recv_line(int fd, char **ptr)
{
    char c, ret, buffer[1024], *temp, *data = *ptr = NULL;
    short i = 0;
    long size = 0;
    while (!(c == '\n' && (i > 1 && buffer[i - 2] == '\r' || data != NULL && i == 1 && data[size - 1] == '\r')))
    {
        /* read a character */
        ret = recv(fd, &c, 1, 0);

        /* error or EOF */
        if (ret <= -1)
        {
            if (data != NULL)
                free(data);
            return -1;
        }

        /* append character to buffer or concat if buffer is full */
        if (i == sizeof(buffer))
        {
            temp = data;
            data = buffcat(data, size, buffer, sizeof(buffer));
            if (temp != NULL)
                free(temp);
            size += sizeof(buffer);
            if (size + sizeof(buffer) >= 4UL * (1 << 30)) // 4 GB limit
                return -2;
            i = 0;
        }
        else
        {
            buffer[i] = c;
            i++;
        }
    }
    if (i > 0)
    {
        temp = data;
        data = buffcat(data, size, buffer, i);
        if (temp != NULL)
            free(temp);
        size += i;
    }
    *ptr = data;
    return size - 2;
}

struct HTTP_request *recv_chunks(int fd, struct HTTP_request *result)
{
    char *data, *temp, *k;
    unsigned short size = 65535;
    long ret;
    unsigned long bytes;
    struct entry e;
    struct chunk chunk;
    ret = recv_line(fd, &data);
    if (ret < 0)
    {
        if (ret == -1)
            result->flags = CONNECTION_ERROR;
        if (ret == -2)
            result->flags = CONTENT_TOO_LARGE;
        return NULL;
    }
    STACK_push(result->stack, data);
    chunk.extension = MAP_new(0);
    if (HTTP_parse_chunk_size(data, &chunk) == NULL)
    {
        MAP_free(chunk.extension);
        result->flags = PARSE_ERROR;
        return NULL;
    }
    while (chunk.size > 0)
    {
        chunk.content = malloc(chunk.size);
        bytes = 0;
        while (bytes < chunk.size)
        {
            ret = recv(fd, chunk.content + bytes, bytes + size > chunk.size ? chunk.size - bytes : size, 0);
            if (ret <= 0)
            {
                MAP_free(chunk.extension);
                free(chunk.content);
                result->flags = CONNECTION_ERROR;
                return NULL;
            }
            bytes += ret;
        }
        ret = recv_line(fd, &data);
        free(data);
        if (ret != 0)
        {
            MAP_free(chunk.extension);
            free(chunk.content);
            if (ret == -1)
                result->flags = CONNECTION_ERROR;
            if (ret == -2)
                result->flags = CONTENT_TOO_LARGE;
            return NULL;
        }
        temp = result->content;
        result->content = buffcat(result->content, result->content_length, chunk.content, chunk.size);
        free(chunk.content);
        if (temp != NULL)
            free(temp);
        result->content_length += chunk.size;
        MAP_free(chunk.extension); // discard chunk extension
        ret = recv_line(fd, &data);
        if (ret < 0)
        {
            if (ret == -1)
                result->flags = CONNECTION_ERROR;
            if (ret == -2)
                result->flags = CONTENT_TOO_LARGE;
            return NULL;
        }
        STACK_push(result->stack, data);
        chunk.extension = MAP_new(0);
        if (HTTP_parse_chunk_size(data, &chunk) == NULL)
        {
            MAP_free(chunk.extension);
            result->flags = PARSE_ERROR;
            return NULL;
        }
    }
    STACK_push(result->stack, result->content);
    while (1)
    {
        size = recv_line(fd, &data);
        STACK_push(result->stack, data);
        if (size == 0)
            break;
        /* field-lines */
        if (HTTP_parse_fieldln(data, &e) == NULL)
        {
            result->flags = PARSE_ERROR;
            return NULL;
        }
        if ((k = MAP_get(result->trailers, e.key)) != NULL && e.value != NULL)
        {
            k = buffcat(k, strlen(k), ", ", 3);
            e.key = buffcat(k, strlen(k), e.key, strlen(e.key) + 1);
            free(k);
            STACK_push(result->stack, e.key);
        }
        MAP_put(result->trailers, e.key, e.value);
    }
    return result;
}

long HTTP_reqsize(HTTP_request *req)
{
    char *date;
    int i;
    long len = 6;
    len += strlen(req->method);
    len += strlen(req->target);
    if (req->query != NULL)
    {
        struct entry **es = MAP_entry_set(req->query);
        int size = MAP_size(req->query);
        for (i = 0; i < size; i++)
        {
            len += 2;
            len += strlen(es[i]->key);
            len += strlen(es[i]->value);
        }
    }
    len += strlen(req->protocol);
    if (req->headers != NULL)
    {
        struct entry **es = MAP_entry_set(req->headers);
        int size = MAP_size(req->headers);
        for (i = 0; i < size; i++)
        {
            len += 4;
            len += strlen(es[i]->key);
            len += strlen(es[i]->value);
        }
    }
    if (req->content != NULL)
        len += req->content_length;
    return len;
}

char *HTTP_reqmsg(HTTP_request *req, char *buffer)
{
    int i;
    long len = 0;
    /* write message */
    buffer[0] = '\0';
    len += sprintf(buffer, "%s %s", req->method, req->target);
    if (req->query != NULL)
    {
        struct entry **es = MAP_entry_set(req->query);
        int size = MAP_size(req->query);
        for (i = 0; i < size; i++)
        {
            len += 1;
            if (i == 0)
                strcat(buffer + len, "?");
            else
                strcat(buffer + len, "&");
            len += sprintf(buffer + len, "%s=%s", es[i]->key, es[i]->value);
        }
    }
    len += sprintf(buffer + len, " %s\r\n", req->protocol);
    if (req->headers != NULL)
    {
        struct entry **es = MAP_entry_set(req->headers);
        int size = MAP_size(req->headers);
        for (i = 0; i < size; i++) /* headers */
            len += sprintf(buffer + len, "%s: %s\r\n", es[i]->key, es[i]->value);
    }
    strcat(buffer + len, "\r\n");

    len += 2;
    if (req->content != NULL) /* body */
        memcpy(buffer + len, req->content, req->content_length);
    return buffer;
}

unsigned long HTTP_ressize(HTTP_response *res)
{
    char *date;
    int i;
    unsigned long len = 9;
    len += strlen(res->protocol);
    len += strlen(res->reason);
    if (res->headers != NULL)
    {
        struct entry **es = MAP_entry_set(res->headers);
        int size = MAP_size(res->headers);
        for (i = 0; i < size; i++)
        {
            len += 4;
            len += strlen(es[i]->key);
            len += strlen(es[i]->value);
        }
    }
    if (res->content != NULL)
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
        struct entry **es = MAP_entry_set(res->headers);
        int size = MAP_size(res->headers);
        for (int i = 0; i < size; i++) /* headers */
            len += sprintf(result + len, "%s: %s\r\n", es[i]->key, es[i]->value);
    }
    strcat(result + len, "\r\n");

    printf("---------------- RESPONSE ----------------\r\n\r\n%s\r\n", result); /* print response (excluding body) */

    len += 2;
    if (res->content != NULL) /* body */
        memcpy(result + len, res->content, res->content_length);
    return result;
}

long HTTP_send_response(HTTP_response *res, int fd)
{
    MAP *headers = MAP_new(1);
    if (res->headers != NULL)
        MAP_put_all(headers, res->headers);
    MAP_put_if_absent(headers, "Connection", "close");
    char date[29];
    if (!MAP_contains_key(headers, "Date"))
    { /* date */
        time_t timer;
        time(&timer);
        struct tm t;
        gmtime_r(&timer, &t);
        HTTP_date_ex(&t, date);
        MAP_put(headers, "Date", date);
    }
    char content_length[numlenul(res->content_length)];
    if (res->content != NULL && !MAP_contains_key(headers, "Content-Length"))
    { /* content-length */
        content_length[0] = '\0';
        sprintf(content_length, "%lu", res->content_length);
        MAP_put(headers, "Content-Length", content_length);
    }
    MAP *temp = res->headers;
    res->headers = headers;
    long len = HTTP_ressize(res);
    char msg[len];
    HTTP_resmsg(res, msg);
    res->headers = temp;
    unsigned long written = send(fd, msg, len, MSG_NOSIGNAL);
    MAP_free(headers);
    return written;
}