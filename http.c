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

// 8 MiB
#define MAX_LINE_SIZE 8 * (1 << 20)

enum FLAGS
{
    CONNECTION_ERROR = 0b00000001,
    PARSE_ERROR = 0b00000010,
    BAD_CONTENT_LENGTH = 0b00000100,
    CONTENT_TOO_LARGE = 0b00001000,
    CONNECTION_CLOSED = 0b00010000
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
    char *file;
    char *content;
    unsigned long content_length;
    MAP *trailers;
    STACK *stack;
} HTTP_response;

/*
 * -----------------
 * |     UTILS     |
 * -----------------
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
    *result = '\0';
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

MAP *content_type_map;
char content_type_map_initialized = 0;

char *HTTP_content_type(char *ext)
{
    if (!content_type_map_initialized)
    {
        content_type_map_initialized = 1;
        MAP *map = MAP_new(1);
        // video/matroska
        MAP_put(map, "mkv", "video/matroska");
        // video/matroska-3d
        MAP_put(map, "mk3d", "video/matroska-3d");
        // audio/matroska
        MAP_put(map, "mka", "audio/matroska");
        // application/octet-stream
        MAP_put(map, "mks", "application/octet-stream");
        // video/mp4
        MAP_put(map, "mp4", "video/mp4");
        MAP_put(map, "m4g4", "video/mp4");
        // audio/mpeg
        MAP_put(map, "mp3", "audio/mpeg");
        // video/webm
        MAP_put(map, "webm", "video/webm");
        // image/webp
        MAP_put(map, "webp", "image/webp");
        // image/svg+xml
        MAP_put(map, "svg", "image/svg+xml");
        MAP_put(map, "svgz", "image/svg+xml");
        // image/jpeg
        MAP_put(map, "jpg", "image/jpeg");
        MAP_put(map, "jpeg", "image/jpeg");
        // image/png
        MAP_put(map, "png", "image/png");
        // image/gif
        MAP_put(map, "gif", "image/gif");
        // text/javascript
        MAP_put(map, "js", "text/javascript");
        MAP_put(map, "mjs", "text/javascript");
        // application/json
        MAP_put(map, "json", "application/json");
        // text/html
        MAP_put(map, "html", "text/html");
        MAP_put(map, "htm", "text/html");
        // text/css
        MAP_put(map, "css", "text/css");
        // text/plain
        MAP_put(map, "txt", "text/plain");
        content_type_map = map;
    }
    return MAP_get_or_default(content_type_map, ext, "*");
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

/*
 * -----------------
 * |    NETWORK    |
 * -----------------
 */

__thread char buffer[65535];
__thread unsigned short buffer_pos = 0;
__thread unsigned short buffer_size = 0;

long recv_line(int fd, char **ptr)
{
    char done = 0, *temp, *data = *ptr = NULL;
    unsigned short n, i;
    long size = 0;
    while (!done)
    {
        // if the size is greater than the max size
        if (size > MAX_LINE_SIZE)
        {
            // free data and return -2
            if (data != NULL)
                free(data);
            return -2;
        }
        // if the buffer postion is past the size of the buffer
        if (buffer_pos >= buffer_size)
        {
            // receive new data
            if ((n = recv(fd, buffer, sizeof(buffer), 0)) < 0)
            {
                if (data != NULL)
                    free(data);
                return -1;
            }
            // if we recieved 0 bytes
            if (n == 0)
                // return -3 indicating the connection was closed
                return -3;
            // buffer position is 0
            buffer_pos = 0;
            // buffer size is the returned size
            buffer_size = n;
        }
        // if the first character in the buffer and the last character of data make a crlf
        if (buffer_pos == 0 && size > 0 && data[size - 1] == '\r' && buffer[0] == '\n')
            done = 1;
        // search for crlf in the buffer
        for (i = buffer_pos; i < buffer_size; i++)
        {
            if (i > 0 && buffer[i - 1] == '\r' && buffer[i] == '\n')
            {
                done = 1;
                break;
            }
        }
        // if we reached the end of the buffer
        if (i == sizeof(buffer) - 1)
        {
            // concatenate data and buffer
            temp = data;
            data = buffcat(data, size, buffer + buffer_pos, sizeof(buffer) - buffer_pos);
            if (temp != NULL)
                free(temp);
            // add buffer size - buffer position to the size
            size += sizeof(buffer) - buffer_pos;
        }
        else
        {
            temp = data;
            data = buffcat(data, size, buffer + buffer_pos, i + 1 - buffer_pos);
            if (temp != NULL)
                free(temp);
            // add read size to size
            size += i + 1 - buffer_pos;
        }
        // buffer position is i + 1
        buffer_pos = i + 1;
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
        if (ret == -3)
            result->flags = CONNECTION_CLOSED;
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
            if (ret == -3)
                result->flags = CONNECTION_CLOSED;
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
            if (ret == -3)
                result->flags = CONNECTION_CLOSED;
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
        if (size < 0)
        {
            STACK_free(result->stack);
            if (size == -1)
                result->flags = CONNECTION_ERROR;
            if (size == -2)
                result->flags = CONTENT_TOO_LARGE;
            if (size == -3)
                result->flags = CONNECTION_CLOSED;
            return NULL;
        }
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
            len += sprintf(buffer + len, "%s=%s", es[i]->key, (char *)es[i]->value);
        }
    }
    len += sprintf(buffer + len, " %s\r\n", req->protocol);
    if (req->headers != NULL)
    {
        struct entry **es = MAP_entry_set(req->headers);
        int size = MAP_size(req->headers);
        for (i = 0; i < size; i++) /* headers */
            len += sprintf(buffer + len, "%s: %s\r\n", es[i]->key, (char *)es[i]->value);
    }
    strcat(buffer + len, "\r\n");

    len += 2;
    if (req->content != NULL) /* body */
        memcpy(buffer + len, req->content, req->content_length);
    return buffer;
}

unsigned long HTTP_ressize(HTTP_response *res, char head)
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
    if (!head && res->content != NULL)
        len += res->content_length;
    return len;
}

char *HTTP_resmsg(HTTP_response *res, char *result, char head)
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
            len += sprintf(result + len, "%s: %s\r\n", es[i]->key, (char *)es[i]->value);
    }
    strcat(result + len, "\r\n");
    len += 2;
    if (!head && res->content != NULL) /* body */
        memcpy(result + len, res->content, res->content_length);
    return result;
}

long HTTP_send_response(HTTP_response *res, int fd, char head)
{
    MAP_put_if_absent(res->headers, "Connection", "close");
    if (!MAP_contains_key(res->headers, "Date"))
    { 
        /* date */
        char *date = malloc(29);
        STACK_push(res->stack, date);
        time_t timer;
        time(&timer);
        struct tm t;
        gmtime_r(&timer, &t);
        HTTP_date_ex(&t, date);
        MAP_put(res->headers, "Date", date);
    }
    if (!MAP_contains_key(res->headers, "Content-Length") && res->code != 204)
    {
        /* content-length */
        char *content_length = malloc(numlenul(res->content_length));
        STACK_push(res->stack, content_length);
        *content_length = '\0';
        sprintf(content_length, "%lu", res->content_length);
        MAP_put(res->headers, "Content-Length", content_length);
    }
    long len = HTTP_ressize(res, head);
    char *msg = malloc(len);
    HTTP_resmsg(res, msg, head);
    unsigned long written = send(fd, msg, len, MSG_NOSIGNAL);
    free(msg);
    return written;
}