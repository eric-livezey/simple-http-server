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

struct uri
{
    char *protocol;
    char *host;
    char *path;
    MAP *query;
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
    struct uri *target;
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

struct uri *URI_init(struct uri *uri)
{
    uri->protocol = NULL;
    uri->host = NULL;
    uri->path = NULL;
    uri->query = MAP_new_ignore_case();
}

int URI_size(struct uri *uri)
{
    int len = 0;
    if (uri->protocol != NULL)
        len += strlen(uri->protocol) + 3;
    if (uri->host != NULL)
        len += strlen(uri->host);
    if (uri->path != NULL)
        len += strlen(uri->path);
    if (uri->query != NULL)
    {
        struct entry **es = MAP_entry_set(uri->query);
        int size = MAP_size(uri->query);
        for (int i = 0; i < size; i++)
        {
            len += 2;
            len += strlen(es[i]->key);
            len += strlen(es[i]->value);
        }
    }
    return len;
}

int URI_tostr_ex(struct uri *uri, char *buffer)
{
    int len = 0;
    *buffer = '\0';
    if (uri->protocol != NULL)
        len += sprintf(buffer + len, "%s://", uri->protocol);
    if (uri->host != NULL)
        len += sprintf(buffer + len, "%s", uri->host);
    if (uri->path != NULL)
        len += sprintf(buffer + len, "%s", uri->path);
    if (uri->query != NULL)
    {
        struct entry **es = MAP_entry_set(uri->query);
        int size = MAP_size(uri->query);
        for (int i = 0; i < size; i++)
        {
            if (i == 0)
                strcat(buffer + len, "?");
            else
                strcat(buffer + len, "&");
            len += 1;
            len += sprintf(buffer + len, "%s=%s", es[i]->key, (char *)es[i]->value);
        }
    }
    return len;
}

char *URI_tostr(struct uri *uri)
{
    char *str = malloc(URI_size(uri));
    URI_tostr_ex(uri, str);
    return str;
}

void HTTP_request_init(HTTP_request *req)
{
    req->method = "GET";
    req->target = malloc(sizeof(struct uri));
    req->protocol = "HTTP/1.1";
    req->headers = MAP_new_ignore_case();
    req->content = NULL;
    req->content_length = 0;
    req->trailers = MAP_new_ignore_case();
    req->stack = STACK_new();
    req->flags = 0;
    URI_init(req->target);
    STACK_push(req->stack, req->target);
}

void HTTP_response_init(HTTP_response *res)
{
    res->protocol = "HTTP/1.1";
    res->code = 200;
    res->reason = "OK";
    res->headers = MAP_new_ignore_case();
    res->file = NULL;
    res->content = NULL;
    res->content_length = 0;
    res->trailers = MAP_new_ignore_case();
    res->stack = STACK_new();
}

void HTTP_request_free(HTTP_request *req)
{
    if (req->target != NULL && req->target->query != NULL)
        MAP_free(req->target->query);
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
    return HTTP_date_ex(tm, malloc(30 * sizeof(char)));
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
        MAP *map = MAP_new_ignore_case();
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

long HTTP_reqsize(HTTP_request *req)
{
    char *date;
    int i;
    long len = 6;
    len += strlen(req->method);
    len += URI_size(req->target);
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

int HTTP_reqmsg_ex(HTTP_request *req, char *buffer)
{
    int i;
    long len = 0;
    // write message
    *buffer = '\0';
    len += sprintf(buffer + len, "%s ", req->method);
    // target
    len += URI_tostr_ex(req->target, buffer + len);
    len += sprintf(buffer + len, " %s\r\n", req->protocol);
    if (req->headers != NULL)
    {
        // headers
        struct entry **es = MAP_entry_set(req->headers);
        int size = MAP_size(req->headers);
        for (i = 0; i < size; i++)
            len += sprintf(buffer + len, "%s: %s\r\n", es[i]->key, (char *)es[i]->value);
    }
    // use memcpy so as not to put a terminating '\0' which might index out of the buffer
    memcpy(buffer + len, "\r\n", 2);
    len += 2;
    // body
    if (req->content != NULL)
        memcpy(buffer + len, req->content, req->content_length);
    return len;
}

char *HTTP_reqmsg(HTTP_request *req)
{
    char *msg = malloc(HTTP_reqsize(req));
    HTTP_reqmsg_ex(req, msg);
    return msg;
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

int HTTP_resmsg_ex(HTTP_response *res, bool head, char *buffer)
{
    long len = 0;
    /* write message */
    *buffer = '\0';
    len += sprintf(buffer, "%s %d %s\r\n", res->protocol, res->code, res->reason); /* protocol code reason */
    if (res->headers != NULL)
    {
        struct entry **es = MAP_entry_set(res->headers);
        int size = MAP_size(res->headers);
        for (int i = 0; i < size; i++) /* headers */
            len += sprintf(buffer + len, "%s: %s\r\n", es[i]->key, (char *)es[i]->value);
    }
    /* use memcpy so as not to put a terminating '\0' which might index out of the buffer */
    memcpy(buffer + len, "\r\n", 2);
    len += 2;
    if (!head && res->content != NULL) /* body */
        memcpy(buffer + len, res->content, res->content_length);
    return len;
}

char *HTTP_resmsg(HTTP_response *res, bool head)
{
    char *msg = malloc(HTTP_ressize(res, head));
    HTTP_resmsg_ex(res, head, msg);
    return msg;
}

void HTTP_print_request(HTTP_request *req)
{
    void *content = req->content;
    req->content = NULL;
    unsigned long size = HTTP_reqsize(req) + 1;
    char *msg = malloc(size);
    HTTP_reqmsg_ex(req, msg);
    msg[size - 1] = '\0';
    printf("================ REQUEST  ================\r\n\r\n%s\r\n", msg);
    free(msg);
    req->content = content;
}

void HTTP_print_response(HTTP_response *res)
{
    unsigned long size = HTTP_ressize(res, 1) + 1;
    char *msg = malloc(size);
    HTTP_resmsg_ex(res, 1, msg);
    msg[size - 1] = '\0';
    printf("---------------- RESPONSE ----------------\r\n\r\n%s\r\n", msg); /* print response head */
    free(msg);
}

/*
 * -----------------
 * |    PARSING    |
 * -----------------
 */

char *parse_qstring(char *ptr, char **endptr)
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
            if ((v = parse_qstring(ptr, &endptr)) == NULL)
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

MAP *parse_query(char *ptr, char **endptr, MAP *result)
{
    char *ep = ptr, *k, *v, c;
    // '?'
    if (*ptr != '?')
        return NULL;
    ptr++;
    while (1)
    {
        // pchar / "/" / "?"
        k = ep = ptr;
        while (*ep != '=' && (*ep == '/' || *ep == '?' || ispchar(ep)))
            ep++;
        ptr = ep;
        // "="
        if (*ptr != '=')
        {
            v = ep;
            MAP_put(result, k, v);
            break;
        }
        *ep = '\0';
        ptr++;
        // pchar / "/" / "?"
        v = ep = ptr;
        while (*ep != '&' && (*ep == '/' || *ep == '?' || ispchar(ep)))
            ep++;
        ptr = ep;
        MAP_put(result, k, v);
        // [ "&" ]
        if (*ptr != '&')
            break;
        *ep = '\0';
        ptr++;
    }
    // temporarily set the endptr to null do as not to url decode past the end of the last value
    c = *ep;
    *ep = '\0';
    for (int i = 0; i < MAP_size(result); i++)
    {
        k = MAP_entry_set(result)[i]->key;
        v = MAP_entry_set(result)[i]->value;
        urldecode(k, k);
        urldecode(v, v);
    }
    *ep = c;
    *endptr = ep;
    return result;
}

struct uri *parse_origin_form(char *ptr, char **endptr, struct uri *result)
{
    char *ep = ptr;
    // 1*( "/" segment )
    result->path = ep = ptr;
    while (*ep == '/')
    {
        ep++;
        while (ispchar(ep))
            ep++;
    }
    if (ptr == ep)
        return NULL;
    *endptr = ptr = ep;
    // [ "?" query ]
    if (parse_query(ptr, endptr, result->query) == NULL)
        MAP_clear(result->query);
    else
        *ep = '\0';
    return result;
}

/// ```abnf
/// *( "/" segment )
/// ```
char *parse_path_abempty(char *ptr, char **endptr)
{
    char *ep = ptr;
    // *( "/" segment )
    while (*ep == '/')
    {
        ep++;
        while (ispchar(ep))
            ep++;
    }
    *endptr = ep;
    return ptr;
}
/// ```abnf
/// "/" [ segment-nz *( "/" segment ) ]
/// ```
char *parse_path_absolute(char *ptr, char **endptr)
{
    char *ep = ptr;
    // "/"
    if (*ep != '/')
        return NULL;
    ep++;
    // [ segment-nz *( "/" segment ) ]
    if (ispchar(ep))
    {
        ep++;
        while (ispchar(ep))
            ep++;
        // *( "/" segment )
        if (parse_path_abempty(ep, &ep) == NULL)
            return NULL;
    }
    *endptr = ep;
    return ptr;
}
/// ```abnf
/// segment-nz *( "/" segment )
/// ```
char *parse_path_rootless(char *ptr, char **endptr)
{
    char *ep = ptr;
    if (!ispchar(ep))
        return NULL;
    ep++;
    while (ispchar(ep))
        ep++;
    // *( "/" segment )
    if (parse_path_abempty(ep, &ep) == NULL)
        return NULL;
    *endptr = ep;
    return ptr;
}

/// ```abnf
/// DIGIT / %x31-39 DIGIT / "1" 2DIGIT / "2" %x30-34 DIGIT / "25" %x30-35 ; Any number from 0-255
/// ```
char *parse_dec_octet(char *ptr, char **endptr)
{
    char *ep = ptr;
    // Parse the integer until it's 3 digits long
    short n = 0;
    while (n < 100 && isdigit(*ep))
    {
        n = n * 10 + (*ep - '0');
        ep++;
    }
    if (n > 255)
        // The number is greater than 255, so omit the last character
        ep--;
    if (ptr == ep)
        // The string is empty, so return null
        return NULL;
    *endptr = ep;
    return ptr;
}
/// ```abnf
/// dec-octet "." dec-octet "." dec-octet "." dec-octet
/// ```
char *parse_ipv4_address(char *ptr, char **endptr)
{
    char *ep = ptr;
    // dec-octet
    if (parse_dec_octet(ep, &ep) == NULL)
    {
        return NULL;
    }
    for (char i = 0; i < 3; i++)
    {
        // "."
        if (*ep != '.')
            return NULL;
        ep++;
        // dec-octet
        if (parse_dec_octet(ep, &ep) == NULL)
            return NULL;
    }
    *endptr = ep;
    return ptr;
}

/// ```abnf
///                              6( h16 ":" ) ls32
/// /                       "::" 5( h16 ":" ) ls32
/// / [               h16 ] "::" 4( h16 ":" ) ls32
/// / [ *1( h16 ":" ) h16 ] "::" 3( h16 ":" ) ls32
/// / [ *2( h16 ":" ) h16 ] "::" 2( h16 ":" ) ls32
/// / [ *3( h16 ":" ) h16 ] "::"    h16 ":"   ls32
/// / [ *4( h16 ":" ) h16 ] "::"              ls32
/// / [ *5( h16 ":" ) h16 ] "::"              h16
/// / [ *6( h16 ":" ) h16 ] "::"
/// ```
char *parse_ipv6_address(char *ptr, char **endptr)
{
    // The unusually long abnf is just to account for the short form
    // :: is valid
    // FFFF::FF is valid
    // ::FFFF::FFFF is ambigous so invalid
    // FFFF:FFFF:FFFF:FFFF:FFFF:FFFF:FFFF:FFFF is valid
    // FF::FFFF:FFFF:FFFF:FFFF:255.255.255.255 is valid
    // Essentially up to 8 segments with no more than one short form
    // Then the last two segments can be an ipv4
    char *ep = ptr, n = 0, len;
    bool short_form = false, separated = true;
    while (n < 8)
    {
        if (separated && (n == 6 || short_form && n < 6) && parse_ipv4_address(ep, &ep) != NULL)
        {
            // Pointer is a terminating IPv4 address, so count 2 segments and break
            n += 2;
            break;
        }
        else if (separated && isxdigit(*ep))
        {
            // Character is a hex digit, so parse up to 4 hex digits
            separated = false;
            len = 0;
            while (isxdigit(*ep) && len < 4)
            {
                ep++;
                len++;
            }
            n++;
        }
        else if (n == 0 && *ep == ':')
        {
            // Character is ":" and is the first character, so parse the short form
            ep++;
            if (*ep != ':')
                return NULL;
            ep++;
            n++;
            short_form = true;
        }
        else if (!separated && *ep == ':')
        {
            // Character is ":", so parse the separator or short form
            separated = true;
            ep++;
            if (!short_form && *ep == ':')
            {
                // Next character is ":" and no short form has been parsed, so parse the short form
                ep++;
                n++;
                short_form = true;
            }
        }
        else
        {
            // Pointer is not a valid token, so break
            break;
        }
    }
    if (n != 8 && (!short_form || n > 8))
        // There must be either 8 segments or the short form and less than 8 segments, so return null
        return NULL;
    *endptr = ep;
    return ptr;
}

// ```abnf
// "v" 1*HEXDIG "." 1*( unreserved / sub-delims / ":" )
// ```
char *parse_ipvfuture(char *ptr, char **endptr)
{
    char *ep = ptr, len;
    // "v"
    if (*ep != 'v')
        return NULL;
    ep++;
    // 1*HEXDIG
    len = 0;
    while (isxdigit(*ep))
    {
        ep++;
        len++;
    }
    if (len < 1)
        return NULL;
    // "."
    if (*ep != '.')
        return NULL;
    ep++;
    // 1*( unreserved / sub-delims / ":" )
    len = 0;
    while (isunreserved(*ep) || issubdelim(*ep) || *ep == ':')
    {
        ep++;
        len++;
    }
    if (len < 1)
        return NULL;
    *endptr = ep;
    return ptr;
}
/// ```abnf
/// "[" ( IPv6address / IPvFuture ) "]"
/// ```
char *parse_ip_literal(char *ptr, char **endptr)
{
    char *ep = ptr;
    // "["
    if (*ep != '[')
        return NULL;
    ep++;
    // ( IPv6address / IPvFuture )
    if (parse_ipv6_address(ep, &ep) == NULL && parse_ipvfuture(ep, &ep) == NULL)
        return NULL;
    // "]"
    if (*ep != ']')
        return NULL;
    ep++;
    *endptr = ep;
    return ptr;
}

/// ```abnf
/// [ userinfo "@" ] host [ ":" port ]
/// ```
char *parse_authority(char *ptr, char **endptr)
{
    char *ep = ptr;
    // *( unreserved / pct-encoded / sub-delims / ":" )
    while (isunreserved(*ep) || ispctenc(ep) || issubdelim(*ep) || *ep == ':')
        ep++;
    // "@"
    if (*ep == '@')
        ep++;
    else
        ep = ptr;
    // IP-literal / IPv4address / reg-name
    if (parse_ip_literal(ep, &ep) == NULL && parse_ipv4_address(ep, &ep) == NULL)
    {
        // *( unreserved / pct-encoded / sub-delims )
        while (isunreserved(*ep) || ispctenc(ep) || issubdelim(*ep))
            ep++;
    }
    // ":" port
    if (*ep == ':')
    {
        ep++;
        // *DIGIT
        while (isdigit(*ep))
            ep++;
    }
    *endptr = ep;
    return ptr;
}
/// ```abnf
/// scheme ":" hier-part [ "?" query ]
/// ```
struct uri *parse_absolute_form(char *ptr, char **endptr, struct uri *result, STACK *stack)
{
    char *ep = ptr;
    result->protocol = ep = ptr;
    // ALPHA
    if (!isalpha(*ep))
        return NULL;
    ep++;
    // *( ALPHA / DIGIT / "+" / "-" / "." )
    while (isalnum(*ep) || *ep == '+' || *ep == '-' || *ep == '.')
        ep++;
    ptr = ep;
    // ":"
    if (*ptr != ':')
        return NULL;
    ptr++;
    *ep = '\0';
    ep = ptr;
    // "//" authority path-abempty / path-absolute / path-rootless / path-empty
    if (strncmp(ep, "//", 2) != 0 || (result->host = parse_authority(ep + 2, &ep)) == NULL || (result->path = parse_path_abempty(ep, &ep)) == NULL)
    {
        ep = ptr;
        if ((result->path = parse_path_absolute(ep, &ep)) == NULL)
            result->path = parse_path_rootless(ep, &ep);
    }
    if (result->host != NULL)
    {
        unsigned char len = ep - result->path;
        char *path = malloc(len + 1);
        STACK_push(stack, path);
        strncpy(path, result->path, len);
        *(result->path) = '\0';
        result->path = path;
    }
    *endptr = ptr = ep;
    // [ "?" query ]
    if (parse_query(ptr, endptr, result->query) == NULL)
        MAP_clear(result->query);
    else
        *ep = '\0';
    return result;
}
/// ```abnf
/// (IP-literal / IPv4address / reg-name) ":" *DIGIT
/// ```
struct uri *parse_authority_form(char *ptr, char **eptr, struct uri *result)
{
    char *endptr = ptr;
    result->host = ptr;
    // IP-literal / IPv4address / reg-name
    if (parse_ip_literal(endptr, &endptr) == NULL && parse_ipv4_address(endptr, &endptr) == NULL)
    {
        // *( unreserved / pct-encoded / sub-delims )
        while (isunreserved(*endptr) || ispctenc(endptr) || issubdelim(*endptr))
            endptr++;
    }
    // ":" port
    if (*endptr == ':')
    {
        endptr++;
        // *DIGIT
        while (isdigit(*endptr))
            endptr++;
    }
    *eptr = endptr;
    return result;
}

struct uri *HTTP_parse_target(char *ptr, char **endptr, struct uri *result, STACK *stack)
{
    if (parse_origin_form(ptr, endptr, result) == NULL && parse_absolute_form(ptr, endptr, result, stack) == NULL && parse_authority_form(ptr, endptr, result) == NULL)
    {
        if (*ptr = '*')
        {
            if (*endptr != NULL)
                *endptr = ptr + 1;
            **endptr = '\0';
        }
        else
        {
            return NULL;
        }
    }
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
    if (HTTP_parse_target(ptr, &endptr, result->target, result->stack) == NULL)
        return NULL;
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
            if ((v = parse_qstring(ptr, &endptr)) == NULL)
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
        part.headers = MAP_new_ignore_case();
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

ssize_t recv_r(int fd, void *buf, size_t n, int flags)
{
    unsigned long len = buffer_size - buffer_pos;
    if (len >= n)
    {
        memcpy(buf, buffer + buffer_pos, n);
        buffer_pos += n;
        return n;
    }
    memcpy(buf, buffer + buffer_pos, len);
    buffer_pos += len;
    ssize_t ret = recv(fd, buf + len, n - len, flags);
    if (ret < 0)
        return ret;
    else
        return ret + len;
}

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
            {
                if (data != NULL)
                    free(data);
                // return -3 indicating the connection was closed
                return -3;
            }
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
    chunk.extension = MAP_new();
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
            ret = recv_r(fd, chunk.content + bytes, bytes + size > chunk.size ? chunk.size - bytes : size, 0);
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
        chunk.extension = MAP_new();
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

long HTTP_send_response(HTTP_response *res, int fd, char head)
{
    MAP_put_if_absent(res->headers, "Connection", "close");
    if (!MAP_contains_key(res->headers, "Date"))
    {
        /* date */
        time_t timer;
        time(&timer);
        struct tm t;
        gmtime_r(&timer, &t);
        char *date = HTTP_date(&t);
        STACK_push(res->stack, date);
        MAP_put(res->headers, "Date", date);
    }
    if (res->code != 204)
    {
        /* content-length */
        char *content_length = malloc(numlenul(res->content_length) + 1);
        STACK_push(res->stack, content_length);
        *content_length = '\0';
        sprintf(content_length, "%lu", res->content_length);
        MAP_put(res->headers, "Content-Length", content_length);
    }
    long size = HTTP_ressize(res, head);
    char *msg = malloc(size);
    HTTP_resmsg_ex(res, head, msg);
    unsigned long written = send(fd, msg, size, MSG_NOSIGNAL);
    free(msg);
    return written;
}

void HTTP_respond_file(HTTP_request *req, char *path, HTTP_response *res, int fd)
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
        if (range == NULL || range[0] < 0 || range[0] >= size || range[0] > range[1])
        {
            res->code = 416; /* Range Not Satisfiable */
            res->reason = HTTP_reason(res->code);
            char *content_range = malloc(numlenul(size) + 9);
            STACK_push(res->stack, content_range);
            *content_range = '\0';
            sprintf(content_range, "bytes */%ld", size);
            MAP_put(res->headers, "Content-Range", content_range);
            HTTP_send_response(res, fd, 0);
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
            res->content_length = size;
            HTTP_send_response(res, fd, 1);
            if (strcmp(req->method, "HEAD") != 0)
                /* body */
                send_file(fd, fp, range[0], range[1]);
        }
    }
    else
    {

        res->reason = HTTP_reason(res->code);
        res->content_length = size;
        HTTP_send_response(res, fd, 1);
        /* body */
        if (strcmp(req->method, "HEAD") != 0)
            send_file(fd, fp, 0, size - 1);
    }
    fclose(fp);
}

HTTP_request *HTTP_readreq_ex(int fd, HTTP_request *result)
{
    char *data = NULL, *temp, *k, *v;
    long i = 0, ret;
    struct entry e;
    result->method = NULL;
    result->protocol = NULL;
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
            ret = recv_r(fd, result->content + bytes, bytes + size > content_length ? content_length - bytes : size, 0);
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
//
// int main(int argc, char **argv)
// {
//     struct uri uri;
//     char *endptr;
//     char *str = malloc(100);
//     strcpy(str, "https://admin:awww@.google.com:8000/watch?uri=https://www.youtube.com?v=1%26b=");
//     printf("%s\n", str);
//     struct uri *result = HTTP_parse_target(str, &endptr, &uri, STACK_new());
//     if (result != NULL)
//     {
//         int len = endptr - str;
//         char buf[len + 1];
//         memset(buf, ' ', len);
//         buf[len] = '\0';
//         printf("%s^\n", buf);
//         printf("protocol=%s\nhost=%s\npath=%s\nquery=", uri.protocol, uri.host, uri.path);
//         if (MAP_size(uri.query) > 0)
//         {
//             printf("{ ");
//             for (int i = 0; i < MAP_size(uri.query); i++)
//             {
//                 if (i > 0)
//                 {
//                     printf(", ");
//                 }
//                 printf("\"%s\"=\"%s\"", MAP_entry_set(uri.query)[i]->key, (char *)MAP_entry_set(uri.query)[i]->value);
//             }
//             printf(" }");
//         }
//         else
//         {
//             printf("{}");
//         }
//         printf("\n");
//     }
//     else
//     {
//         printf("bad URI");
//     }
// }