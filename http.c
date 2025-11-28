#include <stdlib.h>
#include <stdbool.h>
#include <stdio.h>
#include <string.h>
#include <ctype.h>
#include <time.h>
#include <netinet/in.h>
#include "utils.h"
#include "hashmap.h"
#include "uri.h"

// DIGIT
static const uint64_t L_DIGIT = 0x3FF000000000000;
static const uint64_t H_DIGIT = 0x0;

// UPALPHA
static const uint64_t L_UPALPHA = 0x0;
static const uint64_t H_UPALPHA = 0x7FFFFFE;

// LOWALPHA
static const uint64_t L_LOWALPHA = 0x0;
static const uint64_t H_LOWALPHA = 0x7FFFFFE00000000;

// ALPHA
static const uint64_t L_ALPHA = L_LOWALPHA | L_UPALPHA;
static const uint64_t H_ALPHA = H_LOWALPHA | H_UPALPHA;

// ALPHA / DIGIT
static const uint64_t L_ALPHANUM = L_DIGIT | L_ALPHA;
static const uint64_t H_ALPHANUM = H_DIGIT | H_ALPHA;

// VCHAR
static const uint64_t L_VCHAR = 0xfffffffe00000000;
static const uint64_t H_VCHAR = 0x7fffffffffffffff;

// SP / HTAB
static const uint64_t L_LWSP_CHAR = 0x100000200; // low_mask(" \t")
static const uint64_t H_LWSP_CHAR = 0x0;         // high_mask(" \t")

// tchar = "!" / "#" / "$" / "%" / "&" / "'" / "*" / "+" / "-" / "." /
//         "^" / "_" / "`" / "|" / "~" / DIGIT / ALPHA
static const uint64_t L_TCHAR = L_ALPHANUM | 0x6cfa00000000;     // low_mask("!#$%&'*+-.^_`|~")
static const uint64_t H_TCHAR = H_ALPHANUM | 0x50000001c0000000; // high_mask("!#$%&'*+-.^_`|~")

// obs-text
static const uint64_t L_OBS_TEXT = L_NON_ASCII;
static const uint64_t H_OBS_TEXT = H_NON_ASCII;

// qdtext = HTAB / SP / %x21 / %x23-5B / %x5D-7E / obs-text
static const uint64_t L_QDTEXT = (L_LWSP_CHAR | L_VCHAR | L_OBS_TEXT) & ~0x400000000; // low_mask("\"")
static const uint64_t H_QDTEXT = (H_LWSP_CHAR | H_VCHAR | H_OBS_TEXT) & ~0x10000000;  // high_mask("\\")

// quoted-pair = "\" ( HTAB / SP / VCHAR / obs-text )
static const uint64_t L_QUOTED_PAIR = L_LWSP_CHAR | L_VCHAR | L_OBS_TEXT;
static const uint64_t H_QUOTED_PAIR = H_LWSP_CHAR | H_VCHAR | H_OBS_TEXT;

// field-vchar =  VCHAR / obs-text
static const uint64_t L_FIELD_VCHAR = L_VCHAR | L_OBS_TEXT;
static const uint64_t H_FIELD_VCHAR = H_VCHAR | H_OBS_TEXT;

// SP / HTAB / field-vchar
static const uint64_t L_FIELD = L_LWSP_CHAR | L_FIELD_VCHAR;
static const uint64_t H_FIELD = H_LWSP_CHAR | H_FIELD_VCHAR;

// %x21-2B / %x2D-7E ; VCHAR excluding comma
static const uint64_t L_RANGE = L_VCHAR & ~0x100000000000; // low_mask(",")
static const uint64_t H_RANGE = H_VCHAR;

// 8 MiB
#define MAX_LINE_SIZE 0x800000
#define BUFFER_SIZE UINT16_MAX

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
    uint64_t content_length;
    char *content;
};

struct multipart
{
    struct part **parts;
    int32_t length;
    STACK *stack;
};

struct media_type
{
    char *type;
    char *subtype;
    MAP *parameters;
};

struct chunk
{
    uint64_t size;
    char *content;
    MAP *extension;
};

struct int_range
{
    uint64_t first;
    uint64_t last;
};

struct range
{
    char *units;
    char **set;
    int length;
    STACK *stack;
};

struct http_request
{
    char *method;
    struct uri *target;
    char *version;
    MAP *headers;
    char *content;
    uint64_t content_length;
    MAP *trailers;
    STACK *stack;
    uint8_t flags;
};

struct http_response
{
    char *version;
    uint16_t code;
    char *reason;
    MAP *headers;
    char *file;
    char *content;
    uint64_t content_length;
    MAP *trailers;
    STACK *stack;
};

/*
 * -----------------
 * |     UTILS     |
 * -----------------
 */

void RANGE_init(struct range *r)
{
    r->units = NULL;
    r->set = NULL;
    r->length = 0;
    r->stack = STACK_new();
}

void RANGE_free(struct range *r)
{
    STACK_free(r->stack);
}

void HTTP_request_init(struct http_request *req)
{
    req->method = "GET";
    req->target = URI_new();
    req->version = "HTTP/1.1";
    req->headers = MAP_new_ignore_case();
    req->content = NULL;
    req->content_length = 0;
    req->trailers = MAP_new_ignore_case();
    req->stack = STACK_new();
    req->flags = 0;
    STACK_push(req->stack, req->target);
}

void HTTP_response_init(struct http_response *res)
{
    res->version = "HTTP/1.1";
    res->code = 200;
    res->reason = "OK";
    res->headers = MAP_new_ignore_case();
    res->file = NULL;
    res->content = NULL;
    res->content_length = 0;
    res->trailers = MAP_new_ignore_case();
    res->stack = STACK_new();
}

void HTTP_request_free(struct http_request *req)
{
    if (req->headers != NULL)
        MAP_free(req->headers);
    if (req->trailers != NULL)
        MAP_free(req->trailers);
    STACK_free(req->stack);
}

void HTTP_response_free(struct http_response *res)
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

char *HTTP_reason(uint16_t code)
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

MAP *content_type_map = NULL;
bool content_type_map_initialized = false;

char *HTTP_content_type(char *ext)
{
    if (!content_type_map_initialized)
    {
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
        content_type_map_initialized = true;
    }
    return MAP_get_or_default(content_type_map, ext, "*");
}

uint64_t HTTP_reqsize(struct http_request *req, bool head)
{
    // 2SP 2CRLF
    uint64_t len = 6;
    // request-method
    len += strlen(req->method);
    // request-target
    len += URI_size(req->target);
    // HTTP-version
    len += strlen(req->version);
    if (req->headers != NULL)
    {
        struct entry **es = MAP_entry_set(req->headers), *e;
        int size = MAP_size(req->headers);
        for (int i = 0; i < size; i++)
        {
            e = es[i];
            // ":" SP CRLF
            len += 4;
            // field-name
            len += strlen(e->key);
            // field-value
            len += strlen(e->value);
        }
    }
    if (!head && req->content != NULL)
    {
        // content
        len += req->content_length;
    }
    return len;
}

uint64_t HTTP_push_request(BUFFER *b, struct http_request *req, bool head)
{
    uint64_t initial_size = BUFFER_size(b);
    // request-method SP
    BUFFER_sprintf(b, "%s ", req->method);
    // request-target
    URI_sprint(b, req->target);
    // SP HTTP-version CRLF
    BUFFER_sprintf(b, " %s\r\n", req->version);
    if (req->headers != NULL)
    {
        // headers
        struct entry **es = MAP_entry_set(req->headers), *e;
        int size = MAP_size(req->headers);
        for (int i = 0; i < size; i++)
        {
            e = es[i];
            // field-name ":" SP field-value CRLF
            BUFFER_sprintf(b, "%s: %s\r\n", e->key, e->value);
        }
    }
    // CRLF
    BUFFER_sprint(b, "\r\n");
    if (!head && req->content != NULL)
    {
        // content
        BUFFER_push(b, req->content, req->content_length);
    }
    return BUFFER_size(b) - initial_size;
}

uint64_t HTTP_reqmsg_ex(struct http_request *req, bool head, uint8_t **result)
{
    uint64_t size = HTTP_reqsize(req, head);
    BUFFER *b = BUFFER_new(size);
    HTTP_push_request(b, req, head);
    return BUFFER_get_ex(b, result);
}

uint8_t *HTTP_reqmsg(struct http_request *req, bool head)
{
    uint64_t size = HTTP_reqsize(req, head);
    BUFFER *b = BUFFER_new(size);
    HTTP_push_request(b, req, head);
    return BUFFER_get(b);
}

void HTTP_print_request(struct http_request *req)
{
    uint64_t size = HTTP_reqsize(req, true) + 1;
    BUFFER *b = BUFFER_new(size);
    HTTP_push_request(b, req, true);
    BUFFER_pushb(b, 0);
    char *s = BUFFER_get(b);
    printf("================ REQUEST ================\r\n\r\n%s\r\n", s);
    free(s);
}

uint64_t HTTP_ressize(struct http_response *req, bool head)
{
    // 2SP 3DIGIT 2CRLF
    uint64_t len = 9;
    // HTTP-version
    len += strlen(req->version);
    // reason-phrase
    len += strlen(req->reason);
    if (req->headers != NULL)
    {
        struct entry **es = MAP_entry_set(req->headers), *e;
        int size = MAP_size(req->headers);
        for (int i = 0; i < size; i++)
        {
            e = es[i];
            // ":" SP CRLF
            len += 4;
            // field-name
            len += strlen(e->key);
            // field-value
            len += strlen(e->value);
        }
    }
    if (!head && req->content != NULL)
    {
        // content
        len += req->content_length;
    }
    return len;
}

uint64_t HTTP_push_response(BUFFER *b, struct http_response *res, bool head)
{
    uint64_t initial_size = BUFFER_size(b);
    // HTTP-version SP status-code SP reason-phrase CRLF
    BUFFER_sprintf(b, "%s %d %s\r\n", res->version, res->code, res->reason);
    if (res->headers != NULL)
    {
        // headers
        struct entry **es = MAP_entry_set(res->headers), *e;
        int size = MAP_size(res->headers);
        for (int i = 0; i < size; i++)
        {
            e = es[i];
            // field-name ":" SP field-value CRLF
            BUFFER_sprintf(b, "%s: %s\r\n", e->key, e->value);
        }
    }
    // CRLF
    BUFFER_sprint(b, "\r\n");
    if (!head && res->content != NULL)
    {
        // content
        BUFFER_push(b, res->content, res->content_length);
    }
    return BUFFER_size(b) - initial_size;
}

uint64_t HTTP_resmsg_ex(struct http_response *res, bool head, uint8_t **result)
{
    uint64_t size = HTTP_ressize(res, head);
    BUFFER *b = BUFFER_new(size);
    HTTP_push_response(b, res, head);
    return BUFFER_get_ex(b, result);
}

uint8_t *HTTP_resmsg(struct http_response *res, bool head)
{
    uint64_t size = HTTP_ressize(res, head);
    BUFFER *b = BUFFER_new(size);
    HTTP_push_response(b, res, head);
    return BUFFER_get(b);
}

void HTTP_print_response(struct http_response *res)
{
    uint64_t size = HTTP_ressize(res, true) + 1;
    BUFFER *b = BUFFER_new(size);
    HTTP_push_response(b, res, true);
    BUFFER_pushb(b, 0);
    char *s = BUFFER_get(b);
    printf("---------------- RESPONSE ----------------\r\n\r\n%s\r\n", s);
    free(s);
}

/*
 * -----------------
 * |    PARSING    |
 * -----------------
 */

int32_t scan_crlf(char *ptr, char **endptr)
{
    char *ep = ptr;
    // Process CRLF
    if (*ep++ != '\r' || *ep++ != '\n')
    {
        return -1;
    }
    set_endptr(endptr, ep);
    return ep - ptr;
}

int32_t scan_quoted_pair(char *ptr, char **endptr)
{
    char *ep = ptr;
    // Process quoted pair
    if (*ep++ != '\\' || !match(*ep++, L_QUOTED_PAIR, H_QUOTED_PAIR))
    {
        return -1;
    }
    set_endptr(endptr, ep);
    return ep - ptr;
}

int32_t scan_qstring(char *ptr, char **endptr)
{
    char *ep = ptr;
    // DQUOTE
    if (*ep != '"')
    {
        return -1;
    }
    ep++;
    // *( qdtext / quoted-pair )
    if (scan_r(ep, &ep, &scan_quoted_pair, L_QDTEXT, H_QDTEXT) < 0)
    {
        return -1;
    }
    // DQUOTE
    if (*ep != '"')
    {
        return -1;
    }
    set_endptr(endptr, ep);
    return ep - ptr;
}

// quoted-string  = DQUOTE *( qdtext / quoted-pair ) DQUOTE
int32_t parse_qstring(char *ptr, char **endptr, char **s)
{
    bool pair = false;
    char *p, *ep = ptr;
    int32_t offset = 0;
    // DQUOTE
    if (*ep != '"')
        return -1;
    ep++;
    p = ep;
    // *( qdtext / quoted-pair )
    while (match(*ep, L_QDTEXT, H_QDTEXT) || (pair = scan_quoted_pair(ep, &ep) >= 0))
    {
        if (pair)
        {
            ep--;
            offset--;
        }
        (ep++)[offset] = *ep;
        pair = false;
    }
    // DQUOTE
    if (*ep != '"')
    {
        return -1;
    }
    (ep++)[offset] = '\0';
    *s = p;
    set_endptr(endptr, ep);
    return ep - ptr;
}

int scan_ows(char *ptr, char **endptr)
{
    return scan(ptr, endptr, L_LWSP_CHAR, H_LWSP_CHAR);
}

// token = 1*tchar
int scan_token(char *ptr, char **endptr)
{
    char *ep = ptr;
    if (scan(ep, &ep, L_TCHAR, H_TCHAR) < 1)
    {
        return -1;
    }
    set_endptr(endptr, ep);
    return ep - ptr;
}

// parameter       = parameter-name "=" parameter-value
// parameter-name  = token
// parameter-value = ( token / quoted-string )
int HTTP_parse_parameter(char *ptr, char **endptr, struct entry *result)
{
    char *ep = ptr, *k, *v;
    k = ep;
    // token
    if (scan_token(ep, &ep) < 0)
    {
        return -1;
    }
    // '='
    if (*ep != '=')
    {
        return -1;
    }
    *ep = '\0';
    ep++;
    v = ep;
    // token / quoted-string
    if (scan_token(ep, &ep) < 0 && parse_qstring(ep, &ep, &v) < 0)
    {
        return -1;
    }
    result->key = k;
    result->value = v;
    set_endptr(endptr, ep);
    return ep - ptr;
}

// parameters      = *( OWS ";" OWS [ parameter ] )
int HTTP_parse_parameters(char *ptr, char **endptr, MAP *result)
{
    char *p, *ep = ptr;
    struct entry e;
    while (*ep)
    {
        p = ep;
        // OWS
        scan_ows(ep, &ep);
        // ";"
        if (*ep != ';')
        {
            ep = p;
            break;
        }
        *ep = '\0';
        ep++;
        // OWS
        scan_ows(ep, &ep);
        // parameter
        if (HTTP_parse_parameter(ep, &ep, &e) < 0)
        {
            continue;
        }
        MAP_put(result, e.key, e.value);
    }
    set_endptr(endptr, ep);
    return ep - ptr;
}

// int-range     = first-pos "-" [ last-pos ]
// first-pos     = 1*DIGIT
// last-pos      = 1*DIGIT
// suffix-range  = "-" suffix-length
// suffix-length = 1*DIGIT
int HTTP_parse_int_range(char *ptr, char **endptr, uint64_t size, struct int_range *r)
{
    bool has_first, has_last;
    char *p, *ep = ptr;
    uint64_t n;
    // first-pos
    p = ep;
    n = strtoull(ep, &ep, 10);
    has_first = ep > p;
    r->first = has_first ? n : 0;
    // "-"
    if (*ep != '-')
    {
        return -1;
    }
    ep++;
    // last-pos
    p = ep;
    n = strtoull(ep, &ep, 10);
    has_last = ep > p;
    if (!has_first && !has_last)
    {
        return -1;
    }
    r->last = has_last ? n : size - 1;
    set_endptr(endptr, ep);
    return ep - ptr;
}

// range-spec       = int-range
//                  / suffix-range
//                  / other-range
// int-range     = first-pos "-" [ last-pos ]
// first-pos     = 1*DIGIT
// last-pos      = 1*DIGIT
// suffix-range  = "-" suffix-length
// suffix-length = 1*DIGIT
// other-range   = 1*( %x21-2B / %x2D-7E )
//               ; 1*(VCHAR excluding comma)
int HTTP_scan_range_spec(char *ptr, char **endptr)
{
    char *ep = ptr;
    // int-range and suffix-range are both satisfiable by other-range
    if (scan(ep, &ep, L_RANGE, H_RANGE) < 1)
    {
        return -1;
    }
    set_endptr(endptr, ep);
    return ep - ptr;
}

// ranges-specifier = range-unit "=" range-set
// range-unit       = token
// range-set        = range-spec *( OWS "," OWS range-spec )
int HTTP_parse_range(char *ptr, char **endptr, struct range *r)
{
    char *p, *s, *ep = ptr;
    int len;
    // range-unit
    p = ptr;
    if (scan_token(ep, &ep) < 0)
    {
        return -1;
    }
    // "="
    if (*ep != '=')
    {
        return -1;
    }
    *ep = '\0';
    r->units = p;
    ep++;
    // range-set
    // range-spec
    p = ep;
    if ((len = HTTP_scan_range_spec(ep, &ep)) < 0)
    {
        return -1;
    }
    STACK *specs = STACK_new();
    STACK_push(specs, strnalloc(p, len, r->stack));
    // *
    while (1)
    {
        // (
        p = ep;
        // OWS
        scan_ows(ep, &ep);
        // ","
        if (*ep != ',')
        {
            ep = p;
            break;
        }
        // OWS
        scan_ows(ep, &ep);
        s = ep;
        // range-spec
        if ((len = HTTP_scan_range_spec(ep, &ep)) < 0)
        {
            ep = p;
            break;
        }
        STACK_push(specs, strnalloc(s, len, r->stack));
        // )
    }
    int size = STACK_size(specs);
    r->set = malloc(size * sizeof(char *));
    STACK_push(r->stack, r->set);
    while (!STACK_empty(specs))
    {
        r->set[STACK_size(specs) - 1] = STACK_pop(specs);
    }
    STACK_free(specs);
    r->length = size;
    set_endptr(endptr, ep);
    return ep - ptr;
}

typedef int(parser_t)(char *, char **, void *);

/// @brief Parse a line from the ptr into the result using the parser.
/// @note Technically, this could index out of a buffer if we passed an argument for ptr which did
/// not end in a CRLF. This is not an issue for this implementation though since we only receive lines
/// up to and including a terminating CRLF.
/// @param ptr The pointer.
/// @param parser The parser function.
/// @param result The result object for the parser.
/// @return The number of bytes parsed
uint32_t HTTP_parseln(char *ptr, parser_t *parser, void *result)
{
    char *p, *ep = ptr;
    if (parser(ep, &ep, result) < 0)
    {
        return -1;
    }
    p = ep;
    if (scan_crlf(ep, &ep) < 0)
    {
        return -1;
    }
    *p = '\0';
    return ep - ptr;
}

// content-type = media-type
// media-type   = type "/" subtype parameters
// type         = token
// subtype      = token
int HTTP_parse_media_type(char *ptr, char **endptr, struct media_type *result)
{
    char *ep = ptr;
    // type
    result->type = ep;
    if (scan_token(ep, &ep) < 0)
    {
        return -1;
    }
    // "/"
    if (*ep != '/')
    {
        return -1;
    }
    *ep = '\0';
    ep++;
    // subtype
    result->subtype = ep;
    if (scan_token(ep, &ep) < 0)
    {
        return -1;
    }
    // parameters
    if (HTTP_parse_parameters(ep, &ep, result->parameters) < 0)
    {
        return -1;
    }
    if (*ep != '\0')
    {
        return -1;
    }
    set_endptr(endptr, ep);
    return ep - ptr;
}

// authority-form = uri-host ":" port
int HTTP_parse_authority_form(char *ptr, char **endptr, struct uri *uri)
{
    char *p = ptr, *ep = ptr;
    // IP-literal / IPv4address / reg-name
    if (scan_ip_literal(ep, &ep) < 0 && scan_ipv4_address(ep, &ep) < 0 && scan_reg_name(ep, &ep) < 0)
    {
        return -1;
    }
    uri->host = p;
    // ":" port
    if (*ep == ':')
    {
        *ep = '\0';
        ep++;
        // *DIGIT
        uri->port = strtoi(ep, &ep, 10);
    }
    set_endptr(endptr, ep);
    return ep - ptr;
}

// origin-form    = absolute-path [ "?" query ]
int HTTP_parse_origin_form(char *ptr, char **endptr, struct uri *uri)
{
    char *p = ptr, *ep = ptr;
    // 1*( "/" segment )
    if (scan_path_abempty(ep, &ep) < 1)
    {
        return -1;
    }
    uri->path = p;
    p = ep;
    // [ "?" query ]
    if (scan_query(ep, &ep) >= 0)
    {
        *p = '\0';
        p++;
        uri->query = p;
    }
    set_endptr(endptr, ep);
    return ep - ptr;
}

// request-target = origin-form
//                / absolute-form
//                / authority-form
//                / asterisk-form
// absolute-form  = absolute-URI
// asterisk-form  = "*"
int HTTP_parse_request_target(char *ptr, char **endptr, struct uri *uri, STACK *stack)
{
    char *ep = ptr;
    // origin-form / absolute-form / authority-form
    if (HTTP_parse_origin_form(ep, &ep, uri) < 0 && parse_absolute_URI(ep, &ep, uri, stack) < 0 && HTTP_parse_authority_form(ep, &ep, uri) < 0)
    {
        // "*"
        if (*ep = '*')
        {
            ep++;
            uri->host = "*";
        }
        else
        {
            return -1;
        }
    }
    set_endptr(endptr, ep);
    return ep - ptr;
}

// HTTP-version   = HTTP-name "/" DIGIT "." DIGIT
// HTTP-name      = %x48.54.54.50 ; HTTP
int HTTP_scan_HTTP_version(char *ptr, char **endptr)
{
    char *ep = ptr;
    // %x48.54.54.50 ; HTTP
    if (strncmp(ep, "HTTP", 4) != 0)
    {
        return -1;
    }
    ep += 4;
    // "/"
    if (*ep != '/')
    {
        return -1;
    }
    ep++;
    // DIGIT
    if (!isdigit(*ep))
    {
        return -1;
    }
    ep++;
    // '.'
    if (*ep != '.')
    {
        return -1;
    }
    ep++;
    // DIGIT
    if (!isdigit(*ep))
    {
        return -1;
    }
    ep++;
    set_endptr(endptr, ep);
    return ep - ptr;
}

// request-line   = method SP request-target SP HTTP-version
// method         = token
int HTTP_parse_request_line(char *ptr, char **endptr, struct http_request *req)
{
    char *p, *ep = ptr;
    // method
    p = ep;
    if (scan_token(ep, &ep) < 0)
    {
        return -1;
    }
    // SP
    if (*ep != ' ')
    {
        return -1;
    }
    *ep = '\0';
    req->method = p;
    ep++;
    // request-target
    p = ep;
    if (HTTP_parse_request_target(ep, &ep, req->target, req->stack) < 0)
    {
        return -1;
    }
    // SP
    if (*ep != ' ')
    {
        return -1;
    }
    *ep = '\0';
    ep++;
    // HTTP-version
    p = ep;
    if (HTTP_scan_HTTP_version(ep, &ep) < 0)
    {
        return -1;
    }
    req->version = p;
    set_endptr(endptr, ep);
    return ep - ptr;
}

// status-line    = HTTP-version SP status-code SP [ reason-phrase ]
// status-code    = 3DIGIT
int HTTP_parse_status_line(char *ptr, char **endptr, struct http_response *res)
{
    char *p, *ep = ptr;
    // HTTP-version
    p = ep;
    if (HTTP_scan_HTTP_version(ep, &ep) < 0)
    {
        return -1;
    }
    // SP
    if (*ep != ' ')
    {
        return -1;
    }
    *ep = '\0';
    res->version = p;
    ep++;
    // status-code
    p = ep;
    // 3DIGIT
    if (scann(ep, &ep, 3, L_DIGIT, H_DIGIT) < 3)
    {
        return -1;
    }
    // SP
    if (*ep != ' ')
        return -1;
    *ep = '\0';
    res->code = strtos(p, NULL, 10);
    ep++;
    // [ reason-phrase ]
    p = ep;
    if (scan_token(ep, &ep) >= 0)
    {
        res->reason = p;
    }
    set_endptr(endptr, ep);
    return ep - ptr;
}

// field-line     = field-name ":" OWS field-value OWS
// field-name     = token
// field-value    = *field-content
// field-content  = field-vchar
//                  [ 1*( SP / HTAB / field-vchar ) field-vchar ]
// field-vchar    = VCHAR / obs-text
int HTTP_parse_field_line(char *ptr, char **endptr, struct entry *f)
{
    char *p, *ep = ptr;
    // field-name
    p = ep;
    if (scan_token(ep, &ep) < 0)
    {
        return -1;
    }
    // ":"
    if (*ep != ':')
    {
        return -1;
    }
    *ep = '\0';
    f->key = p;
    ep++;
    // OWS
    scan_ows(ep, &ep); // field-content
    p = ep;
    if (match(*(ep++), L_FIELD_VCHAR, H_FIELD_VCHAR))
    {
        // 1*( SP / HTAB / field-vchar )
        if (scan(ep, &ep, L_FIELD, H_FIELD) > 0)
        {
            // field-vchar
            while (!match(*(ep - 1), L_FIELD_VCHAR, H_FIELD_VCHAR))
            {
                ep--;
            }
        }
        // OWS
        int n = scan_ows(ep, &ep);
        if (n >= 0)
        {
            if (n > 0)
            {
                ep[-n + 1] = '\0';
            }
            f->value = p;
        }
        else
        {
            ep = p;
        }
    }
    set_endptr(endptr, ep);
    return ep - ptr;
}

// chunk-ext      = *( BWS ";" BWS chunk-ext-name
//                     [ BWS "=" BWS chunk-ext-val ] )
// chunk-ext-name = token
// chunk-ext-val  = token / quoted-string
// BWS            = OWS
int HTTP_parse_chunk_ext(char *ptr, char **endptr, MAP *ext)
{
    char *p, *ep = ptr, *k, *v;
    // *
    while (1)
    {
        p = ep;
        // (
        // BWS
        scan_ows(ep, &ep);
        // ";"
        if (*ep != ';')
        {
            ep = p;
            break;
        }
        *p = '\0';
        ep++;
        // BWS
        scan_ows(ep, &ep);
        // chunk-ext-name
        k = ep;
        if (scan_token(ep, &ep) < 0)
        {
            ep = p;
            break;
        }
        p = ep;
        // [
        // BWS
        if (scan_ows(ep, &ep) > 0)
        {
            *p = '\0';
        }
        // "="
        if (*ep != '=')
        {
            MAP_put(ext, k, NULL);
            ep = p;
            continue;
        }
        *p = '\0';
        ep++;
        // BWS
        scan_ows(ep, &ep);
        // chunk-ext-val
        if (scan_token(v = ep, &ep) < 0 && parse_qstring(ep, &ep, &v) < 0)
        {
            MAP_put(ext, k, NULL);
            ep = p;
            break;
        }
        MAP_put(ext, k, v);
    }
    set_endptr(endptr, ep);
    return ep - ptr;
}

// chunk          = chunk-size [ chunk-ext ] CRLF
//                  chunk-data CRLF
// chunk-size     = 1*HEXDIG
int HTTP_parse_chunk_head(char *ptr, char **endptr, struct chunk *chunk)
{
    char *p, *ep = ptr, *k, *v;
    // chunk-size
    p = ep;
    chunk->size = strtoull(ep, &ep, 16);
    if (ep == p)
        return -1;
    // chunk-ext
    HTTP_parse_chunk_ext(ep, &ep, chunk->extension);
    return ep - ptr;
}

// bchars = "'" / "(" / ")" /
//          "+" / "_" / "," / "-" / "." /
//          "/" / ":" / "=" / "?" / SP
static const uint64_t L_BCHARS = L_ALPHANUM | 0x8400fb8100000000; // low_mask("'()+_,-./:? ")
static const uint64_t H_BCHARS = H_ALPHANUM | 0x80000000;         // high_mask("'()+_,-./:? ")

static const uint64_t L_BCHARSNOSPACE = L_BCHARS & ~0x100000000; // low_mask(" ")
static const uint64_t H_BCHARSNOSPACE = H_BCHARS;

// boundary = 0*69<bchars> bcharsnospace
int32_t scan_boundary(char *ptr, char **endptr)
{
    char *ep = ptr;
    // 0*69<bchars>
    scann(ep, &ep, 69, L_BCHARS, H_BCHARS);
    // bcharsnospace
    while (ep > ptr && !match(*(ep - 1), L_BCHARSNOSPACE, H_BCHARSNOSPACE))
    {
        ep--;
    }
    set_endptr(endptr, ep);
    return ep - ptr;
}

int32_t scann_crlf(char *ptr, char **endptr, int32_t n)
{
    char *ep = ptr;
    // Process CRLF
    if (n < 2 || *ep++ != '\r' || *ep++ != '\n')
    {
        return -1;
    }
    set_endptr(endptr, ep);
    return ep - ptr;
}

//                                             ; (  Octal, Decimal.)
// text        =  <any CHAR, including bare    ; => atoms, specials,
//                 CR & bare LF, but NOT       ;  comments and
//                 including CRLF>             ;  quoted-strings are
//                                             ;  NOT recognized.
// CHAR        =  <any ASCII character>        ; (  0-177,  0.-127.)
int32_t scan_text(char *ptr, char **endptr, int32_t *nptr)
{
    int32_t off = 0, n = *nptr, ret;
    while (((uint8_t)ptr[off]) < 128 && scann_crlf(ptr + off, NULL, n - off) < 0 && off < n)
    {
        off++;
    }
    *nptr = n;
    set_endptr(endptr, ptr + off);
    return off;
}

// discard-text = *(*text CRLF) *text
int32_t scan_discard_text(char *ptr, char **endptr, int32_t *nptr)
{
    char *ep = ptr;
    int32_t n = *nptr, ret;
    // *(*text CRLF)
    while (scan_text(ep, &ep, &n) > 0)
    {
        // CRLF
        if ((ret = scann_crlf(ep, &ep, n)) < 0)
        {
            return -1;
        }
        n -= ret;
    }
    scan_text(ep, &ep, &n);
    *nptr = n;
    set_endptr(endptr, ep);
    return ep - ptr;
}

// transport-padding = *LWSP-char
//                     ; Composers MUST NOT generate
//                     ; non-zero length transport
//                     ; padding, but receivers MUST
//                     ; be able to handle padding
//                     ; added by message transports.
int32_t scan_transport_padding(char *ptr, char **endptr, int32_t *nptr)
{
    int32_t ret;
    ret = scann(ptr, endptr, *nptr, L_LWSP_CHAR, H_LWSP_CHAR);
    *nptr -= ret;
    return ret;
}

// dash-boundary = "--" boundary
int32_t scan_dash_boundary(char *ptr, char **endptr, int32_t *nptr, char *boundary)
{
    char *ep = ptr;
    int32_t n = *nptr, ret;
    // "--"
    if ((ret = scann_str(ep, &ep, n, "--")) < 0)
    {
        return -1;
    }
    n -= ret;
    // boundary
    if ((ret = scann_str(ep, &ep, n, boundary)) < 0)
    {
        return -1;
    }
    n -= ret;
    *nptr = n;
    set_endptr(endptr, ep);
    return ep - ptr;
}

// delimiter = CRLF dash-boundary
int32_t scan_delimiter(char *ptr, char **endptr, int32_t *nptr, char *boundary)
{
    char *ep = ptr;
    int32_t n = *nptr, ret;
    // CRLF
    if ((ret = scann_crlf(ep, &ep, n)) < 0)
    {
        return -1;
    }
    n -= ret;
    // dash-boundary
    if (scan_dash_boundary(ep, &ep, &n, boundary) < 0)
    {
        return -1;
    }
    *nptr = n;
    set_endptr(endptr, ep);
    return ep - ptr;
}

// dash-boundary transport-padding CRLF
int32_t scan_first_boundary_line(char *ptr, char **endptr, int32_t *nptr, char *boundary)
{
    char *ep = ptr;
    int32_t n = *nptr, ret;
    // dash-boundary transport-padding CRLF
    if (scan_dash_boundary(ep, &ep, &n, boundary) < 0 || scan_transport_padding(ep, &ep, &n) < 0 || (ret = scann_crlf(ep, &ep, n)) < 0)
    {
        return -1;
    }
    n -= ret;
    *nptr = n;
    set_endptr(endptr, ep);
    return ep - ptr;
}

// multipart-body  = [preamble CRLF]
//                   dash-boundary transport-padding CRLF
//                   body-part *encapsulation
//                   close-delimiter transport-padding
//                   [CRLF epilogue]
// dash-boundary   = "--" boundary
//                   ; boundary taken from the value of
//                   ; boundary parameter of the
//                   ; Content-Type field.
// preamble        = discard-text
// epilogue        = discard-text
// discard-text    = *(*text CRLF) *text
//                   ; May be ignored or discarded.
// body-part       = MIME-part-headers [CRLF *OCTET]
// OCTET           = <any 0-255 octet value>
// encapsulation   = delimiter transport-padding
//                   CRLF body-part
// delimiter       = CRLF dash-boundary
// close-delimiter = delimiter "--"
bool parse_multipart_body(char *ptr, uint64_t n, char *boundary, struct multipart *mp)
{
    bool done = false;
    char c, *p, *ep = ptr, *v;
    struct entry e;
    struct part *part, **parts = NULL, **temp;
    // only the actual body part can exceed INT32_MAX
    int32_t ret, smax = INT32_MAX > n ? n : INT32_MAX, srem = smax;
    uint32_t length = 0;
    uint64_t rem = n;
    // Validate boundary
    if (scan_boundary(boundary, &p) < 0 || *p)
    {
        return false;
    }
    // [preamble CRLF] dash-boundary transport-padding CRLF
    while (scan_first_boundary_line(ep, &ep, &srem, boundary) < 0)
    {
        // *text
        if (scan_text(ep, &ep, &srem) < 0)
        {
            return false;
        }
        // CRLF
        if ((ret = scann_crlf(ep, &ep, srem)) < 0)
        {
            return false;
        }
        srem -= ret;
    }
    rem -= smax - srem;
    // scan each body part
    while (!done)
    {
        part = malloc(sizeof(part));
        part->headers = MAP_new_ignore_case();
        part->content = NULL;
        part->content_length = 0;
        // Temporarily terminate the buffer with a null terminator so that parseln doesn't index out of it
        c = ep[rem - 1];
        ep[rem - 1] = '\0';
        // MIME-part-headers
        while ((ret = HTTP_parseln(ep, (parser_t *)&HTTP_parse_field_line, &e)) >= 0)
        {
            ep += ret;
            rem -= ret;
            if ((v = MAP_get(part->headers, e.key)) != NULL && e.value != NULL)
            {
                // delimit duplicate fields by "," characters
                v = buffcat(v, strlen(v), ", ", 3);
                e.key = buffcat(v, strlen(v), e.value, strlen(e.value) + 1);
                free(v);
                STACK_push(mp->stack, e.key);
            }
            MAP_put(part->headers, e.key, e.value);
        }
        ep[rem - 1] = c;
        srem = smax = INT32_MAX > rem ? rem : INT32_MAX;
        // [CRLF *OCTET] *encapsulation close-delimiter
        if (scan_delimiter(ep, &ep, &srem, boundary) < 0)
        {
            // If the boundary doesn't immediately follow the headers, then there must be a body
            // which must be preceeded by a CRLF
            if ((ret = scann_crlf(ep, &ep, srem)) < 0)
            {
                MAP_free(part->headers);
                free(part);
                if (parts != NULL)
                {
                    free(parts);
                }
                return false;
            }
            srem -= ret;
            p = ep;
            rem -= smax - srem;
            srem = smax = INT32_MAX > rem ? rem : INT32_MAX;
            // Parse every byte until the next delimiter
            while (scan_delimiter(ep, &ep, &srem, boundary) < 0)
            {
                if (rem == 0)
                {
                    MAP_free(part->headers);
                    free(part);
                    if (parts != NULL)
                    {
                        free(parts);
                    }
                    return false;
                }
                ep++;
                rem--;
                srem = smax = INT32_MAX > rem ? rem : INT32_MAX;
            }
            part->content = p;
            part->content_length = ep - p;
        }
        rem -= smax - srem;
        srem = smax = INT32_MAX > rem ? rem : INT32_MAX;
        // Check if the delimiter is a close-delimiter
        if ((ret = scann_str(ep, &ep, srem, "--")) >= 0)
        {
            srem -= ret;
            done = true;
        }
        // transport-padding
        if (scan_transport_padding(ep, &ep, &srem) < 0)
        {
            MAP_free(part->headers);
            free(part);
            if (parts != NULL)
            {
                free(parts);
            }
            return false;
        }
        if (!done)
        {
            // If the delimiter wasn't closing, then there must be a CRLF before the next body-part
            if ((ret = scann_crlf(ep, &ep, srem)) < 0)
            {
                MAP_free(part->headers);
                free(part);
                if (parts != NULL)
                {
                    free(parts);
                }
                return false;
            }
            srem -= ret;
        }
        part->content = p;
        rem -= smax - srem;
        length++;
        // Allocate memory for the new part in the array
        temp = parts;
        parts = malloc(sizeof(struct part *) * length);
        memcpy(parts, temp, sizeof(struct part *) * (length - 1));
        parts[length - 1] = part;
        if (temp != NULL)
        {
            free(temp);
        }
    }
    srem = smax = INT32_MAX > rem ? rem : INT32_MAX;
    // [CRLF epilogue]
    if ((ret = scann_crlf(ep, &ep, srem)) >= 0)
    {
        srem -= ret;
        if (scan_discard_text(ep, &ep, &srem) < 0)
        {
            return false;
        }
        rem -= smax - srem;
    }
    mp->parts = parts;
    mp->length = length;
    STACK_push(mp->stack, parts);
    return rem == 0;
}

/*
 * -----------------
 * |    NETWORK    |
 * -----------------
 */

/// @brief The thread specific buffer
__thread char buffer[BUFFER_SIZE];

/// @brief The index of the next unread character in the buffer
__thread uint16_t buffer_pos = 0;

/// @brief The total size of the data read to the buffer
__thread uint16_t buffer_size = 0;

/// @brief Receives up to N bytes from the socket FD and places them into the buffer.
/// Ensures that data is read from the global buffer if applicable before receiving new data.
/// @param fd The socket file descriptor
/// @param buf The buffer
/// @param n The maximum number of bytes to read
/// @param flags Flags for `recv`
/// @return The number of bytes read
ssize_t recv_r(int fd, void *buf, size_t n, int flags)
{
    uint64_t len = buffer_size - buffer_pos;
    if (len >= n)
    {
        // The size of the data in the buffer is larger than N, so copy N bytes from the buffer
        memcpy(buf, buffer + buffer_pos, n);
        buffer_pos += n;
        return n;
    }
    // Copy the remainder of the buffer
    memcpy(buf, buffer + buffer_pos, len);
    buffer_pos += len;
    // Receive the rest of the data up to N bytes
    ssize_t ret = recv(fd, buf + len, n - len, flags);
    if (ret < 0)
    {
        return ret;
    }
    else
    {
        return ret + len;
    }
}

/// @brief Receives an sequence of characters until a CRLF over a file socket FD.
/// @param fd The socket file descriptor
/// @param ptr Pointer where the result will be placed into
/// @return The size of the line ending in a CRLF
int32_t recvln(int fd, char **ptr)
{
    bool done = false;
    char *temp, *data = *ptr = NULL;
    uint16_t i = buffer_pos, n = buffer_size;
    int32_t size = 0;
    while (!done)
    {
        if (size > MAX_LINE_SIZE)
        {
            // Size is too large, so free the data and return -2
            if (data != NULL)
                free(data);
            return -2;
        }
        if (i >= n)
        {
            // Position is past the end of the buffer, so receive new data
            if ((n = recv(fd, buffer, BUFFER_SIZE, 0)) < 0)
            {
                if (data != NULL)
                {
                    free(data);
                }
                return -1;
            }
            if (n == 0)
            {
                // 0 bytes were read, so return -3 to indicate a closed connection
                if (data != NULL)
                {
                    free(data);
                }
                return -3;
            }
            // Set buffer position and size to correspond the received data
            buffer_pos = i = 0;
            buffer_size = n;
        }
        if (i == 0 && size >= 1 && data[size - 1] == '\r' && buffer[0] == '\n')
        {
            // The last character from the data and first character from the buffer make a CRLF, so mark the loop as done
            done = true;
        }
        // Search for the CRLF in the buffer
        while (!done && i < n - 1)
        {
            char *ptr = buffer + i;
            if (scan_crlf(buffer + i, NULL) >= 0)
            {
                done = true;
            }
            i++;
        }
        i++;
        // Concatenate the buffer to the data
        temp = data;
        data = buffcat(data, size, buffer + buffer_pos, i - buffer_pos);
        if (temp != NULL)
        {
            free(temp);
        }
        // Add read size to data size
        size += i - buffer_pos;
        buffer_pos = i;
    }
    *ptr = data;
    return size;
}

int32_t HTTP_recvln(int fd, parser_t *parser, void *result, uint8_t *flags, STACK *stack, bool allow_empty)
{
    char *ptr;
    int32_t ret = recvln(fd, &ptr);
    if (ret < 0)
    {
        if (ret == -1)
        {
            *flags |= CONNECTION_ERROR;
        }
        else if (ret == -2)
        {
            *flags |= CONTENT_TOO_LARGE;
        }
        else if (ret == -3)
        {
            *flags |= CONNECTION_CLOSED;
        }
        return -1;
    }
    STACK_push(stack, ptr);
    if (ret == 2 && allow_empty)
    {
        return 2;
    }
    ret = HTTP_parseln(ptr, parser, result);
    if (ret < 0)
    {
        *flags |= PARSE_ERROR;
        return -1;
    }
    return ret;
}

bool HTTP_recvln_empty(int fd, uint8_t *flags)
{
    char *ptr;
    int32_t ret = recvln(fd, &ptr);
    if (ret < 0)
    {
        if (ret == -1)
        {
            *flags |= CONNECTION_ERROR;
        }
        else if (ret == -2)
        {
            *flags |= CONTENT_TOO_LARGE;
        }
        else if (ret == -3)
        {
            *flags |= CONNECTION_CLOSED;
        }
        return -1;
    }
    free(ptr);
    return ret == 2;
}

struct http_request *HTTP_recv_chunks(int fd, struct http_request *result)
{
    char *data, *temp, *v;
    uint16_t size = BUFFER_SIZE;
    ssize_t ret;
    uint64_t bytes;
    struct entry e;
    struct chunk chunk;
    chunk.extension = MAP_new();
    if (HTTP_recvln(fd, (parser_t *)&HTTP_parse_chunk_head, &chunk, &result->flags, result->stack, false) < 0)
    {
        MAP_free(chunk.extension);
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
                result->flags |= CONNECTION_ERROR;
                return NULL;
            }
            bytes += ret;
        }
        if (!HTTP_recvln_empty(fd, &result->flags))
        {
            MAP_free(chunk.extension);
            free(chunk.content);
            return NULL;
        }
        temp = result->content;
        result->content = buffcat(result->content, result->content_length, chunk.content, chunk.size);
        free(chunk.content);
        if (temp != NULL)
            free(temp);
        result->content_length += chunk.size;
        MAP_free(chunk.extension); // discard chunk extension
        chunk.extension = MAP_new();
        if (HTTP_recvln(fd, (parser_t *)&HTTP_parse_chunk_head, &chunk, &result->flags, result->stack, false) < 0)
        {
            MAP_free(chunk.extension);
            return NULL;
        }
    }
    STACK_push(result->stack, result->content);
    while (1)
    {
        // field-lines
        if ((ret = HTTP_recvln(fd, (parser_t *)&HTTP_parse_field_line, &e, &result->flags, result->stack, true)) < 0)
        {
            return NULL;
        }
        if (ret == 2)
        {
            break;
        }
        if ((v = MAP_get(result->headers, e.key)) != NULL && e.value != NULL)
        {
            // delimit duplicate headers by ","
            v = buffcat(v, strlen(v), ", ", 3);
            e.value = buffcat(v, strlen(v), e.value, strlen(e.value) + 1);
            free(v);
            STACK_push(result->stack, e.value);
        }
        MAP_put(result->trailers, e.key, e.value);
    }
    return result;
}

ssize_t HTTP_send_response(struct http_response *res, int fd, bool head)
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
    uint8_t *s;
    uint64_t size = HTTP_resmsg_ex(res, head, &s);
    ssize_t written = send(fd, s, size, MSG_NOSIGNAL);
    free(s);
    return written;
}

void HTTP_respond_file(struct http_request *req, char *path, struct http_response *res, int fd)
{
    MAP_put(res->headers, "Accept-Ranges", "bytes");
    MAP_put_if_absent(res->headers, "Cache-Control", "no-cache");
    FILE *fp = fopen(path, "r");
    fseek(fp, 0L, SEEK_END);
    uint64_t size = ftell(fp); /* file size */
    char *rangeh = MAP_get(req->headers, "Range");
    if (rangeh != NULL)
    {
        // Range was specified
        bool bad_range = false;
        char *endptr;
        struct range range;
        RANGE_init(&range);
        struct int_range spec = {0, 0};
        // Parse range
        if (HTTP_parse_range(rangeh, &endptr, &range) < 0 || *endptr != '\0')
        {
            bad_range = true;
        }
        // TODO: Handle multiple ranges
        // Parse specifier
        if (strcmp(range.units, "bytes") != 0 || range.length > 1 || HTTP_parse_int_range(range.set[0], &endptr, size, &spec) < 0 || *endptr != '\0')
        {
            bad_range = true;
        }
        RANGE_free(&range);
        // Validate range
        if (spec.first < 0 || spec.last >= size || spec.first > spec.last)
        {
            bad_range = true;
        }
        if (bad_range)
        {
            res->code = 416; /* Range Not Satisfiable */
            res->reason = HTTP_reason(res->code);
            char *content_range = malloc(numlenul(size) + 9);
            STACK_push(res->stack, content_range);
            *content_range = '\0';
            sprintf(content_range, "bytes */%ld", size);
            MAP_put(res->headers, "Content-Range", content_range);
            HTTP_send_response(res, fd, false);
        }
        else
        {
            res->code = 206; /* Partial Content */
            res->reason = HTTP_reason(res->code);
            /* content-range */
            char *content_range = malloc(numlenul(spec.first) + numlenul(spec.last) + numlenul(size) + 9);
            STACK_push(res->stack, content_range);
            *content_range = '\0';
            sprintf(content_range, "bytes %ld-%ld/%ld", spec.first, spec.last, size);
            MAP_put(res->headers, "Content-Range", content_range);
            /* size */
            size = spec.last - spec.first + 1;
            res->content_length = size;
            HTTP_send_response(res, fd, true);
            if (strcmp(req->method, "HEAD") != 0)
                /* body */
                send_file(fd, fp, spec.first, spec.last);
        }
    }
    else
    {

        res->reason = HTTP_reason(res->code);
        res->content_length = size;
        HTTP_send_response(res, fd, true);
        /* body */
        if (strcmp(req->method, "HEAD") != 0)
            send_file(fd, fp, 0, size - 1);
    }
    fclose(fp);
}

struct http_request *HTTP_recvreq(int fd, struct http_request *result)
{
    char *data = NULL, *temp, *ep, *v;
    int32_t ret;
    struct entry e;
    result->method = NULL;
    result->version = NULL;
    if (HTTP_recvln(fd, (parser_t *)&HTTP_parse_request_line, result, &result->flags, result->stack, false) < 0)
    {
        return NULL;
    }
    while (1)
    {
        // field-lines
        if ((ret = HTTP_recvln(fd, (parser_t *)&HTTP_parse_field_line, &e, &result->flags, result->stack, true)) < 0)
        {
            return NULL;
        }
        if (ret == 2)
        {
            break;
        }
        if ((v = MAP_get(result->headers, e.key)) != NULL && e.value != NULL)
        {
            // delimit duplicate headers by ","
            v = buffcat(v, strlen(v), ", ", 3);
            e.value = buffcat(v, strlen(v), e.value, strlen(e.value) + 1);
            free(v);
            STACK_push(result->stack, e.value);
        }
        MAP_put(result->headers, e.key, e.value);
    }
    // message body
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
                HTTP_recv_chunks(fd, result);
    }
    else if (MAP_contains_key(result->headers, "Content-Length"))
    {
        char *ptr, *endptr;
        uint64_t content_length = strtoull(ptr = MAP_get(result->headers, "Content-Length"), &endptr, 10);
        if (*ptr == '\0' || *endptr != '\0')
        {
            result->flags |= BAD_CONTENT_LENGTH;
            return NULL;
        }
        if (content_length > 0x200000000) // 8 GB limit
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
        uint16_t size = BUFFER_SIZE;
        uint64_t bytes = 0;
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
