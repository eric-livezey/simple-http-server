#include "hashmap.h"
#include "uri.h"

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
    short flags;
};

struct http_response
{
    char *version;
    short code;
    char *reason;
    MAP *headers;
    char *file;
    char *content;
    uint64_t content_length;
    MAP *trailers;
    STACK *stack;
};

void HTTP_request_init(struct http_request *req);

void HTTP_response_init(struct http_response *res);

void HTTP_request_free(struct http_request *req);

void HTTP_response_free(struct http_response *res);

char *HTTP_date_ex(struct tm *tm, char *result);

char *HTTP_date(struct tm *tm);

char *HTTP_reason(uint16_t code);

char *HTTP_content_type(char *ext);

uint64_t HTTP_reqsize(struct http_request *req, bool head);

uint64_t HTTP_push_request(BUFFER *b, struct http_request *req, bool head);

uint64_t HTTP_reqmsg_ex(struct http_request *req, bool head, uint8_t **result);

uint8_t *HTTP_reqmsg(struct http_request *req, bool head);

void HTTP_print_request(struct http_request *req);

uint64_t HTTP_ressize(struct http_response *req, bool head);

uint64_t HTTP_push_response(BUFFER *b, struct http_response *res, bool head);

uint64_t HTTP_resmsg_ex(struct http_response *res, bool head, uint8_t **result);

uint8_t *HTTP_resmsg(struct http_response *res, bool head);

void HTTP_print_response(struct http_response *res);

int parse_qstring(char *ptr, char **endptr, char **s);

int HTTP_parse_range(char *ptr, char **endptr, struct range *r);

int HTTP_parse_media_type(char *ptr, char **endptr, struct media_type *result);

int HTTP_parse_request_line(char *ptr, char **endptr, struct http_request *req);

int HTTP_parse_status_line(char *ptr, char **endptr, struct http_response *res);

int HTTP_parse_field_line(char *ptr, char **endptr, struct entry *result);

int HTTP_parse_chunk_head(char *ptr, char **endptr, struct chunk *result);

bool parse_multipart_body(char *ptr, uint64_t n, char *boundary, struct multipart *mp);

long recvln(int fd, char **ptr);

struct http_request *HTTP_recv_chunks(int fd, struct http_request *result);

long HTTP_send_response(struct http_response *res, int fd, bool head);

void HTTP_respond_file(struct http_request *req, char *path, struct http_response *res, int fd);

struct http_request *HTTP_recvreq(int fd, struct http_request *result);