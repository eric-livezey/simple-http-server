#include "hashmap.h"

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

unsigned long *parse_range(char *ptr, unsigned long size, unsigned long *result);

int HTTP_request_free(HTTP_request *req);

int HTTP_response_free(HTTP_response *res);

char *HTTP_date_ex(struct tm *tm, char *result);

char *HTTP_date(struct tm *tm);

char *HTTP_reason(unsigned short code);

char *HTTP_content_type(char *ext);

long HTTP_reqsize(HTTP_request *req);

char *HTTP_reqmsg_ex(HTTP_request *req, char *buffer);

long HTTP_ressize(HTTP_response *res, char head);

char *HTTP_resmsg_ex(HTTP_response *res, char head, char *result);

void HTTP_print_request(HTTP_request *req);

void HTTP_print_response(HTTP_response *res);

char *qstring(char *ptr, char **endptr);

MAP *parse_query(char *ptr, char **endptr, MAP *result);

struct content_type *parse_content_type(char *ptr, struct content_type *result);

struct HTTP_request *HTTP_parse_reqln(char *ptr, struct HTTP_request *result);

struct HTTP_response *HTTP_parse_statusln(char *ptr, struct HTTP_response *result);

struct entry *HTTP_parse_fieldln(char *ptr, struct entry *result);

struct chunk *HTTP_parse_chunk_size(char *ptr, struct chunk *result);

struct multipart *parse_multipart(char *content, unsigned long content_length, char *boundary, struct multipart *result);

long recv_line(int fd, char **ptr);

struct HTTP_request *recv_chunks(int fd, struct HTTP_request *result);

long HTTP_send_response(HTTP_response *res, int connfd, char head);

void HTTP_respond_file(HTTP_request *req, char *path, HTTP_response *res, int fd);

HTTP_request *HTTP_readreq_ex(int fd, HTTP_request *result);