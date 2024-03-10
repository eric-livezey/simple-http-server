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

int HTTP_request_destroy(HTTP_request_t *request);

int HTTP_response_destroy(HTTP_response_t *response);

char *HTTP_reason(unsigned short code);

char *HTTP_date_r(struct tm *tm, char *result);

char *HTTP_date(struct tm *tm);

HTTP_request_t *HTTP_parserequest(char *data, HTTP_request_t *result);

long HTTP_ressize(HTTP_response_t *res);

char *HTTP_resmsg(HTTP_response_t *res, char *result);

int HTTP_response(int fd, HTTP_response_t *res);