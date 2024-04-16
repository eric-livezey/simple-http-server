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

void urldecode(char *dst, const char *src);

int HTTP_request_free(HTTP_request *request);

int HTTP_response_free(HTTP_response *response);

char *HTTP_date_ex(struct tm *tm, char *result);

char *HTTP_date(struct tm *tm);

char *HTTP_reason(unsigned short code);

HTTP_request *HTTP_parserequest(char *data, HTTP_request *result);

long HTTP_reqsize(HTTP_request *req);

char *HTTP_reqmsg(HTTP_request *req, char *result);

long HTTP_ressize(HTTP_response *res);

char *HTTP_resmsg(HTTP_response *res, char *result);

long HTTP_send_response(HTTP_response *res, int connfd);
