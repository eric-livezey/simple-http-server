#include <stdlib.h>
#include <stdio.h>
#include <ctype.h>
#include <time.h>
#include <netinet/in.h>

struct node
{
    void *ptr;
    struct node *prev;
};

typedef struct node *STACK;

void node_init(struct node *n, void *ptr, struct node *prev)
{
    n->ptr = ptr;
    n->prev = prev;
}

STACK *STACK_new()
{
    STACK *sp = malloc(sizeof(STACK *));
    *sp = NULL;
    return sp;
}

void *STACK_pop(STACK *sp)
{
    struct node *node = *sp;
    *sp = node->prev;
    void *ptr = node->ptr;
    free(node);
    return ptr;
}

void STACK_push(STACK *sp, void *ptr)
{
    struct node *prev = *sp;
    node_init(*sp = malloc(sizeof(struct node *)), ptr, prev);
}

char STACK_empty(STACK *sp)
{
    return *sp == NULL;
}

void STACK_free(STACK *sp)
{
    struct node *temp, *node = *sp;
    while (node != NULL)
    {
        free(node->ptr);
        temp = node->prev;
        free(node);
        node = temp;
    }
    free(sp);
}

long double gettime()
{
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (ts.tv_sec + ts.tv_nsec / 1000000000.0L) * 1000.0L;
}

char send_file(int fd, FILE *fp, unsigned long begin, unsigned long end)
{
    if (begin < 0 || end < begin)
        return 0;
    char buffer[65535];
    unsigned short nread, written;
    unsigned long sent = 0, size = end - begin + 1;
    fseek(fp, begin, SEEK_SET);
    while (sent < size)
    {
        nread = fread(buffer, 1, sizeof(buffer), fp);
        written = send(fd, buffer, nread, MSG_NOSIGNAL);
        if (written < 0)
            return 0;
        if (written < nread)
            fseek(fp, nread - written, SEEK_CUR);
        sent += written;
        fflush(fp);
    }
    return 1;
}

char *buffcat(char *buff1, unsigned long n1, char *buff2, unsigned long n2)
{
    char *buff = malloc(n1 + n2);
    unsigned int i;
    for (i = 0; i < n1; i++)
        buff[i] = buff1[i];
    for (i = 0; i < n2; i++)
        buff[i + n1] = buff2[i];
    return buff;
}

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

unsigned short strtous(char *nptr, char **endptr, int base)
{
    return strtoul(nptr, endptr, base);
}

int strindexof(char *ptr, char c)
{
    int i = 0;
    while (ptr[i] != '\0')
    {
        if (ptr[i] == c)
        {
            return i;
        }
        i++;
    }
    return -1;
}

int numlenul(unsigned long x)
{
    int i = 1;
    while (x >= 10UL)
    {
        x /= 10UL;
        i++;
    }
    return i;
}

int log2floor(int x)
{
    int log = 0;
    if (x <= 0) // invalid logarithm
        return -1;
    while (x >= 2)
    {
        x >>= 1;
        log++;
    }
    return log;
}

int log2ceil(int x)
{
    int log = 0;
    if (x <= 0) // invalid logarithm
        return -1;
    x <<= 1;
    x--;
    while (x >= 2)
    {
        x >>= 1;
        log++;
    }
    return log;
}