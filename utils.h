#include <stdlib.h>
#include <stdio.h>
#include <ctype.h>
#include <time.h>
#include <netinet/in.h>

typedef struct node *STACK;

STACK *STACK_new();

void *STACK_pop(STACK *sp);

void STACK_push(STACK *stack, void *ptr);

char STACK_empty(STACK *sp);

void STACK_free(STACK *stack);

long double gettime();

char send_file(int fd, FILE *fp, unsigned long begin, unsigned long end);

char *buffcat(char *buff1, unsigned long n1, char *buff2, unsigned long n2);

void urldecode(char *dst, const char *src);

unsigned short strtous(char *nptr, char **endptr, int base);

int strindexof(char *ptr, char c);

int strlastindexof(char *ptr, char c);

int numlenul(unsigned long x);

int log2floor(int x);

int log2ceil(int x);