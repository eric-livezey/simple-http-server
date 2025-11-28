#include <stdbool.h>
#include <stdint.h>
#include <bits/types/FILE.h>

typedef struct stack_s STACK;

void STACK_init(STACK *s);

STACK *STACK_new();

void *STACK_pop(STACK *s);

void STACK_push(STACK *s, void *data);

uint32_t STACK_size(STACK *s);

bool STACK_empty(STACK *s);

void STACK_free(STACK *s);

typedef struct buffer_s BUFFER;

BUFFER *BUFFER_new(uint64_t capacity);

uint64_t BUFFER_size(BUFFER *b);

uint64_t BUFFER_push(BUFFER *b, uint8_t *data, uint64_t n);

bool BUFFER_pushb(BUFFER *b, uint8_t byte);

uint32_t BUFFER_sprint(BUFFER *b, char *str);

int BUFFER_sprintf(BUFFER *b, char *format, ...);

uint64_t BUFFER_pop(BUFFER *b, uint64_t n, uint8_t *result);

uint8_t *BUFFER_get(BUFFER *b);

uint64_t BUFFER_get_ex(BUFFER *b, uint8_t **result);

int strtoi(char *ptr, char **endptr, int base);

unsigned int strtoui(char *ptr, char **endptr, int base);

short strtos(char *ptr, char **endptr, int base);

unsigned short strtous(char *ptr, char **endptr, int base);

uint64_t low_mask(char *chars);

uint64_t high_mask(char *chars);

#define L_NON_ASCII UINT64_C(0x1)
#define H_NON_ASCII UINT64_C(0x0)

typedef int32_t(scanfn_t)(char *, char **);

bool match(uint8_t c, uint64_t low_mask, uint64_t high_mask);

void set_endptr(char **endptr, char *ep);

int32_t scan(char *ptr, char **endptr, uint64_t low_mask, uint64_t high_mask);

int32_t scann(char *ptr, char **endptr, uint32_t n, uint64_t low_mask, uint64_t high_mask);

int32_t scan_r(char *ptr, char **endptr, scanfn_t *scanfn, uint64_t low_mask, uint64_t high_mask);

int32_t scann_r(char *ptr, char **endptr, uint32_t n, scanfn_t *scanfn, uint64_t low_mask, uint64_t high_mask);

int32_t scan_str(char *ptr, char **endptr, char *str);

int32_t scann_str(char *ptr, char **endptr, int32_t n, char *str);

char *strnalloc(char *src, size_t n, STACK *stack);

long double gettime();

char send_file(int fd, FILE *fp, unsigned long begin, unsigned long end);

uint8_t *buffcat(uint8_t *buff1, unsigned long n1, uint8_t *buff2, unsigned long n2);

void urldecode(char *dst, char *src);

unsigned short strtous(char *nptr, char **endptr, int base);

int strindexof(char *ptr, char c);

int strlastindexof(char *ptr, char c);

int numlenul(unsigned long x);

int log2floor(int x);

int log2ceil(int x);
