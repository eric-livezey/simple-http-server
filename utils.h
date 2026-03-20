#ifndef _UTILS_H
#define _UTILS_H

#include <stdbool.h>
#include <stdint.h>
#include <bits/types/FILE.h>
#include <sys/types.h>
#include "types.h"

typedef struct buffer_s BUFFER;

BUFFER *BUFFER_new(size_t capacity);

size_t BUFFER_size(BUFFER *b);

size_t BUFFER_push(BUFFER *b, uint8_t *data, size_t n);

bool BUFFER_pushb(BUFFER *b, uint8_t byte);

size_t BUFFER_sprint(BUFFER *b, char *str);

int32_t BUFFER_sprintf(BUFFER *b, char *format, ...);

size_t BUFFER_pop(BUFFER *b, size_t n, uint8_t *result);

uint8_t *BUFFER_get(BUFFER *b);

size_t BUFFER_get_ex(BUFFER *b, uint8_t **result);

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

char *strnalloc(const char *src, size_t n, MEM_STACK *stack);

long double gettime();

/// @brief Sends a file over a socket.
/// @param fd The socket file descriptor
/// @param fp The file pointer
/// @param offset The offset
/// @param n The number of bytes to send
/// @return The number if bytes sent
ssize_t send_file(int32_t fd, FILE *fp, int64_t offset, int64_t n);

uint8_t *buffcat(uint8_t *buff1, size_t n1, uint8_t *buff2, size_t n2);

void urldecode(char *dst, char *src);

unsigned short strtous(char *nptr, char **endptr, int base);

int strindexof(char *ptr, char c);

int strlastindexof(char *ptr, char c);

int numlenul(unsigned long x);

#endif
