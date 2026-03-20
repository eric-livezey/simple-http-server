#ifndef _TYPES_UTILS_H
#define _TYPES_UTILS_H

#include <bits/stdint-uintn.h>
#include <bits/stdint-intn.h>

uint32_t max(uint32_t a, uint32_t b);
uint32_t min(uint32_t a, uint32_t b);
uint32_t log2floor(uint32_t x);
uint32_t log2ceil(uint32_t x);
uint32_t strhash(const char *s);
uint32_t strcasehash(const char *s);
uint32_t strhash_p(const void *ptr);
int32_t strcmp_p(const void *a, const void *b);
uint32_t strcasehash_p(const void *ptr);
int32_t strcasecmp_p(const void *a, const void *b);

#endif
