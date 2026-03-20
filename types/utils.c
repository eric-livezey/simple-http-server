#include <stdint.h>
#include <ctype.h>
#include <string.h>
#include <strings.h>

uint32_t max(uint32_t a, uint32_t b)
{
    return a > b ? a : b;
}

uint32_t min(uint32_t a, uint32_t b)
{
    return a < b ? a : b;
}

uint32_t log2floor(uint32_t x)
{
    uint32_t result = 0;
    while (x >= 2)
    {
        x >>= 1;
        result++;
    }
    return result;
}

uint32_t log2ceil(uint32_t x)
{
    return log2floor(x - 1) + 1;
}

uint32_t strhash(const char *s)
{
    uint32_t h = 0;
    while (*s != '\0')
        h = 31 * h + *s++;
    return h;
}

uint32_t strcasehash(const char *s)
{
    uint32_t h = 0;
    for (uint32_t i = 0; s[i] != '\0'; i++)
        h = 31 * h + tolower(s[i]);
    return h;
}

uint32_t strhash_p(const void *ptr)
{
    return strhash(*(char **)ptr);
}

int32_t strcmp_p(const void *a, const void *b)
{
    return strcmp(*(char **)a, *(char **)b);
}

uint32_t strcasehash_p(const void *ptr)
{
    return strcasehash(*(char **)ptr);
}

int32_t strcasecmp_p(const void *a, const void *b)
{
    return strcasecmp(*(char **)a, *(char **)b);
}