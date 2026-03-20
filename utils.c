#include <stdlib.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdarg.h>
#include <stdint.h>
#include <ctype.h>
#include <time.h>
#include <netinet/in.h>
#include <string.h>
#include "types.h"

typedef struct buffer_s
{
    uint8_t *data;
    size_t size;
    size_t capacity;
} BUFFER;

/// @brief Initializes a buffer.
/// @param sb The buffer
/// @param capacity The capacity
void BUFFER_init(BUFFER *b, size_t capacity)
{
    *b = (BUFFER){.data = malloc(capacity), .size = 0, .capacity = capacity};
}

/// @brief Creates a new buffer.
/// @param capacity The capacity
/// @return The new buffer
BUFFER *BUFFER_new(size_t capacity)
{
    BUFFER *b = malloc(sizeof(BUFFER));
    BUFFER_init(b, capacity);
    return b;
}

/// @brief Creates a new buffer from an existing pointer.
/// @param data The pointer
/// @param size The size of the data
/// @param capacity The capacity
/// @return The new buffer
BUFFER *BUFFER_from_r(void *data, size_t size, size_t capacity)
{
    BUFFER *b = malloc(sizeof(BUFFER));
    *b = (BUFFER){.data = data, size = size, capacity = capacity};
    return b;
}

/// @brief Creates a new buffer from an existing pointer.
/// @param data The pointer
/// @param size The size of the data
/// @return The new buffer
BUFFER *BUFFER_from(void *data, size_t size)
{
    return BUFFER_from_r(data, size, size);
}

/// @brief Returns the size of the buffer.
/// @param b The buffer
/// @return The size of the buffer
size_t BUFFER_size(BUFFER *b)
{
    return b->size;
}

/// @brief Pushes up to N bytes data to the end of the buffer.
/// @param b The buffer
/// @param data The data
/// @param n The number of bytes to copy
/// @return The number of bytes pushed
size_t BUFFER_push(BUFFER *b, uint8_t *data, size_t n)
{
    size_t p = 0;
    while (p < n && b->size < b->capacity)
    {
        b->data[b->size++] = data[p++];
    }
    return p;
}

/// @brief Pushes a single byte to the buffer.
/// @param b The buffer
/// @param byte The byte
/// @return `true` if the byte was pushed, else `false`
bool BUFFER_pushb(BUFFER *b, uint8_t byte)
{
    bool p = false;
    if (p = b->size < b->capacity)
    {
        b->data[b->size++] = byte;
    }
    return p;
}

/// @brief Pushes characters in the given string to the buffer.
/// @param b The buffer
/// @param str The string to push
/// @return The number of characters pushed
size_t BUFFER_sprint(BUFFER *b, char *s)
{
    char *ptr = s;
    while (*ptr && b->size < b->capacity)
    {
        b->data[b->size++] = *ptr++;
    }
    return ptr - s;
}

/// @brief Write formatted output to the buffer.
/// @param b The buffer
/// @param format The format string
/// @return The number of characters written
int32_t BUFFER_sprintf(BUFFER *b, char *format, ...)
{
    va_list args;
    va_start(args, format);
    int32_t size = vsnprintf(b->data + b->size, b->capacity - b->size, format, args);
    b->size += size;
    va_end(args);
    return size;
}

/// @brief Pops up to N bytes from the buffer and places them into result.
/// @param n The number of bytes to pop
/// @return The numbers of bytes popped
size_t BUFFER_pop(BUFFER *b, size_t n, uint8_t *result)
{
    size_t p = n;
    while (p > 0 && b->size > 0)
    {
        result[n - p--] = b->data[n - b->size--];
    }
    return n - p;
}

/// @brief Returns the buffer content and frees the struct.
/// @param b The buffer
/// @return The buffer content
uint8_t *BUFFER_get(BUFFER *b)
{
    uint8_t *data = b->data;
    free(b);
    return data;
}

/// @brief Places the buffer content in the result and frees the struct.
/// @param b The buffer
/// @return The size of the buffer
size_t BUFFER_get_ex(BUFFER *b, uint8_t **result)
{
    uint64_t size = b->size;
    *result = BUFFER_get(b);
    return size;
}

int strtoi(char *ptr, char **endptr, int base)
{
    return strtol(ptr, endptr, base);
}

unsigned int strtoui(char *ptr, char **endptr, int base)
{
    return strtoul(ptr, endptr, base);
}

short strtos(char *ptr, char **endptr, int base)
{
    return strtoi(ptr, endptr, base);
}

unsigned short strtous(char *ptr, char **endptr, int base)
{
    return strtoui(ptr, endptr, base);
}

/// @brief Generates a low mask for the given characters.
/// @param chars A null terminated list of characters
/// @return The mask
uint64_t low_mask(char *chars)
{
    char *ptr = chars;
    uint64_t mask = 0;
    while (*ptr)
    {
        unsigned char c = *ptr;
        if (c < 64)
        {
            mask |= UINT64_C(1) << c;
        }
        ptr++;
    }
    return mask;
}

/// @brief Generates a high mask for the given characters.
/// @param chars A null terminated list of characters
/// @return The mask
uint64_t high_mask(char *chars)
{
    char *ptr = chars;
    uint64_t mask = 0;
    while (*ptr)
    {
        unsigned char c = *ptr;
        if (c >= 64 && c < 128)
        {
            mask |= UINT64_C(1) << (c - 64);
        }
        ptr++;
    }
    return mask;
}

// Helper to avoid writing this case and end of every scan/parse function
void set_endptr(char **endptr, char *ep)
{
    if (endptr != NULL)
    {
        *endptr = ep;
    }
}

// The zero'th bit is used to indicate that non-US-ASCII characters are allowed
#define L_NON_ASCII UINT64_C(0x1)
#define H_NON_ASCII UINT64_C(0x0)

typedef int32_t(scanfn_t)(char *, char **);

/// @brief Tells whether the given character is permitted by the given mask pair.
/// @param c The character
/// @param low_mask Low mask
/// @param high_mask High mask
/// @return `true` if the character is permitted, else `false`
bool match(uint8_t c, uint64_t low_mask, uint64_t high_mask)
{
    if (c == 0)
        return false;
    if (c < 64)
        return ((UINT64_C(1) << c) & low_mask) != 0;
    if (c < 128)
        return ((UINT64_C(1) << (c - 64)) & high_mask) != 0;
    return low_mask & L_NON_ASCII == 0;
}

/// @brief Scans all characters after the pointer that match the given mask.
/// @param ptr Pointer
/// @param endptr Optional end pointer
/// @param low_mask Low mask
/// @param high_mask High mask
/// @return The length of the partition of characters the pointer which matches the mask
uint32_t scan(char *ptr, char **endptr, uint64_t low_mask, uint64_t high_mask)
{
    char *ep = ptr;
    while (*ep)
    {
        uint8_t c = *ep;
        if (match(c, low_mask, high_mask))
        {
            ep++;
        }
        else
        {
            break;
        }
    }
    set_endptr(endptr, ep);
    return ep - ptr;
}

/// @brief Scans up to `n` characters after the pointer which match the given mask.
/// @param ptr Pointer
/// @param endptr Optional end pointer
/// @param n Maximum length
/// @param low_mask Low mask
/// @param high_mask High mask
/// @return The length of the partition of characters after `start` which matches the mask
uint32_t scann(char *ptr, char **endptr, uint32_t n, uint64_t low_mask, uint64_t high_mask)
{
    uint32_t off = 0;
    while (ptr[off] && off < n)
    {
        uint8_t c = ptr[off];
        if (match(c, low_mask, high_mask))
        {
            off++;
        }
        else
        {
            break;
        }
    }
    set_endptr(endptr, ptr + off);
    return off;
}

/// @brief Scans all characters after the pointer that match the given mask.
/// @param ptr Pointer
/// @param endptr Optional end pointe
/// @param scanner Function to scan an escape sequence
/// @param low_mask Low mask
/// @param high_mask High mask
/// @return The length of the partition of characters the pointer which matches the mask
uint32_t scan_r(char *ptr, char **endptr, scanfn_t *scanfn, uint64_t low_mask, uint64_t high_mask)
{
    char *ep = ptr;
    while (*ep)
    {
        uint8_t c = *ep;
        if (match(c, low_mask, high_mask))
        {
            ep++;
        }
        else if (scanfn(ep, &ep) < 1)
        {
            break;
        }
    }
    set_endptr(endptr, ep);
    return ep - ptr;
}

/// @brief Scans up to `n` characters after the pointer which match the given mask.
/// @param ptr Pointer
/// @param endptr Optional end pointer
/// @param n Maximum length
/// @param scanner Function to scan an escape sequence
/// @param low_mask Low mask
/// @param high_mask High mask
/// @return The length of the partition of characters after `start` which matches the mask
uint32_t scann_r(char *ptr, char **endptr, uint32_t n, scanfn_t *scanfn, uint64_t low_mask, uint64_t high_mask)
{
    uint32_t off = 0;
    while (ptr[off] && off < n)
    {
        uint8_t c = ptr[off];
        if (match(c, low_mask, high_mask))
        {
            off++;
        }
        else
        {
            int32_t q = scanfn(ptr + off, NULL);
            if (q < 1)
            {
                break;
            }
            else if (off + q < n)
            {
                off += q;
            }
            break;
        }
    }
    set_endptr(endptr, ptr + off);
    return off;
}

int32_t scan_str(char *ptr, char **endptr, char *str)
{
    char *ep = ptr, *sp = str;
    while (*sp)
    {
        if (*ep++ != *sp++)
        {
            return -1;
        }
    }
    set_endptr(endptr, ep);
    return ep - ptr;
}

int32_t scann_str(char *ptr, char **endptr, int32_t n, char *str)
{
    int32_t off = 0;
    while (str[off] && off < n)
    {
        if (ptr[off] != str[off])
        {
            return -1;
        }
        off++;
    }
    set_endptr(endptr, ptr + off);
    return off;
}

/// @brief Copies N characters of src to a new block of memory and pushes it to the stack.
/// @param src The source string
/// @param n Number of characters to copy
/// @return The newly allocated string
char *strnalloc(const char *src, size_t n, MEM_STACK *stack)
{
    char *result;
    if (n > 0)
    {
        result = malloc(n + 1);
        MEM_STACK_push(stack, result);
        strncpy(result, src, n);
        result[n] = '\0';
    }
    else
    {
        result = "";
    }
    return result;
}

long double gettime()
{
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (ts.tv_sec + ts.tv_nsec / 1000000000.0L) * 1000.0L;
}

#define BUFFER_SIZE UINT16_MAX

/// @brief Sends a file over a socket
/// @param fd The socket file descriptor
/// @param fp The file pointer
/// @param offset The offset
/// @param n The number of bytes to send
/// @return The number if bytes sent
ssize_t send_file(int32_t fd, FILE *fp, int64_t offset, int64_t n)
{
    if (offset < 0 || n < 0)
        return -1;
    if (n == 0)
        return 0;
    int32_t nread, nsent;
    ssize_t total = 0;
    fseek(fp, offset, SEEK_SET);
    if (ftell(fp) < offset)
        // The file is smaller than the offset, so send 0 bytes
        return 0;
    uint8_t *buffer = malloc(BUFFER_SIZE);
    do
    {
        nread = fread(buffer, 1, BUFFER_SIZE, fp);
        if (nread < 0)
        {
            // Error while reading, so exit
            free(buffer);
            return -1;
        }
        if (nread == 0)
            // 0 bytes were read, so break
            break;
        nsent = send(fd, buffer, nread, MSG_NOSIGNAL);
        if (nsent < 0)
        {
            // Error while sending, so exit
            free(buffer);
            return -1;
        }
        if (nsent < nread)
            // Less bytes were sent than read, so seek to the last byte sent
            fseek(fp, nread - nsent, SEEK_CUR);
        total += nsent;
    } while (total < n && nread == BUFFER_SIZE);
    free(buffer);
    return total;
}

uint8_t *buffcat(uint8_t *buff1, size_t n1, uint8_t *buff2, size_t n2)
{
    uint8_t *buff = malloc(n1 + n2);
    memcpy(buff, buff1, n1);
    memcpy(buff + n1, buff2, n2);
    return buff;
}

void urldecode(char *dst, char *src)
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

int strlastindexof(char *ptr, char c)
{
    int index = -1, i = 0;
    while (ptr[i] != '\0')
    {
        if (ptr[i] == c)
        {
            index = i;
        }
        i++;
    }
    return index;
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
