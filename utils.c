#include <stdlib.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdarg.h>
#include <stdint.h>
#include <ctype.h>
#include <time.h>
#include <netinet/in.h>
#include <string.h>

typedef struct node_s
{
    void *data;
    struct node_s *prev;
} NODE;

/// @brief Represents a stack.
typedef struct stack_s
{
    NODE *head;
    int size;
} STACK;

NODE *NODE_new(void *data, NODE *prev)
{
    NODE *node = malloc(sizeof(NODE));
    node->data = data;
    node->prev = prev;
    return node;
}

NODE *NODE_free(NODE *n)
{
    free(n->data);
    NODE *prev = n->prev;
    free(n);
    return prev;
}

/// @brief Initializes an empty stack.
/// @param s The stack
void STACK_init(STACK *s)
{
    s->head = NULL;
    s->size = 0;
}

/// @brief Constructs an empty stack.
/// @return The stack
STACK *STACK_new()
{
    STACK *s = malloc(sizeof(STACK));
    STACK_init(s);
    return s;
}

/// @brief Pops an item from from the stack and returns it.
/// @param s The stack
/// @return The data
void *STACK_pop(STACK *s)
{
    NODE *node = s->head;
    s->head = node->prev;
    void *data = node->data;
    free(node);
    s->size--;
    return data;
}

/// @brief Pushes an item onto the stack.
/// @param s The stack
/// @param data The data
void STACK_push(STACK *s, void *data)
{
    s->head = NODE_new(data, s->head);
    s->size++;
}

/// @brief Returns the size of the stack.
/// @param s The stack
/// @return The size of the stack
int STACK_size(STACK *s)
{
    return s->size;
}

/// @brief Returns whether or not the stack is empty.
/// @param s The stack
/// @return `true` if the stack is empty, else `false`
bool STACK_empty(STACK *s)
{
    return s->head == NULL;
}

/// @brief Sequentially frees all memory in the stack. Assumes all data is allocated memory and frees it.
/// @param s The stack
void STACK_free(STACK *s)
{
    NODE *node = s->head;
    while (node != NULL)
    {
        node = NODE_free(node);
    }
    free(s);
}

typedef struct buffer_s
{
    uint8_t *data;
    uint64_t size;
    uint64_t capacity;
} BUFFER;

/// @brief Initializes a buffer.
/// @param sb The buffer
/// @param capacity The initial capacity
void BUFFER_init(BUFFER *b, uint64_t capacity)
{
    b->data = malloc(capacity);
    b->size = 0;
    b->capacity = capacity;
}

/// @brief Creates a new buffer.
/// @param capacity The length
/// @return The new buffer
BUFFER *BUFFER_new(uint64_t capacity)
{
    BUFFER *b = malloc(sizeof(BUFFER));
    BUFFER_init(b, capacity);
    return b;
}

/// @brief Returns the size of the buffer.
/// @param b The buffer
/// @return The size of the buffer
uint64_t BUFFER_size(BUFFER *b)
{
    return b->size;
}

/// @brief Pushes up to N bytes data to the end of the buffer.
/// @param b The buffer
/// @param data The data
/// @param n The number of bytes to copy
/// @return The number of bytes pushed
uint64_t BUFFER_push(BUFFER *b, uint8_t *data, uint64_t n)
{
    uint64_t p = 0;
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
uint64_t BUFFER_sprint(BUFFER *b, char *s)
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
int BUFFER_sprintf(BUFFER *b, char *format, ...)
{
    va_list args;
    va_start(args, format);
    int size = vsnprintf(b->data + b->size, b->capacity - b->size, format, args);
    b->size += size;
    va_end(args);
    return size;
}

/// @brief Pops up to N bytes from the buffer and places them into result.
/// @param n The number of bytes to pop
/// @return The numbers of bytes popped
uint64_t BUFFER_pop(BUFFER *b, uint64_t n, uint8_t *result)
{
    uint64_t p = n;
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
uint64_t BUFFER_get_ex(BUFFER *b, uint8_t **result)
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
char *strnalloc(char *src, size_t n, STACK *stack)
{
    char *result;
    if (n > 0)
    {
        result = malloc(n + 1);
        STACK_push(stack, result);
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

bool send_file(int fd, FILE *fp, unsigned long begin, unsigned long end)
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
            return false;
        if (written < nread)
            fseek(fp, nread - written, SEEK_CUR);
        sent += written;
        fflush(fp);
    }
    return true;
}

uint8_t *buffcat(uint8_t *buff1, unsigned long n1, uint8_t *buff2, unsigned long n2)
{
    uint8_t *buff = malloc(n1 + n2);
    unsigned int i;
    for (i = 0; i < n1; i++)
        buff[i] = buff1[i];
    for (i = 0; i < n2; i++)
        buff[i + n1] = buff2[i];
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
