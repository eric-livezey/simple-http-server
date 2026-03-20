#include <stdlib.h>
#include <stdbool.h>
#include <stdint.h>
#include <string.h>

#define NODE_NEXT_TYPE NODE *
#define NODE_NEXT_SIZE sizeof(NODE_NEXT_TYPE)
#define NODE_NEXT(n) *(NODE_NEXT_TYPE *)(n)
#define NODE_VALUE_OFFSET NODE_NEXT_SIZE
#define NODE_VALUE_PTR(n) ((n) + NODE_VALUE_OFFSET)
#define NODE_SIZE(ds) (NODE_NEXT_SIZE + ds)

typedef void NODE;

// Initializes a new node.
static NODE *NODE_init(NODE *n, size_t data_size, const void *value, NODE_NEXT_TYPE next)
{
    memcpy(NODE_VALUE_PTR(n), value, data_size);
    NODE_NEXT(n) = next;
    return n;
}

// Constructs a new node.
static NODE *NODE_new(size_t data_size, const void *value, NODE_NEXT_TYPE next)
{
    NODE *n = malloc(NODE_SIZE(data_size));
    if (!n)
        return NULL;
    return NODE_init(n, data_size, value, next);
}

/// @brief Represents a stack.
typedef struct stack_s
{
    // The size of the data type
    size_t data_size;
    // The head node
    NODE *head;
    // The total number of nodes in the stack
    int32_t size;
} STACK;

// Initializes a new stack.
static STACK *STACK_init(STACK *s, size_t data_size)
{
    *s = (STACK){.data_size = data_size, .head = NULL, .size = 0};
    return s;
}

/// @brief Constructs a new stack.
/// @param data_size The size of the data type
/// @return The stack
STACK *STACK_new(size_t data_size)
{
    STACK *s = malloc(sizeof(STACK));
    if (!s)
        return NULL;
    return STACK_init(s, data_size);
}

/// @brief Returns the total number of elements in the stack.
/// @param s The stack
/// @return The size of the stack
int32_t STACK_size(const STACK *s)
{
    return s->size;
}

/// @brief Pushes a new element to the top of the stack.
/// @param s The stack
/// @param e A pointer to the element
/// @return `true` if the element was pushed, else `false`
bool STACK_push(STACK *s, const void *e)
{
    NODE *n = NODE_new(s->data_size, e, s->head);
    if (!n)
        return false;
    s->head = n;
    s->size++;
    return true;
}

/// @brief Pops an element from the top of the stack and return it.
/// @param s The stack
/// @return A pointer to the element which was popped
void *STACK_pop(STACK *s)
{
    NODE *n = s->head;
    if (!n)
        return NULL;
    s->head = NODE_NEXT(n);
    s->size--;
    return NODE_VALUE_PTR(n);
}

/// @brief Returns the element at the top of the stack.
/// @param s The stack
/// @return A pointer to the element at the top of the stack
void *STACK_peek(const STACK *s)
{
    return s->head == NULL ? NULL : NODE_VALUE_PTR(s->head);
}

/// @brief Frees the pointer to a value returned by `STACK_pop`
void STACK_ptr_free(void *ptr)
{
    free(ptr - NODE_VALUE_OFFSET);
}

/// @brief Frees the stack from memory.
/// @param s The stack
void STACK_free(STACK *s)
{
    NODE *n = s->head, *temp;
    while (n)
    {
        temp = n;
        n = NODE_NEXT(n);
        free(temp);
    }
    free(s);
}
