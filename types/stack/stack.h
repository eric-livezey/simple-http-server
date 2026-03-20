#ifndef _STACK_H
#define _STACK_H

#include <stddef.h>
#include <stdbool.h>
#include <stdint.h>

/// @brief Represents a stack.
typedef struct stack_s STACK;

STACK *STACK_new(size_t data_size);
int32_t STACK_size(const STACK *s);
bool STACK_push(STACK *s, const void *e);
void *STACK_pop(STACK *s);
void *STACK_peek(const STACK *s);
void STACK_ptr_free(void *ptr);
void STACK_free(STACK *s);

#endif
