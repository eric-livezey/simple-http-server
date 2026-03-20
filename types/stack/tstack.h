#include "stack.h"

#ifndef TYPE
#error 'TYPE must be defined'
#endif
#ifndef LABEL
#error 'LABEL must be defined'
#endif

#define CONCAT(x, y) x##_##y
#define CONCAT_EXPAND(x, y) CONCAT(x, y)
#define NAME(x) CONCAT_EXPAND(LABEL, x)

typedef STACK LABEL;

static inline LABEL *NAME(new)()
{
    return STACK_new(sizeof(TYPE));
}

static inline int32_t NAME(size)(const LABEL *s)
{
    return STACK_size(s);
}

static inline bool NAME(push)(LABEL *s, const TYPE e)
{
    return STACK_push(s, &e);
}

static inline TYPE NAME(pop)(LABEL *s)
{
    TYPE *ptr = STACK_pop(s);
    if (ptr == NULL)
    {
        return (TYPE){0};
    }
    TYPE value = *ptr;
    STACK_ptr_free(ptr);
    return value;
}

static inline TYPE NAME(peek)(const LABEL *s)
{
    TYPE *ptr = STACK_peek(s);
    return ptr == NULL ? (TYPE){0} : *ptr;
}

static inline void NAME(free)(LABEL *s)
{
    STACK_free(s);
}

#undef CONCAT
#undef CONCAT_EXPAND
#undef NAME
