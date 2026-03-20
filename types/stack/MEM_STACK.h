#ifndef _MEM_STACK_H
#define _MEM_STACK_H

#include <stdlib.h>

#define TYPE void *
#define LABEL MEM_STACK
#include "tstack.h"
#undef TYPE
#undef LABEL

static inline void MEM_STACK_free_all(MEM_STACK *s)
{
    while (MEM_STACK_size(s) > 0)
    {
        free(MEM_STACK_pop(s));
    }
    MEM_STACK_free(s);
}

#endif
