#ifndef _STR_MAP_H
#define _STR_MAP_H

#include "../utils.h"

#define KEY_TYPE char *
#define KEY_HASH strhash_p
#define KEY_CMP strcmp_p
#define VALUE_TYPE char *
#define VALUE_CMP strcmp_p
#define LABEL STR_MAP
#include "tmap.h"
#undef KEY_TYPE
#undef KEY_HASH
#undef KEY_CMP
#undef VALUE_TYPE
#undef VALUE_CMP
#undef LABEL

#endif
