#ifndef _STRCASE_MAP_H
#define _STRCASE_MAP_H

#include "../utils.h"

#define KEY_TYPE char *
#define KEY_HASH strcasehash_p
#define KEY_CMP strcasecmp_p
#define VALUE_TYPE char *
#define VALUE_CMP strcmp_p
#define LABEL STRCASE_MAP
#include "tmap.h"
#undef KEY_TYPE
#undef KEY_HASH
#undef KEY_CMP
#undef VALUE_TYPE
#undef VALUE_CMP
#undef LABEL

#endif
