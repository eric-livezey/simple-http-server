#include "hashmap.h"

#ifndef KEY_TYPE
#error 'KEY_TYPE must be defined'
#endif
#ifndef KEY_HASH
#error 'KEY_HASH must be defined'
#endif
#ifndef KEY_CMP
#error 'KEY_CMP must be defined'
#endif
#ifndef VALUE_TYPE
#error 'VALUE_TYPE must be defined'
#endif
#ifndef LABEL
#error 'LABEL must be defined'
#endif

#define CONCAT(x, y) x##_##y
#define CONCAT_EXPAND(x, y) CONCAT(x, y)
#define NAME(x) CONCAT_EXPAND(LABEL, x)

typedef struct NAME(entry_s)
{
    KEY_TYPE key;
    VALUE_TYPE value;
} NAME(entry_t);
typedef MAP LABEL;
static inline LABEL *NAME(new_r)(float load_factor, int32_t initial_capacity)
{
    return MAP_new_r(sizeof(KEY_TYPE), sizeof(VALUE_TYPE), &KEY_HASH, &KEY_CMP, load_factor, initial_capacity);
}
static inline LABEL *NAME(new)()
{
    return MAP_new(sizeof(KEY_TYPE), sizeof(VALUE_TYPE), &KEY_HASH, &KEY_CMP);
}
static inline LABEL *NAME(from_entries)(const NAME(entry_t)  *entries, int32_t size)
{
    return MAP_from_entries(sizeof(KEY_TYPE), sizeof(VALUE_TYPE), &KEY_HASH, &KEY_CMP, entries, size);
}
static inline int32_t NAME(size)(const LABEL *map)
{
    return MAP_size(map);
}
static inline void NAME(clear)(LABEL *map)
{
    MAP_clear(map);
}
static inline NAME(entry_t) * *NAME(entry_set)(LABEL *map)
{
    return (NAME(entry_t) **)MAP_entry_set(map);
}
static inline KEY_TYPE *NAME(key_set)(LABEL *map)
{
    return (KEY_TYPE *)MAP_key_set(map);
}
static inline VALUE_TYPE *NAME(values)(LABEL *map)
{
    return (VALUE_TYPE *)MAP_values(map);
}
static inline VALUE_TYPE NAME(put)(LABEL *map, const KEY_TYPE key, const VALUE_TYPE value)
{
    VALUE_TYPE v = (VALUE_TYPE){0};
    VALUE_TYPE *p = MAP_put(map, &key, &value, &v);
    return v;
}
static inline void NAME(put_all)(LABEL *map, LABEL *m)
{
    MAP_put_all(map, m);
}
static inline VALUE_TYPE NAME(get)(const LABEL *map, const KEY_TYPE key)
{
    VALUE_TYPE *p = MAP_get(map, &key);
    return p == NULL ? (VALUE_TYPE){0} : *p;
}
static inline VALUE_TYPE NAME(remove)(LABEL *map, const KEY_TYPE key)
{
    VALUE_TYPE *p = MAP_remove(map, &key);
    if (p == NULL)
    {
        return (VALUE_TYPE){0};
    }
    VALUE_TYPE v = *p;
    MAP_free_ptr(p);
    return v;
}
static inline bool NAME(contains_key)(const LABEL *map, const KEY_TYPE key)
{
    return MAP_contains_key(map, &key);
}
static inline bool NAME(contains_value)(const LABEL *map, const VALUE_TYPE value
#ifndef VALUE_CMP
                                        ,
                                        cmpfn *vcmpfn
#endif
)
{
    return MAP_contains_value(map, &value,
#ifndef VALUE_CMP
                              vcmpfn
#else
                              &VALUE_CMP
#endif
    );
}
static inline VALUE_TYPE NAME(get_or_default)(const LABEL *map, const KEY_TYPE key, const VALUE_TYPE default_value)
{
    return *(VALUE_TYPE *)MAP_get_or_default(map, &key, &default_value);
}
static inline VALUE_TYPE NAME(put_if_absent)(LABEL *map, const KEY_TYPE key, const VALUE_TYPE value)
{
    VALUE_TYPE v = (VALUE_TYPE){0};
    VALUE_TYPE *p = MAP_put_if_absent(map, &key, &value, &v);
    return v;
}
static inline VALUE_TYPE NAME(replace)(const LABEL *map, const KEY_TYPE key, const VALUE_TYPE value)
{
    VALUE_TYPE v = (VALUE_TYPE){0};
    VALUE_TYPE *p = MAP_replace(map, &key, &value, &v);
    return v;
}
static inline void NAME(free)(LABEL *map)
{
    MAP_free(map);
}
