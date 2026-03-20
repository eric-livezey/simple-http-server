#include <stdlib.h>
#include <stdint.h>
#include <stdbool.h>
#include <string.h>
#include <ctype.h>
#include "../utils.h"

// Adapted from the JDK java.util.HashMap class
// Treeification is omitted for simplicity

#define DEFAULT_INITIAL_CAPACITY (1 << 4)
#define MAXIMUM_CAPACITY (1 << 30)
#define DEFAULT_LOAD_FACTOR 0.75f

typedef uint32_t hashfn(const void *value);
typedef int32_t cmpfn(const void *a, const void *b);

// Represents a node
typedef void *NODE;
#define NODE_HASH_TYPE uint32_t
#define NODE_HASH(n) *(NODE_HASH_TYPE *)(n)
#define NODE_NEXT_OFFSET sizeof(NODE_HASH_TYPE)
#define NODE_NEXT_TYPE NODE *
#define NODE_NEXT(n) *(NODE_NEXT_TYPE *)((uint8_t *)n + NODE_NEXT_OFFSET)
#define NODE_VALUE_OFFSET (NODE_NEXT_OFFSET + sizeof(NODE_NEXT_TYPE))
#define NODE_VALUE_PTR(n) ((uint8_t *)n + NODE_VALUE_OFFSET)
#define NODE_VALUE_CPY(n, p, vs) memcpy(NODE_VALUE_PTR(n), p, vs)
#define NODE_KEY_OFFSET(vs) (NODE_VALUE_OFFSET + vs)
#define NODE_KEY_PTR(n, vs) ((uint8_t *)n + NODE_KEY_OFFSET(vs))
#define NODE_KEY_CPY(n, vs, p, ks) memcpy(NODE_KEY_PTR(n, vs), p, ks)
#define NODE_SIZE(ks, vs) (NODE_KEY_OFFSET(vs) + ks)

// Calculates the table size for a capacity
static int32_t table_size_for(int32_t cap)
{
    int32_t n = -1 >> (((int32_t)log2ceil(cap) - 31) * -1);
    return (n < 0) ? 1 : (n >= MAXIMUM_CAPACITY) ? MAXIMUM_CAPACITY
                                                 : n + 1;
}

// Initializes a node
static NODE *NODE_init(NODE *n, uint32_t hash, const void *key, size_t key_size,
                       const void *value, size_t value_size, NODE *next)
{
    NODE_HASH(n) = hash;
    NODE_KEY_CPY(n, value_size, key, key_size);
    NODE_VALUE_CPY(n, value, value_size);
    NODE_NEXT(n) = next;
    return n;
}

// Constructs a new node
static NODE *NODE_new(uint32_t hash, const void *key, size_t key_size, const void *value,
                      size_t value_size, NODE *next)
{
    NODE *n = malloc(NODE_SIZE(key_size, value_size));
    if (n == NULL)
        return NULL;
    return NODE_init(n, hash, key, key_size, value, value_size, next);
}

// Represents a map entry
typedef void *ENTRY;
#define ENTRY_KEY_PTR(n) (n)
#define ENTRY_KEY_CPY(n, p, ks) memcpy(ENTRY_KEY_PTR(n), p, ks)
#define ENTRY_VALUE_OFFSET(ks) (ks)
#define ENTRY_VALUE_PTR(n, ks) ((uint8_t *)n + ENTRY_VALUE_OFFSET(ks))
#define ENTRY_VALUE_CPY(n, ks, p, vs) memcpy(ENTRY_VALUE_PTR(n, ks), p, vs)
#define ENTRY_SIZE(ks, vs) (ENTRY_VALUE_OFFSET(ks) + vs)

// Represents a hashmap
typedef struct hashmap_s
{
    // The size of the key's data type
    size_t key_size;
    // The size of the value's data type
    size_t value_size;
    // The function to hash a key
    hashfn *khashfn;
    // The function to compare two keys
    cmpfn *kcmpfn;
    // The cached entry set
    ENTRY **entry_set;
    // The cached key set
    void *key_set;
    // The cached array of values
    void *values;
    // The table
    NODE **table;
    // The capacity
    int32_t capacity;
    // The size
    int32_t size;
    // The threshold
    int32_t threshold;
    // The load factor
    float load_factor;
} MAP;

// Initializes a new map
MAP *MAP_init(MAP *m, size_t key_size, size_t value_size, hashfn *khashfn, cmpfn *kcmpfn,
              float load_factor, int32_t initial_capacity)
{
    *m = (MAP){
        .key_size = key_size,
        .value_size = value_size,
        .khashfn = khashfn,
        .kcmpfn = kcmpfn,
        .entry_set = NULL,
        .key_set = NULL,
        .values = NULL,
        .table = NULL,
        .capacity = 0,
        .size = 0,
        .load_factor = load_factor,
        .threshold = table_size_for(initial_capacity)};
    return m;
}

/// @brief Constructs a new map with the given parameters.
/// @param key_size The size of the key's data type
/// @param value_size The size of the value's data type
/// @param khashfn The function to hash a key
/// @param kcmpfn The function to compare two keys
/// @param load_factor The load factor
/// @param initial_capacity The initial capacity
/// @return The map
MAP *MAP_new_r(size_t key_size, size_t value_size, hashfn *khashfn, cmpfn *kcmpfn,
               float load_factor, int32_t initial_capacity)
{
    MAP *m = malloc(sizeof(MAP));
    if (!m)
        return NULL;
    return MAP_init(m, key_size, value_size, khashfn, kcmpfn, load_factor, initial_capacity);
}

/// @brief Constructs a new map with the given parameters.
/// @param key_size The size of the key's data type
/// @param value_size The size of the value's data type
/// @param khashfn The function to hash a key
/// @param kcmpfn The function to compare two keys
/// @return The map
MAP *MAP_new(size_t key_size, size_t value_size, hashfn *khashfn, cmpfn *kcmpfn)
{
    return MAP_new_r(key_size, value_size, khashfn, kcmpfn, DEFAULT_LOAD_FACTOR,
                     DEFAULT_INITIAL_CAPACITY);
}

/// @brief Returns the total number of entries which exist in the map.
/// @param map The map
/// @return The size of the map
int32_t MAP_size(const MAP *map)
{
    return map->size;
}

// Frees any cached data which dependent on the current state of the maps
static void MAP_free_cache(MAP *map)
{
    if (map->entry_set != NULL)
    {
        for (int32_t i = 0; i < map->size; i++)
            free(map->entry_set[i]);
        free(map->entry_set);
        map->entry_set = NULL;
    }
    if (map->key_set != NULL)
    {
        free(map->key_set);
        map->key_set = NULL;
    }
    if (map->values != NULL)
    {
        free(map->values);
        map->values = NULL;
    }
}

/// @brief Clears all entries from the map
/// @param map The map
void MAP_clear(MAP *map)
{
    NODE **tab;
    if ((tab = map->table) != NULL && map->size > 0)
    {
        MAP_free_cache(map);
        map->size = 0;
        for (int32_t i = 0; i < map->capacity; i++)
        {
            if (tab[i] != NULL)
            {
                NODE *e = tab[i], *n;
                while (e != NULL)
                {
                    n = NODE_NEXT(e);
                    free(e);
                    e = n;
                }
                tab[i] = NULL;
            }
        }
    }
}

// Expands the map to a larger size
static NODE **MAP_resize(MAP *map)
{
    NODE **old_tab = map->table;
    int32_t old_cap = (old_tab == NULL) ? 0 : map->capacity, old_thr = map->threshold, new_cap,
            new_thr = 0;
    if (old_cap > 0)
    {
        if (old_cap >= MAXIMUM_CAPACITY)
        {
            map->threshold = UINT32_MAX;
            return old_tab;
        }
        else if ((new_cap = old_cap << 1) < MAXIMUM_CAPACITY && old_cap >= DEFAULT_INITIAL_CAPACITY)
            new_thr = old_thr << 1; // double threshold
    }
    else if (old_thr > 0) // initial capacity was placed in threshold
        new_cap = old_thr;
    else
    { // zero initial threshold signifies using defaults
        new_cap = DEFAULT_INITIAL_CAPACITY;
        new_thr = (int32_t)(DEFAULT_LOAD_FACTOR * DEFAULT_INITIAL_CAPACITY);
    }
    if (new_thr == 0)
    {
        float ft = (float)new_cap * map->load_factor;
        new_thr = (new_cap < MAXIMUM_CAPACITY && ft < (float)MAXIMUM_CAPACITY ? (int32_t)ft
                                                                              : INT32_MAX);
    }
    map->threshold = new_thr;
    NODE **new_tab = calloc(new_cap, sizeof(NODE *));
    if (new_tab == NULL)
        return NULL;
    map->table = new_tab;
    map->capacity = new_cap;
    if (old_tab != NULL)
    {
        for (int32_t j = 0; j < old_cap; j++)
        {
            NODE *e;
            if ((e = old_tab[j]) != NULL)
            {
                old_tab[j] = NULL;
                if (NODE_NEXT(e) == NULL)
                    new_tab[NODE_HASH(e) & (new_cap - 1)] = e;
                else
                { // preserve order
                    NODE *lo_head = NULL, *lo_tail = NULL, *hi_head = NULL, *hi_tail = NULL, *next;
                    do
                    {
                        next = NODE_NEXT(e);
                        if ((NODE_HASH(e) & old_cap) == 0)
                        {
                            if (lo_tail == NULL)
                                lo_head = e;
                            else
                                NODE_NEXT(lo_tail) = e;
                            lo_tail = e;
                        }
                        else
                        {
                            if (hi_tail == NULL)
                                hi_head = e;
                            else
                                NODE_NEXT(hi_tail) = e;
                            hi_tail = e;
                        }
                    } while ((e = next) != NULL);
                    if (lo_tail != NULL)
                    {
                        NODE_NEXT(lo_tail) = NULL;
                        new_tab[j] = lo_head;
                    }
                    if (hi_tail != NULL)
                    {
                        NODE_NEXT(hi_tail) = NULL;
                        new_tab[j + old_cap] = hi_head;
                    }
                }
            }
        }
        free(old_tab);
    }
    return new_tab;
}

/// @brief Returns a set of all entries in the map.
/// @param map The map
/// @return The entry set
ENTRY **MAP_entry_set(MAP *map)
{
    ENTRY **es;
    if ((es = map->entry_set) == NULL)
    {
        NODE **tab;
        int32_t n;
        if ((tab = map->table) != NULL && (n = map->size) > 0)
        {
            if ((es = malloc(n * sizeof(ENTRY *))) == NULL)
                return NULL;
            size_t ks = map->key_size, vs = map->value_size;
            int32_t j = 0;
            for (int32_t i = 0; i < map->capacity; i++)
            {
                for (NODE *e = tab[i]; e != NULL; e = NODE_NEXT(e), j++)
                {
                    if ((es[j] = malloc(ENTRY_SIZE(ks, vs))) == NULL)
                        return NULL;
                    ENTRY_KEY_CPY(es[j], NODE_KEY_PTR(e, vs), ks);
                    ENTRY_VALUE_CPY(es[j], ks, NODE_VALUE_PTR(e), vs);
                }
            }
            map->entry_set = es;
        }
    }
    return es;
}

/// @brief Returns a set of all key in the map.
/// @param map The map
/// @return The key set
void *MAP_key_set(MAP *map)
{
    void *ks;
    if ((ks = map->key_set) == NULL)
    {
        ENTRY **es;
        if ((es = MAP_entry_set(map)) != NULL)
        {
            if ((ks = malloc(map->size * sizeof(void *))) == NULL)
                return NULL;
            for (int32_t i = 0; i < map->size; i++)
                memcpy((uint8_t *)ks + i, ENTRY_KEY_PTR(es[i]), map->key_size);
            map->key_set = ks;
        }
    }
    return ks;
}

/// @brief Returns an array of all values in the map.
/// @param map The map
/// @return The values
void *MAP_values(MAP *map)
{
    void *vals;
    if ((vals = map->values) == NULL)
    {
        ENTRY **es;
        if ((es = MAP_entry_set(map)) != NULL)
        {
            if ((vals = malloc(map->size * sizeof(void *))) == NULL)
                return NULL;
            for (int32_t i = 0; i < map->size; i++)
                memcpy((uint8_t *)vals + i, ENTRY_VALUE_PTR(es[i], map->key_size), map->value_size);
            map->values = vals;
        }
    }
    return vals;
}

// Puts a value in the map, returns the previous mapping in `rp` if given
static void *MAP_put_val(MAP *map, uint32_t hash, const void *key, const void *value, bool only_if_absent, void *rp)
{
    NODE **tab, *p;
    size_t ks = map->key_size, vs = map->value_size;
    int32_t n, i;
    if ((tab = map->table) == NULL || (n = map->capacity) == 0)
    {
        tab = MAP_resize(map);
        n = map->capacity;
    }
    if ((p = tab[i = (n - 1) & hash]) == NULL)
        tab[i] = NODE_new(hash, key, ks, value, vs, NULL);
    else
    {
        NODE *e;
        void *k;
        if (NODE_HASH(p) == hash && ((k = NODE_KEY_PTR(p, vs)) == key || (key != NULL &&
                                                                          map->kcmpfn(key, k) == 0)))
            e = p;
        else
        {
            for (;;)
            {
                if ((e = NODE_NEXT(p)) == NULL)
                {
                    NODE_NEXT(p) = NODE_new(hash, key, ks, value, vs, NULL);
                    break;
                }
                if (NODE_HASH(e) == hash && ((k = NODE_KEY_PTR(e, vs)) == key ||
                                             (key != NULL && map->kcmpfn(key, k) == 0)))
                    break;
                p = e;
            }
        }
        if (e != NULL)
        { // existing mapping for key
            if (rp != NULL)
                memcpy(rp, NODE_VALUE_PTR(e), vs);
            // NOTE: In Java, NULL is considered absent, but there is not way to check that if the value
            // is NULL since it cannot be safely dereferenced to a pointer
            if (!only_if_absent)
                NODE_VALUE_CPY(e, value, vs);
            return rp;
        }
    }
    MAP_free_cache(map);
    if (map->size++ > map->threshold)
        MAP_resize(map);
    return NULL;
}

/// @brief Puts a value in the map mapped to a key.
/// @param map The map
/// @param key A pointer to the key
/// @param value A pointer the value
/// @param rp A pointer in which to store the previous value
/// @return The previous mapping if `rp` is given, else `NULL`
void *MAP_put(MAP *map, const void *key, const void *value, void *rp)
{
    return MAP_put_val(map, map->khashfn(key), key, value, false, rp);
}

// Puts the entries of a map into the map
static void MAP_put_map_entries(MAP *map, MAP *m)
{
    int32_t s = m->size;
    if (s > 0)
    {
        if (map->table == NULL)
        { // pre-size
            float ft = ((float)s / map->load_factor) + 1.0F;
            int32_t t = ((ft < (float)MAXIMUM_CAPACITY) ? (int32_t)ft : MAXIMUM_CAPACITY);
            if (t > map->threshold)
                map->threshold = table_size_for(t);
        }
        else
        {
            // Because of linked-list bucket constraints, we cannot
            // expand all at once, but can reduce total resize
            // effort by repeated doubling now vs later
            while (s > map->threshold && map->capacity < MAXIMUM_CAPACITY)
                MAP_resize(map);
        }
        ENTRY **es = MAP_entry_set(m);
        for (int32_t i = 0; i < m->size; i++)
        {
            ENTRY *e = es[i];
            MAP_put_val(map, map->khashfn(ENTRY_KEY_PTR(e)), ENTRY_KEY_PTR(e), ENTRY_VALUE_PTR(e, map->key_size), false, NULL);
        }
    }
}

/// @brief Puts all entries from a map into the map.
/// @param map The map
/// @param m The map to put
void MAP_put_all(MAP *map, MAP *m)
{
    MAP_put_map_entries(map, m);
}

// Returns the node which has the given key
static NODE *MAP_get_node(const MAP *map, const void *key)
{
    NODE **tab, *first, *e;
    size_t vs = map->value_size;
    uint32_t h;
    int32_t n;
    void *k;
    if ((tab = map->table) != NULL && (n = map->capacity) > 0 &&
        (first = tab[(n - 1) & (h = map->khashfn(key))]) != NULL)
    {
        if (NODE_HASH(first) == h && ((k = NODE_KEY_PTR(first, vs)) == key || (key != NULL &&
                                                                               map->kcmpfn(key, k) == 0)))
            return first;
        if ((e = NODE_NEXT(first)) != NULL)
            do
                if (NODE_HASH(e) == h && ((k = NODE_KEY_PTR(e, vs)) == key || (key != NULL &&
                                                                               map->kcmpfn(key, k) == 0)))
                    return e;
            while ((e = NODE_NEXT(e)) != NULL);
    }
    return NULL;
}

/// @brief Returns the mapping for a given key.
/// @param map The map
/// @param key A pointer to the key
/// @return A pointer to the value which was mapped to the key, or `NULL`
void *MAP_get(const MAP *map, const void *key)
{
    NODE *e = MAP_get_node(map, key);
    return e == NULL ? NULL : NODE_VALUE_PTR(e);
}

// Removes a node from the map and returns it
static NODE *MAP_remove_node(MAP *map, uint32_t hash, const void *key, const void *value, cmpfn *vcmpfn)
{
    NODE **tab, *p;
    size_t vs = map->value_size;
    int32_t n, index;
    if ((tab = map->table) != NULL && (n = map->capacity) > 0 &&
        (p = tab[index = (n - 1) & hash]) != NULL)
    {
        NODE *node = NULL, *e;
        void *k, *v;
        if (NODE_HASH(p) == hash && ((k = NODE_KEY_PTR(p, vs)) == key || (key != NULL &&
                                                                          map->kcmpfn(key, k) == 0)))
            node = p;
        else if ((e = NODE_NEXT(p)) != NULL)
        {
            do
            {
                if (NODE_HASH(e) == hash && ((k = NODE_KEY_PTR(e, vs)) == key ||
                                             (key != NULL && map->kcmpfn(key, k) == 0)))
                {
                    node = e;
                    break;
                }
                p = e;
            } while ((e = NODE_NEXT(e)) != NULL);
        }
        if (node != NULL && (vcmpfn == NULL ||
                             (v = NODE_VALUE_PTR(node)) == value ||
                             (value != NULL && vcmpfn(value, v) == 0)))
        {
            if (node == p)
            {
                tab[index] = NODE_NEXT(node);
            }
            else
            {
                NODE_NEXT(p) = NODE_NEXT(node);
            }
            MAP_free_cache(map);
            map->size--;
            return node;
        }
    }
    return NULL;
}

/// @brief Removes a key from the map
/// @param map The map
/// @param key A pointer to the key
/// @return A pointer to the value which was mapped to the key, or `NULL`
void *MAP_remove(MAP *map, const void *key)
{
    NODE *e;
    if ((e = MAP_remove_node(map, map->khashfn(key), key, NULL, false)) == NULL)
        return NULL;
    return NODE_VALUE_PTR(e);
}

/// @brief Returns `true` if the map contains a key.
/// @param map The map
/// @param key A pointer to the key
/// @return `true` if the map contains the key, else `false`
bool MAP_contains_key(const MAP *map, const void *key)
{
    return MAP_get_node(map, key) != NULL;
}

/// @brief Returns `true` if the map contains a value.
/// @param map The map
/// @param value A pointer to the value
/// @param vcmpfn A function to compare two values
/// @return `true` if the map contains the value, else `false`
bool MAP_contains_value(const MAP *map, const void *value, cmpfn *vcmpfn)
{
    NODE **tab;
    void *v;
    if ((tab = map->table) != NULL && map->size > 0)
        for (int32_t i = 0; i < map->capacity; i++)
            for (NODE *e = tab[i]; e != NULL; e = NODE_NEXT(e))
                if ((v = NODE_VALUE_PTR(e)) == value || (value != NULL && vcmpfn(value, v) == 0))
                    return true;
    return false;
}

/// @brief Returns the mapping for a given key, or a default value.
/// @param map The map
/// @param key A pointer to the key
/// @param default_value A pointer to the default value
/// @return A pointer to the mapping for the key, or `NULL`
const void *MAP_get_or_default(const MAP *map, const void *key, const void *default_value)
{
    NODE *e = MAP_get_node(map, key);
    return e == NULL ? default_value : NODE_VALUE_PTR(e);
}

/// @brief Puts a value into the map mapped to a key only if the key is not already mapped.
/// @param map The map
/// @param key A pointer to the key
/// @param value A pointer to the value
/// @param rp A pointer to store the return value
/// @return The existing mapping if `rp` is given, else `NULL`
void *MAP_put_if_absent(MAP *map, const void *key, const void *value, void *rp)
{
    return MAP_put_val(map, map->khashfn(key), key, value, true, rp);
}

/// @brief Replaces the value which is mapped to a key with a new value
/// @param map The map
/// @param key A pointer to the key
/// @param value A pointer to the value
/// @param rp A pointer to store the return value
/// @return The value which was replaced if `rp` is given, else `NULL`
void *MAP_replace(const MAP *map, const void *key, const void *value, void *rp)
{
    NODE *e;
    if ((e = MAP_get_node(map, key)) != NULL)
    {
        size_t ks = map->key_size, vs = map->value_size;
        if (rp != NULL)
            memcpy(rp, NODE_VALUE_PTR(e), vs);
        NODE_VALUE_CPY(e, value, vs);
        return rp;
    }
    return NULL;
}

/// @brief Frees a pointer to a map value
/// @param ptr The pointer
void MAP_free_ptr(void *ptr)
{
    free(ptr - NODE_VALUE_OFFSET);
}

/// @brief Frees a map
/// @param map The map
void MAP_free(MAP *map)
{
    NODE **tab;
    if ((tab = map->table) != NULL && map->size > 0)
    {
        MAP_free_cache(map);
        for (int32_t i = 0; i < map->capacity; i++)
            if (tab[i] != NULL)
            {
                NODE *e = tab[i], *n;
                while (e != NULL)
                {
                    n = NODE_NEXT(e);
                    free(e);
                    e = n;
                }
            }
        free(tab);
    }
    free(map);
}
