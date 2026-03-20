#ifndef _HASHMAP_H
#define _HASHMAP_H

#include <stddef.h>
#include <stdint.h>
#include <stdbool.h>

/// @brief A function which hashes a value when given a pointer
typedef uint32_t hashfn(const void *value);
/// @brief A function which compares two values when given pointers
typedef int32_t cmpfn(const void *a, const void *b);
/// @brief Represents an map entry with a key and a value.
/// @note This is equivalent to a struct with a format of `{ key, value }`, but it cannot be
/// properly defined as such in c since the types of the key and value are unknown
typedef void *ENTRY;
/// @brief Represents a map
typedef struct hashmap_s MAP;
MAP *MAP_new_r(size_t key_size, size_t value_size, hashfn *khashfn, cmpfn *kcmpfn,
               float load_factor, int32_t initial_capacity);
MAP *MAP_new(size_t key_size, size_t value_size, hashfn *khashfn, cmpfn *kcmpfn);
int32_t MAP_size(const MAP *map);
void MAP_clear(MAP *map);
ENTRY **MAP_entry_set(MAP *map);
void *MAP_key_set(MAP *map);
void *MAP_values(MAP *map);
void *MAP_put(MAP *map, const void *key, const void *value, void *rp);
void MAP_put_all(MAP *map, MAP *m);
void *MAP_get(const MAP *map, const void *key);
void *MAP_remove(MAP *map, const void *key);
bool MAP_contains_key(const MAP *map, const void *key);
bool MAP_contains_value(const MAP *map, const void *value, cmpfn *vcmpfn);
void *MAP_get_or_default(const MAP *map, const void *key, const void *default_value);
void *MAP_put_if_absent(MAP *map, const void *key, const void *value, void *rp);
void *MAP_replace(const MAP *map, const void *key, const void *value, void *rp);
void MAP_free_ptr(void *ptr);
void MAP_free(MAP *map);

#endif
