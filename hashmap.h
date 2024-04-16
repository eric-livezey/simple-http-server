#include <stdlib.h>
#include <string.h>
#include <ctype.h>
#include "utils.h"

#define DEFAULT_INITIAL_CAPACITY (1 << 4)
#define MAXIMUM_CAPACITY (1 << 30)
#define DEFAULT_LOAD_FACTOR 0.75f

typedef struct entry_s
{
    char *key;
    char *value;
} entry;

typedef struct node_s
{
    int hash;
    char *key;
    char *value;
    struct node_s *next;
} hashmap_node;

typedef struct hashmap_s
{
    entry **entryset;
    char **keyset;
    char **values;
    struct node_s **table;
    int capacity;
    int size;
    int modcount;
    int threshold;
    float loadfactor;
    char ignorecase;
} hashmap;

int hash(char *s, char lower);

int table_size_for(int cap);

int node_init(int hash, char *key, char *value, hashmap_node *next, hashmap_node *node);

int hashmap_init(hashmap *hashmap, char ignorecase);

void hashmap_free_cache(hashmap *map);

void hashmap_clear(hashmap *map);

int hashmap_free_all(hashmap *map);

hashmap_node **hashmap_resize(hashmap *map);

entry **hashmap_entry_set(hashmap *map);

char **hashmap_key_set(hashmap *map);

char **hashmap_values(hashmap *map);

char *hashmap_put_val(hashmap *map, int hash, char *key, char *value, int onlyIfAbsent, int evict);

char *hashmap_put(hashmap *map, char *key, char *value);

void hashmap_put_map_entries(hashmap *map, hashmap *m, int evict);

void hashmap_put_all(hashmap *map, hashmap *m);

hashmap_node *hashmap_get_node(hashmap *map, char *key);

char *hashmap_get(hashmap *map, char *key);

hashmap_node *hashmap_remove_node(hashmap *map, int hash, char *key, char *value, int matchValue, int movable);

char *hashmap_remove(hashmap *map, char *key);

int hashmap_contains_key(hashmap *map, char *key);

int hashmap_contains_value(hashmap *map, char *value);

char *hashmap_get_or_default(hashmap *map, char *key, char *defaultValue);

char *hashmap_put_if_absent(hashmap *map, char *key, char *value);

char *hashmap_replace(hashmap *map, char *key, char *value);
