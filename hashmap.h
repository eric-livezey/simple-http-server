#include <string.h>
#include <stdlib.h>
#include <math.h>

#define DEFAULT_INITIAL_CAPACITY (1 << 4)
#define MAXIMUM_CAPACITY (1 << 30)
#define DEFAULT_LOAD_FACTOR 0.75f

typedef struct entry_s
{
    char *key;
    char *value;
} entry_t;

typedef struct node_s
{
    int hash;
    char *key;
    char *value;
    struct node_s *next;
} node_t;

typedef struct hashmap_s
{
    entry_t **entryset;
    char **keyset;
    char **values;
    struct node_s **table;
    int capacity;
    int size;
    int modcount;
    int threshold;
    float loadfactor;
} hashmap_t;

int hash(char *s);

int table_size_for(int cap);

int node_init(int hash, char *key, char *value, node_t *next, node_t *node);

int hashmap_init(hashmap_t *hashmap);

void hashmap_destroy_cache(hashmap_t *map);

void hashmap_clear(hashmap_t *map);

int hashmap_destroy(hashmap_t *map);

node_t **hashmap_resize(hashmap_t *map);

entry_t **hashmap_entry_set(hashmap_t *map);

char **hashmap_key_set(hashmap_t *map);

char **hashmap_values(hashmap_t *map);

char *hashmap_put_val(hashmap_t *map, int hash, char *key, char *value, int onlyIfAbsent, int evict);

char *hashmap_put(hashmap_t *map, char *key, char *value);

void hashmap_put_map_entries(hashmap_t *map, hashmap_t *m, int evict);

void hashmap_put_all(hashmap_t *map, hashmap_t *m);

node_t *hashmap_get_node(hashmap_t *map, char *key);

char *hashmap_get(hashmap_t *map, char *key);

node_t *hashmap_remove_node(hashmap_t *map, int hash, char *key, char *value, int matchValue, int movable);

char *hashmap_remove(hashmap_t *map, char *key);

int hashmap_contains_key(hashmap_t *map, char *key);

int hashmap_contains_value(hashmap_t *map, char *value);

char *hashmap_get_or_default(hashmap_t *map, char *key, char *defaultValue);

char *hashmap_put_if_absent(hashmap_t *map, char *key, char *value);

char *hashmap_replace(hashmap_t *map, char *key, char *value);