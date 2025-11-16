#include <stdlib.h>
#include <stdbool.h>
#include <string.h>
#include <ctype.h>
#include "utils.h"

#define DEFAULT_INITIAL_CAPACITY (1 << 4)
#define MAXIMUM_CAPACITY (1 << 30)
#define DEFAULT_LOAD_FACTOR 0.75f

struct entry
{
    char *key;
    void *value;
};

typedef struct hashmap_s MAP;

MAP *MAP_new_r(float load_factor, int initial_capacity, bool ignore_case);

MAP *MAP_new();

MAP *MAP_new_ignore_case();

int MAP_size(MAP *map);

void MAP_clear(MAP *map);

int MAP_free(MAP *map);

struct entry **MAP_entry_set(MAP *map);

char **MAP_key_set(MAP *map);

void **MAP_values(MAP *map);

void *MAP_put(MAP *map, char *key, void *value);

void MAP_put_all(MAP *map, MAP *m);

void *MAP_get(MAP *map, char *key);

void *MAP_remove(MAP *map, char *key);

int MAP_contains_key(MAP *map, char *key);

int MAP_contains_value(MAP *map, void *value);

void *MAP_get_or_default(MAP *map, char *key, void *default_value);

void *MAP_put_if_absent(MAP *map, char *key, void *value);

void *MAP_replace(MAP *map, char *key, void *value);