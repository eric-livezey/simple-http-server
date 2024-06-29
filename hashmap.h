#include <string.h>
#include "utils.h"

#define DEFAULT_INITIAL_CAPACITY (1 << 4)
#define MAXIMUM_CAPACITY (1 << 30)
#define DEFAULT_LOAD_FACTOR 0.75f

struct entry
{
    char *key;
    char *value;
};

typedef struct hashmap_s MAP;

MAP *MAP_new_r(char ignorecase, float loadfactor, int initialcapacity);

MAP *MAP_new(char ignorecase);

int MAP_size(MAP *map);

void MAP_clear(MAP *map);

int MAP_free(MAP *map);

struct entry **MAP_entry_set(MAP *map);

char **MAP_key_set(MAP *map);

char **MAP_values(MAP *map);

char *MAP_put(MAP *map, char *key, char *value);

void MAP_put_all(MAP *map, MAP *m);

char *MAP_get(MAP *map, char *key);

char *MAP_remove(MAP *map, char *key);

int MAP_contains_key(MAP *map, char *key);

int MAP_contains_value(MAP *map, char *value);

char *MAP_get_or_default(MAP *map, char *key, char *defaultValue);

char *MAP_put_if_absent(MAP *map, char *key, char *value);

char *MAP_replace(MAP *map, char *key, char *value);