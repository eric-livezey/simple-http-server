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

typedef struct node_s
{
    int hash;
    char *key;
    char *value;
    struct node_s *next;
} NODE;

typedef struct hashmap_s
{
    struct entry **entryset;
    char **keyset;
    char **values;
    struct node_s **table;
    int capacity;
    int size;
    int modcount;
    int threshold;
    float loadfactor;
    char ignorecase;
} MAP;

int hash(char *s, char lower)
{
    int h = 0;
    for (int i = 0; s[i] != '\0'; i++)
        h = 31 * h + lower ? tolower(s[i]) : s[i];
    return h;
}

int table_size_for(int cap)
{
    int n = -1 >> (((int)(log2ceil(cap)) - 31) * -1);
    return (n < 0) ? 1 : (n >= MAXIMUM_CAPACITY) ? MAXIMUM_CAPACITY
                                                 : n + 1;
}

NODE *NODE_new(int hash, char *key, char *value, NODE *next)
{
    NODE *node = malloc(sizeof(NODE));
    node->hash = hash;
    node->key = key;
    node->value = value;
    node->next = next;
    return node;
}

MAP *MAP_new_r(char ignorecase, float loadfactor, int initialcapacity)
{
    MAP *map = malloc(sizeof(MAP));
    map->entryset = NULL;
    map->keyset = NULL;
    map->values = NULL;
    map->table = NULL;
    map->capacity = 0;
    map->size = 0;
    map->modcount = 0;
    map->loadfactor = loadfactor;
    map->threshold = table_size_for(initialcapacity);
    map->ignorecase = ignorecase;
    return map;
}

MAP *MAP_new(char ignorecase)
{
    return MAP_new_r(ignorecase, DEFAULT_LOAD_FACTOR, DEFAULT_INITIAL_CAPACITY);
}

int MAP_size(MAP *map) {
    return map->size;
}

void MAP_free_cache(MAP *map)
{
    if (map->entryset != NULL)
    {
        for (int i = 0; i < map->size; i++)
            free(map->entryset[i]);
        free(map->entryset);
        map->entryset = NULL;
    }
    if (map->keyset != NULL)
    {
        free(map->keyset);
        map->keyset = NULL;
    }
    if (map->values != NULL)
    {
        free(map->values);
        map->values = NULL;
    }
}

void MAP_clear(MAP *map)
{
    NODE **tab;
    map->modcount++;
    if ((tab = map->table) != NULL && map->size > 0)
    {
        MAP_free_cache(map);
        map->size = 0;
        for (int i = 0; i < map->capacity; i++)
        {
            if (tab[i] != NULL)
            {
                for (NODE *e = tab[i]; e != NULL; e = e->next)
                    free(e);
                tab[i] = NULL;
            }
        }
    }
}

void MAP_free(MAP *map)
{
    NODE **tab;
    if ((tab = map->table) != NULL && map->size > 0)
    {
        MAP_free_cache(map);
        for (int i = 0; i < map->capacity; i++)
            if (tab[i] != NULL)
                for (NODE *e = tab[i]; e != NULL; e = e->next)
                    free(e);
        free(tab);
    }
    free(map);
}

NODE **MAP_resize(MAP *map)
{
    NODE **oldTab = map->table;
    int oldCap = (oldTab == NULL) ? 0 : map->capacity;
    int oldThr = map->threshold;
    int newCap, newThr = 0;
    if (oldCap > 0)
    {
        if (oldCap >= MAXIMUM_CAPACITY)
        {
            map->threshold = __INT_MAX__;
            return oldTab;
        }
        else if ((newCap = oldCap << 1) < MAXIMUM_CAPACITY && oldCap >= DEFAULT_INITIAL_CAPACITY)
            newThr = oldThr << 1; // double threshold
    }
    else if (oldThr > 0) // initial capacity was placed in threshold
        newCap = oldThr;
    else
    { // zero initial threshold signifies using defaults
        newCap = DEFAULT_INITIAL_CAPACITY;
        newThr = (int)(DEFAULT_LOAD_FACTOR * DEFAULT_INITIAL_CAPACITY);
    }
    if (newThr == 0)
    {
        float ft = (float)newCap * map->loadfactor;
        newThr = (newCap < MAXIMUM_CAPACITY && ft < (float)MAXIMUM_CAPACITY ? (int)ft : __INT_MAX__);
    }
    map->threshold = newThr;
    NODE **newTab = calloc(newCap, sizeof(NODE *));
    map->table = newTab;
    map->capacity = newCap;
    if (oldTab != NULL)
    {
        for (int j = 0; j < oldCap; j++)
        {
            NODE *e;
            if ((e = oldTab[j]) != NULL)
            {
                oldTab[j] = NULL;
                if (e->next == NULL)
                    newTab[e->hash & (newCap - 1)] = e;
                else
                { // preserve order
                    NODE *loHead = NULL, *loTail = NULL;
                    NODE *hiHead = NULL, *hiTail = NULL;
                    NODE *next;
                    do
                    {
                        next = e->next;
                        if ((e->hash & oldCap) == 0)
                        {
                            if (loTail == NULL)
                                loHead = e;
                            else
                                loTail->next = e;
                            loTail = e;
                        }
                        else
                        {
                            if (hiTail == NULL)
                                hiHead = e;
                            else
                                hiTail->next = e;
                            hiTail = e;
                        }
                    } while ((e = next) != NULL);
                    if (loTail != NULL)
                    {
                        loTail->next = NULL;
                        newTab[j] = loHead;
                    }
                    if (hiTail != NULL)
                    {
                        hiTail->next = NULL;
                        newTab[j + oldCap] = hiHead;
                    }
                }
            }
        }
        free(oldTab);
    }
    return newTab;
}

struct entry **MAP_entry_set(MAP *map)
{
    struct entry **es;
    if ((es = map->entryset) == NULL)
    {
        NODE **tab;
        int n;
        if ((tab = map->table) != NULL && (n = map->size) > 0)
        {
            es = malloc(n * sizeof(struct entry *));
            int j = 0;
            for (int i = 0; i < map->capacity; i++)
            {
                for (NODE *e = tab[i]; e != NULL; e = e->next, j++)
                {
                    es[j] = malloc(sizeof(struct entry));
                    es[j]->key = e->key;
                    es[j]->value = e->value;
                }
            }
            map->entryset = es;
        }
    }
    return es;
}

char **MAP_key_set(MAP *map)
{
    char **ks;
    if ((ks = map->keyset) != NULL)
    {
        struct entry **es;
        if ((es = MAP_entry_set(map)) != NULL)
        {
            char **ks = malloc(map->size * sizeof(char *));
            for (int i = 0; i < map->size; i++)
                ks[i] = es[i]->key;
            map->keyset = ks;
        }
    }
    return ks;
}

char **MAP_values(MAP *map)
{
    struct entry **es;
    if ((es = MAP_entry_set(map)) != NULL)
    {
        char **vals = malloc(map->size * sizeof(char *));
        for (int i = 0; i < map->size; i++)
            vals[i] = es[i]->value;
        map->values = vals;
        return vals;
    }
    return NULL;
}

char *MAP_put_val(MAP *map, int hash, char *key, char *value, char onlyIfAbsent, char evict)
{
    NODE **tab;
    int cap = 0;
    NODE *p;
    int n, i;
    if ((tab = map->table) == NULL || (n = map->capacity) == 0)
    {
        tab = MAP_resize(map);
        n = map->capacity;
    }
    if ((p = tab[i = (n - 1) & hash]) == NULL)
    {
        tab[i] = NODE_new(hash, key, value, NULL);
    }
    else
    {
        NODE *e;
        char *k;
        if (p->hash == hash && ((k = p->key) == key || (key != NULL && (map->ignorecase ? strcasecmp(key, k) : strcmp(key, k)) == 0)))
            e = p;
        else
        {
            for (int binCount = 0;; binCount++)
            {
                if ((e = p->next) == NULL)
                {
                    p->next = NODE_new(hash, key, value, NULL);
                    break;
                }
                if (e->hash == hash && ((k = e->key) == key || (key != NULL && (map->ignorecase ? strcasecmp(key, k) : strcmp(key, k)) == 0)))
                    break;
                p = e;
            }
        }
        if (e != NULL)
        { // existing mapping for key
            char *oldValue = e->value;
            if (!onlyIfAbsent || oldValue == NULL)
                e->value = value;
            return oldValue;
        }
    }
    map->modcount++;
    MAP_free_cache(map);
    if (map->size++ > map->threshold)
        MAP_resize(map);
    return NULL;
}

char *MAP_put(MAP *map, char *key, char *value)
{
    return MAP_put_val(map, hash(key, map->ignorecase), key, value, 0, 1);
}

void MAP_put_map_entries(MAP *map, MAP *m, char evict)
{
    int s = m->size;
    if (s > 0)
    {
        if (map->table == NULL)
        { // pre-size
            float ft = ((float)s / map->loadfactor) + 1.0F;
            int t = ((ft < (float)MAXIMUM_CAPACITY) ? (int)ft : MAXIMUM_CAPACITY);
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
        struct entry **es = MAP_entry_set(m);
        for (int i = 0; i < m->size; i++)
        {
            struct entry *e = es[i];
            MAP_put_val(map, hash(e->key, map->ignorecase), e->key, e->value, 0, evict);
        }
    }
}

void MAP_put_all(MAP *map, MAP *m)
{
    MAP_put_map_entries(map, m, 1);
}

NODE *MAP_get_node(MAP *map, char *key)
{
    NODE **tab;
    NODE *first, *e;
    int n, h;
    char *k;
    if ((tab = map->table) != NULL && (n = map->capacity) > 0 && (first = tab[(n - 1) & (h = hash(key, map->ignorecase))]) != NULL)
    {
        if (first->hash == h && ((k = first->key) == key || (key != NULL && (map->ignorecase ? strcasecmp(key, k) : strcmp(key, k)) == 0)))
            return first;
        if ((e = first->next) != NULL)
        {
            do
            {
                if (e->hash == h && ((k = e->key) == key || (key != NULL && (map->ignorecase ? strcasecmp(key, k) : strcmp(key, k)) == 0)))
                    return e;
            } while ((e = e->next) != NULL);
        }
    }
    return NULL;
}

char *MAP_get(MAP *map, char *key)
{
    NODE *e;
    return (e = MAP_get_node(map, key)) == NULL ? NULL : e->value;
}

NODE *MAP_remove_node(MAP *map, int hash, char *key, char *value, char matchValue, char movable)
{
    NODE **tab;
    NODE *p;
    int n, index;
    if ((tab = map->table) != NULL && (n = map->capacity) > 0 && (p = tab[index = (n - 1) & hash]) != NULL)
    {
        NODE *node = NULL, *e;
        char *k;
        char *v;
        if (p->hash == hash && ((k = p->key) == key || (key != NULL && (map->ignorecase ? strcasecmp(key, k) : strcmp(key, k)) == 0)))
            node = p;
        else if ((e = p->next) != NULL)
        {
            do
            {
                if (e->hash == hash && ((k = e->key) == key || (key != NULL && (map->ignorecase ? strcasecmp(key, k) : strcmp(key, k)) == 0)))
                {
                    node = e;
                    break;
                }
                p = e;
            } while ((e = e->next) != NULL);
        }
        if (node != NULL && (!matchValue || (v = node->value) == value || (value != NULL && strcmp(value, v) == 0)))
        {
            if (node == p)
            {
                tab[index] = node->next;
            }
            else
            {
                p->next = node->next;
            }
            map->modcount++;
            MAP_free_cache(map);
            map->size--;
            return node;
        }
    }
    return NULL;
}

char *MAP_remove(MAP *map, char *key)
{
    NODE *e;
    if ((e = MAP_remove_node(map, hash(key, map->ignorecase), key, NULL, 0, 1)) == NULL)
        return NULL;
    char *value = e->value;
    free(e);
    return value;
}

int MAP_contains_key(MAP *map, char *key)
{
    return MAP_get_node(map, key) != NULL;
}

int MAP_contains_value(MAP *map, char *value)
{
    NODE **tab;
    char *v;
    if ((tab = map->table) != NULL && map->size > 0)
        for (int i = 0; i < map->capacity; i++)
            for (NODE *e = tab[i]; e != NULL; e = e->next)
                if ((v = e->value) == value || (value != NULL && strcmp(value, v) == 0))
                    return 1;
    return 0;
}

char *MAP_get_or_default(MAP *map, char *key, char *defaultValue)
{
    NODE *e;
    return (e = MAP_get_node(map, key)) == NULL ? defaultValue : e->value;
}

char *MAP_put_if_absent(MAP *map, char *key, char *value)
{
    return MAP_put_val(map, hash(key, map->ignorecase), key, value, 1, 1);
}

char *MAP_replace(MAP *map, char *key, char *value)
{
    NODE *e;
    if ((e = MAP_get_node(map, key)) != NULL)
    {
        char *oldValue = e->value;
        e->value = value;
        return oldValue;
    }
    return NULL;
}