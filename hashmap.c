#include <ctype.h>
#include <string.h>
#include <stdlib.h>
#include "utils.h"

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

int hash(char *s)
{
    int h = 0;
    for (int i = 0; s[i] != '\0'; i++)
        // case insensitive
        h = 31 * h + tolower(s[i]);
    return h;
}

int table_size_for(int cap)
{
    int n = -1 >> (((int)(log2ceil(cap)) - 31) * -1);
    return (n < 0) ? 1 : (n >= MAXIMUM_CAPACITY) ? MAXIMUM_CAPACITY
                                                 : n + 1;
}

int node_init(int hash, char *key, char *value, node_t *next, node_t *node)
{
    node->hash = hash;
    node->key = key;
    node->value = value;
    node->next = next;
    return 0;
}

int hashmap_init(hashmap_t *hashmap)
{
    hashmap->entryset = NULL;
    hashmap->keyset = NULL;
    hashmap->values = NULL;
    hashmap->table = NULL;
    hashmap->capacity = 0;
    hashmap->size = 0;
    hashmap->modcount = 0;
    hashmap->loadfactor = DEFAULT_LOAD_FACTOR;
    hashmap->threshold = table_size_for(DEFAULT_INITIAL_CAPACITY);
    return 0;
}

void hashmap_destroy_cache(hashmap_t *map)
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

void hashmap_clear(hashmap_t *map)
{
    node_t **tab;
    map->modcount++;
    if ((tab = map->table) != NULL && map->size > 0)
    {
        hashmap_destroy_cache(map);
        map->size = 0;
        for (int i = 0; i < map->capacity; i++)
        {
            if (tab[i] != NULL)
            {
                for (node_t *e = tab[i]; e != NULL; e = e->next)
                    free(e);
                tab[i] = NULL;
            }
        }
    }
}

int hashmap_destroy(hashmap_t *map)
{
    node_t **tab;
    if ((tab = map->table) != NULL && map->size > 0)
    {
        hashmap_destroy_cache(map);
        for (int i = 0; i < map->capacity; i++)
            if (tab[i] != NULL)
                for (node_t *e = tab[i]; e != NULL; e = e->next)
                    free(e);
    }
    return 0;
}

node_t **hashmap_resize(hashmap_t *map)
{
    node_t **oldTab = map->table;
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
    node_t **newTab = calloc(newCap, sizeof(node_t *));
    map->table = newTab;
    map->capacity = newCap;
    if (oldTab != NULL)
    {
        for (int j = 0; j < oldCap; j++)
        {
            node_t *e;
            if ((e = oldTab[j]) != NULL)
            {
                oldTab[j] = NULL;
                if (e->next == NULL)
                    newTab[e->hash & (newCap - 1)] = e;
                else
                { // preserve order
                    node_t *loHead = NULL, *loTail = NULL;
                    node_t *hiHead = NULL, *hiTail = NULL;
                    node_t *next;
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

entry_t **hashmap_entry_set(hashmap_t *map)
{
    entry_t **es;
    if ((es = map->entryset) == NULL)
    {
        node_t **tab;
        int n;
        if ((tab = map->table) != NULL && (n = map->size) > 0)
        {
            es = malloc(n * sizeof(entry_t *));
            int j = 0;
            for (int i = 0; i < map->capacity; i++)
            {
                for (node_t *e = tab[i]; e != NULL; e = e->next, j++)
                {
                    es[j] = malloc(sizeof(entry_t));
                    es[j]->key = e->key;
                    es[j]->value = e->value;
                }
            }
            map->entryset = es;
        }
    }
    return es;
}

char **hashmap_key_set(hashmap_t *map)
{
    char **ks;
    if ((ks = map->keyset) != NULL)
    {
        entry_t **es;
        if ((es = hashmap_entry_set(map)) != NULL)
        {
            char **ks = malloc(map->size * sizeof(char *));
            for (int i = 0; i < map->size; i++)
                ks[i] = es[i]->key;
            map->keyset = ks;
        }
    }
    return ks;
}

char **hashmap_values(hashmap_t *map)
{
    entry_t **es;
    if ((es = hashmap_entry_set(map)) != NULL)
    {
        char **vals = malloc(map->size * sizeof(char *));
        for (int i = 0; i < map->size; i++)
            vals[i] = es[i]->value;
        map->values = vals;
        return vals;
    }
    return NULL;
}

char *hashmap_put_val(hashmap_t *map, int hash, char *key, char *value, int onlyIfAbsent, int evict)
{
    node_t **tab;
    int cap = 0;
    node_t *p;
    int n, i;
    if ((tab = map->table) == NULL || (n = map->capacity) == 0)
    {
        tab = hashmap_resize(map);
        n = map->capacity;
    }
    if ((p = tab[i = (n - 1) & hash]) == NULL)
    {
        tab[i] = malloc(sizeof(node_t));
        node_init(hash, key, value, NULL, tab[i]);
    }
    else
    {
        node_t *e;
        char *k;
        if (p->hash == hash && ((k = p->key) == key || (key != NULL && strcasecmp(key, k) == 0)))
            e = p;
        else
        {
            for (int binCount = 0;; binCount++)
            {
                if ((e = p->next) == NULL)
                {
                    p->next = malloc(sizeof(node_t));
                    node_init(hash, key, value, NULL, p->next);
                    break;
                }
                if (e->hash == hash && ((k = e->key) == key || (key != NULL && strcasecmp(key, k) == 0)))
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
    hashmap_destroy_cache(map);
    if (map->size++ > map->threshold)
        hashmap_resize(map);
    return NULL;
}

char *hashmap_put(hashmap_t *map, char *key, char *value)
{
    return hashmap_put_val(map, hash(key), key, value, 0, 1);
}

void hashmap_put_map_entries(hashmap_t *map, hashmap_t *m, int evict)
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
                hashmap_resize(map);
        }
        entry_t **es = hashmap_entry_set(m);
        for (int i = 0; i < m->size; i++)
        {
            entry_t *e = es[i];
            hashmap_put_val(map, hash(e->key), e->key, e->value, 0, evict);
        }
    }
}

void hashmap_put_all(hashmap_t *map, hashmap_t *m)
{
    hashmap_put_map_entries(map, m, 1);
}

node_t *hashmap_get_node(hashmap_t *map, char *key)
{
    node_t **tab;
    node_t *first, *e;
    int n, h;
    char *k;
    if ((tab = map->table) != NULL && (n = map->capacity) > 0 && (first = tab[(n - 1) & (h = hash(key))]) != NULL)
    {
        if (first->hash == h && ((k = first->key) == key || (key != NULL && strcasecmp(key, k) == 0)))
            return first;
        if ((e = first->next) != NULL)
        {
            do
            {
                if (e->hash == h && ((k = e->key) == key || (key != NULL && strcasecmp(key, k) == 0)))
                    return e;
            } while ((e = e->next) != NULL);
        }
    }
    return NULL;
}

char *hashmap_get(hashmap_t *map, char *key)
{
    node_t *e;
    return (e = hashmap_get_node(map, key)) == NULL ? NULL : e->value;
}

node_t *hashmap_remove_node(hashmap_t *map, int hash, char *key, char *value, int matchValue, int movable)
{
    node_t **tab;
    node_t *p;
    int n, index;
    if ((tab = map->table) != NULL && (n = map->capacity) > 0 && (p = tab[index = (n - 1) & hash]) != NULL)
    {
        node_t *node = NULL, *e;
        char *k;
        char *v;
        if (p->hash == hash && ((k = p->key) == key || (key != NULL && strcasecmp(key, k) == 0)))
            node = p;
        else if ((e = p->next) != NULL)
        {
            do
            {
                if (e->hash == hash && ((k = e->key) == key || (key != NULL && strcasecmp(key, k) == 0)))
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
            hashmap_destroy_cache(map);
            map->size--;
            return node;
        }
    }
    return NULL;
}

char *hashmap_remove(hashmap_t *map, char *key)
{
    node_t *e;
    if ((e = hashmap_remove_node(map, hash(key), key, NULL, 0, 1)) == NULL)
        return NULL;
    char *value = e->value;
    free(e);
    return value;
}

int hashmap_contains_key(hashmap_t *map, char *key)
{
    return hashmap_get_node(map, key) != NULL;
}

int hashmap_contains_value(hashmap_t *map, char *value)
{
    node_t **tab;
    char *v;
    if ((tab = map->table) != NULL && map->size > 0)
        for (int i = 0; i < map->capacity; i++)
            for (node_t *e = tab[i]; e != NULL; e = e->next)
                if ((v = e->value) == value || (value != NULL && strcmp(value, v) == 0))
                    return 1;
    return 0;
}

char *hashmap_get_or_default(hashmap_t *map, char *key, char *defaultValue)
{
    node_t *e;
    return (e = hashmap_get_node(map, key)) == NULL ? defaultValue : e->value;
}

char *hashmap_put_if_absent(hashmap_t *map, char *key, char *value)
{
    return hashmap_put_val(map, hash(key), key, value, 1, 1);
}

char *hashmap_replace(hashmap_t *map, char *key, char *value)
{
    node_t *e;
    if ((e = hashmap_get_node(map, key)) != NULL)
    {
        char *oldValue = e->value;
        e->value = value;
        return oldValue;
    }
    return NULL;
}