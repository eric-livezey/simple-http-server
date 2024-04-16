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
    return (n < 0) ? 1 : (n >= MAXIMUM_CAPACITY) ? MAXIMUM_CAPACITY : n + 1;
}

void node_init(int hash, char *key, char *value, hashmap_node *next, hashmap_node *node)
{
    node->hash = hash;
    node->key = key;
    node->value = value;
    node->next = next;
}

void hashmap_init(hashmap *hashmap, char ignorecase)
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
    hashmap->ignorecase = ignorecase;
}

void hashmap_free_cache(hashmap *map)
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

void hashmap_clear(hashmap *map)
{
    hashmap_node **tab;
    map->modcount++;
    if ((tab = map->table) != NULL && map->size > 0)
    {
        hashmap_free_cache(map);
        map->size = 0;
        for (int i = 0; i < map->capacity; i++)
        {
            if (tab[i] != NULL)
            {
                for (hashmap_node *e = tab[i]; e != NULL; e = e->next)
                    free(e);
                tab[i] = NULL;
            }
        }
    }
}

void hashmap_free_all(hashmap *map)
{
    hashmap_node **tab;
    if ((tab = map->table) != NULL && map->size > 0)
    {
        hashmap_free_cache(map);
        for (int i = 0; i < map->capacity; i++)
            if (tab[i] != NULL)
                for (hashmap_node *e = tab[i]; e != NULL; e = e->next)
                    free(e);
    }
}

hashmap_node **hashmap_resize(hashmap *map)
{
    hashmap_node **oldTab = map->table;
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
    hashmap_node **newTab = calloc(newCap, sizeof(hashmap_node *));
    map->table = newTab;
    map->capacity = newCap;
    if (oldTab != NULL)
    {
        for (int j = 0; j < oldCap; j++)
        {
            hashmap_node *e;
            if ((e = oldTab[j]) != NULL)
            {
                oldTab[j] = NULL;
                if (e->next == NULL)
                    newTab[e->hash & (newCap - 1)] = e;
                else
                { // preserve order
                    hashmap_node *loHead = NULL, *loTail = NULL;
                    hashmap_node *hiHead = NULL, *hiTail = NULL;
                    hashmap_node *next;
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

entry **hashmap_entry_set(hashmap *map)
{
    entry **es;
    if ((es = map->entryset) == NULL)
    {
        hashmap_node **tab;
        int n;
        if ((tab = map->table) != NULL && (n = map->size) > 0)
        {
            es = malloc(n * sizeof(entry *));
            int j = 0;
            for (int i = 0; i < map->capacity; i++)
            {
                for (hashmap_node *e = tab[i]; e != NULL; e = e->next, j++)
                {
                    es[j] = malloc(sizeof(entry));
                    es[j]->key = e->key;
                    es[j]->value = e->value;
                }
            }
            map->entryset = es;
        }
    }
    return es;
}

char **hashmap_key_set(hashmap *map)
{
    char **ks;
    if ((ks = map->keyset) != NULL)
    {
        entry **es;
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

char **hashmap_values(hashmap *map)
{
    entry **es;
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

char *hashmap_put_val(hashmap *map, int hash, char *key, char *value, int onlyIfAbsent, int evict)
{
    hashmap_node **tab;
    int cap = 0;
    hashmap_node *p;
    int n, i;
    if ((tab = map->table) == NULL || (n = map->capacity) == 0)
    {
        tab = hashmap_resize(map);
        n = map->capacity;
    }
    if ((p = tab[i = (n - 1) & hash]) == NULL)
    {
        tab[i] = malloc(sizeof(hashmap_node));
        node_init(hash, key, value, NULL, tab[i]);
    }
    else
    {
        hashmap_node *e;
        char *k;
        if (p->hash == hash && ((k = p->key) == key || (key != NULL && (map->ignorecase ? strcasecmp(key, k) : strcmp(key, k)) == 0)))
            e = p;
        else
        {
            for (int binCount = 0;; binCount++)
            {
                if ((e = p->next) == NULL)
                {
                    p->next = malloc(sizeof(hashmap_node));
                    node_init(hash, key, value, NULL, p->next);
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
    hashmap_free_cache(map);
    if (map->size++ > map->threshold)
        hashmap_resize(map);
    return NULL;
}

char *hashmap_put(hashmap *map, char *key, char *value)
{
    return hashmap_put_val(map, hash(key, map->ignorecase), key, value, 0, 1);
}

void hashmap_put_map_entries(hashmap *map, hashmap *m, int evict)
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
        entry **es = hashmap_entry_set(m);
        for (int i = 0; i < m->size; i++)
        {
            entry *e = es[i];
            hashmap_put_val(map, hash(e->key, map->ignorecase), e->key, e->value, 0, evict);
        }
    }
}

void hashmap_put_all(hashmap *map, hashmap *m)
{
    hashmap_put_map_entries(map, m, 1);
}

hashmap_node *hashmap_get_node(hashmap *map, char *key)
{
    hashmap_node **tab;
    hashmap_node *first, *e;
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

char *hashmap_get(hashmap *map, char *key)
{
    hashmap_node *e;
    return (e = hashmap_get_node(map, key)) == NULL ? NULL : e->value;
}

hashmap_node *hashmap_remove_node(hashmap *map, int hash, char *key, char *value, int matchValue, int movable)
{
    hashmap_node **tab;
    hashmap_node *p;
    int n, index;
    if ((tab = map->table) != NULL && (n = map->capacity) > 0 && (p = tab[index = (n - 1) & hash]) != NULL)
    {
        hashmap_node *node = NULL, *e;
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
            hashmap_free_cache(map);
            map->size--;
            return node;
        }
    }
    return NULL;
}

char *hashmap_remove(hashmap *map, char *key)
{
    hashmap_node *e;
    if ((e = hashmap_remove_node(map, hash(key, map->ignorecase), key, NULL, 0, 1)) == NULL)
        return NULL;
    char *value = e->value;
    free(e);
    return value;
}

int hashmap_contains_key(hashmap *map, char *key)
{
    return hashmap_get_node(map, key) != NULL;
}

int hashmap_contains_value(hashmap *map, char *value)
{
    hashmap_node **tab;
    char *v;
    if ((tab = map->table) != NULL && map->size > 0)
        for (int i = 0; i < map->capacity; i++)
            for (hashmap_node *e = tab[i]; e != NULL; e = e->next)
                if ((v = e->value) == value || (value != NULL && strcmp(value, v) == 0))
                    return 1;
    return 0;
}

char *hashmap_get_or_default(hashmap *map, char *key, char *defaultValue)
{
    hashmap_node *e;
    return (e = hashmap_get_node(map, key)) == NULL ? defaultValue : e->value;
}

char *hashmap_put_if_absent(hashmap *map, char *key, char *value)
{
    return hashmap_put_val(map, hash(key, map->ignorecase), key, value, 1, 1);
}

char *hashmap_replace(hashmap *map, char *key, char *value)
{
    hashmap_node *e;
    if ((e = hashmap_get_node(map, key)) != NULL)
    {
        char *oldValue = e->value;
        e->value = value;
        return oldValue;
    }
    return NULL;
}
