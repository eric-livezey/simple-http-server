#include <stdlib.h>
#include <string.h>
#include <ctype.h>
#include "utils.h"

// Adapted from the JDK java.util.HashMap class

#define DEFAULT_INITIAL_CAPACITY (1 << 4)
#define MAXIMUM_CAPACITY (1 << 30)
#define DEFAULT_LOAD_FACTOR 0.75f

struct entry
{
    char *key;
    void *value;
};

typedef struct node_s
{
    int hash;
    char *key;
    void *value;
    struct node_s *next;
} NODE;

typedef struct hashmap_s
{
    struct entry **entry_set;
    char **key_set;
    void **values;
    NODE **table;
    int capacity;
    int size;
    int threshold;
    float load_factor;
    bool ignore_case;
} MAP;

int hash(char *s, bool lower)
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

NODE *MAP_NODE_new(int hash, char *key, void *value, NODE *next)
{
    NODE *node = malloc(sizeof(NODE));
    node->hash = hash;
    node->key = key;
    node->value = value;
    node->next = next;
    return node;
}

MAP *MAP_new_r(float load_factor, int initial_capacity, bool ignore_case)
{
    MAP *map = malloc(sizeof(MAP));
    map->entry_set = NULL;
    map->key_set = NULL;
    map->values = NULL;
    map->table = NULL;
    map->capacity = 0;
    map->size = 0;
    map->load_factor = load_factor;
    map->threshold = table_size_for(initial_capacity);
    map->ignore_case = ignore_case;
    return map;
}

MAP *MAP_new()
{
    return MAP_new_r(DEFAULT_LOAD_FACTOR, DEFAULT_INITIAL_CAPACITY, false);
}

MAP *MAP_new_ignore_case()
{
    return MAP_new_r(DEFAULT_LOAD_FACTOR, DEFAULT_INITIAL_CAPACITY, true);
}

int MAP_size(MAP *map)
{
    return map->size;
}

void MAP_free_cache(MAP *map)
{
    if (map->entry_set != NULL)
    {
        for (int i = 0; i < map->size; i++)
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

void MAP_clear(MAP *map)
{
    NODE **tab;
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
    NODE **old_tab = map->table;
    int old_cap = (old_tab == NULL) ? 0 : map->capacity;
    int old_thr = map->threshold;
    int new_cap, new_thr = 0;
    if (old_cap > 0)
    {
        if (old_cap >= MAXIMUM_CAPACITY)
        {
            map->threshold = __INT_MAX__;
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
        new_thr = (int)(DEFAULT_LOAD_FACTOR * DEFAULT_INITIAL_CAPACITY);
    }
    if (new_thr == 0)
    {
        float ft = (float)new_cap * map->load_factor;
        new_thr = (new_cap < MAXIMUM_CAPACITY && ft < (float)MAXIMUM_CAPACITY ? (int)ft : __INT_MAX__);
    }
    map->threshold = new_thr;
    NODE **new_tab = calloc(new_cap, sizeof(NODE *));
    map->table = new_tab;
    map->capacity = new_cap;
    if (old_tab != NULL)
    {
        for (int j = 0; j < old_cap; j++)
        {
            NODE *e;
            if ((e = old_tab[j]) != NULL)
            {
                old_tab[j] = NULL;
                if (e->next == NULL)
                    new_tab[e->hash & (new_cap - 1)] = e;
                else
                { // preserve order
                    NODE *lo_head = NULL, *lo_tail = NULL;
                    NODE *hi_head = NULL, *hi_tail = NULL;
                    NODE *next;
                    do
                    {
                        next = e->next;
                        if ((e->hash & old_cap) == 0)
                        {
                            if (lo_tail == NULL)
                                lo_head = e;
                            else
                                lo_tail->next = e;
                            lo_tail = e;
                        }
                        else
                        {
                            if (hi_tail == NULL)
                                hi_head = e;
                            else
                                hi_tail->next = e;
                            hi_tail = e;
                        }
                    } while ((e = next) != NULL);
                    if (lo_tail != NULL)
                    {
                        lo_tail->next = NULL;
                        new_tab[j] = lo_head;
                    }
                    if (hi_tail != NULL)
                    {
                        hi_tail->next = NULL;
                        new_tab[j + old_cap] = hi_head;
                    }
                }
            }
        }
        free(old_tab);
    }
    return new_tab;
}

struct entry **MAP_entry_set(MAP *map)
{
    struct entry **es;
    if ((es = map->entry_set) == NULL)
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
            map->entry_set = es;
        }
    }
    return es;
}

char **MAP_key_set(MAP *map)
{
    char **ks;
    if ((ks = map->key_set) != NULL)
    {
        struct entry **es;
        if ((es = MAP_entry_set(map)) != NULL)
        {
            char **ks = malloc(map->size * sizeof(char *));
            for (int i = 0; i < map->size; i++)
                ks[i] = es[i]->key;
            map->key_set = ks;
        }
    }
    return ks;
}

void **MAP_values(MAP *map)
{
    struct entry **es;
    if ((es = MAP_entry_set(map)) != NULL)
    {
        void **vals = malloc(map->size * sizeof(void *));
        for (int i = 0; i < map->size; i++)
            vals[i] = es[i]->value;
        map->values = vals;
        return vals;
    }
    return NULL;
}

void *MAP_put_val(MAP *map, int hash, char *key, void *value, bool only_if_absent)
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
        tab[i] = MAP_NODE_new(hash, key, value, NULL);
    }
    else
    {
        NODE *e;
        char *k;
        if (p->hash == hash && ((k = p->key) == key || (key != NULL && (map->ignore_case ? strcasecmp(key, k) : strcmp(key, k)) == 0)))
            e = p;
        else
        {
            for (int bin_count = 0;; bin_count++)
            {
                if ((e = p->next) == NULL)
                {
                    p->next = MAP_NODE_new(hash, key, value, NULL);
                    break;
                }
                if (e->hash == hash && ((k = e->key) == key || (key != NULL && (map->ignore_case ? strcasecmp(key, k) : strcmp(key, k)) == 0)))
                    break;
                p = e;
            }
        }
        if (e != NULL)
        { // existing mapping for key
            void *old_value = e->value;
            if (!only_if_absent || old_value == NULL)
                e->value = value;
            return old_value;
        }
    }
    MAP_free_cache(map);
    if (map->size++ > map->threshold)
        MAP_resize(map);
    return NULL;
}

void *MAP_put(MAP *map, char *key, void *value)
{
    return MAP_put_val(map, hash(key, map->ignore_case), key, value, false);
}

void MAP_put_map_entries(MAP *map, MAP *m)
{
    int s = m->size;
    if (s > 0)
    {
        if (map->table == NULL)
        { // pre-size
            float ft = ((float)s / map->load_factor) + 1.0F;
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
            MAP_put_val(map, hash(e->key, map->ignore_case), e->key, e->value, false);
        }
    }
}

void MAP_put_all(MAP *map, MAP *m)
{
    MAP_put_map_entries(map, m);
}

NODE *MAP_get_node(MAP *map, char *key)
{
    NODE **tab;
    NODE *first, *e;
    int n, h;
    char *k;
    if ((tab = map->table) != NULL && (n = map->capacity) > 0 && (first = tab[(n - 1) & (h = hash(key, map->ignore_case))]) != NULL)
    {
        if (first->hash == h && ((k = first->key) == key || (key != NULL && (map->ignore_case ? strcasecmp(key, k) : strcmp(key, k)) == 0)))
            return first;
        if ((e = first->next) != NULL)
        {
            do
            {
                if (e->hash == h && ((k = e->key) == key || (key != NULL && (map->ignore_case ? strcasecmp(key, k) : strcmp(key, k)) == 0)))
                    return e;
            } while ((e = e->next) != NULL);
        }
    }
    return NULL;
}

void *MAP_get(MAP *map, char *key)
{
    NODE *e;
    return (e = MAP_get_node(map, key)) == NULL ? NULL : e->value;
}

NODE *MAP_remove_node(MAP *map, int hash, char *key, void *value, bool match_value)
{
    NODE **tab;
    NODE *p;
    int n, index;
    if ((tab = map->table) != NULL && (n = map->capacity) > 0 && (p = tab[index = (n - 1) & hash]) != NULL)
    {
        NODE *node = NULL, *e;
        char *k;
        void *v;
        if (p->hash == hash && ((k = p->key) == key || (key != NULL && (map->ignore_case ? strcasecmp(key, k) : strcmp(key, k)) == 0)))
            node = p;
        else if ((e = p->next) != NULL)
        {
            do
            {
                if (e->hash == hash && ((k = e->key) == key || (key != NULL && (map->ignore_case ? strcasecmp(key, k) : strcmp(key, k)) == 0)))
                {
                    node = e;
                    break;
                }
                p = e;
            } while ((e = e->next) != NULL);
        }
        if (node != NULL && (!match_value || (v = node->value) == value || (value != NULL && strcmp(value, v) == 0)))
        {
            if (node == p)
            {
                tab[index] = node->next;
            }
            else
            {
                p->next = node->next;
            }
            MAP_free_cache(map);
            map->size--;
            return node;
        }
    }
    return NULL;
}

void *MAP_remove(MAP *map, char *key)
{
    NODE *e;
    if ((e = MAP_remove_node(map, hash(key, map->ignore_case), key, NULL, false)) == NULL)
        return NULL;
    void *value = e->value;
    free(e);
    return value;
}

int MAP_contains_key(MAP *map, char *key)
{
    return MAP_get_node(map, key) != NULL;
}

int MAP_contains_value(MAP *map, void *value)
{
    NODE **tab;
    void *v;
    if ((tab = map->table) != NULL && map->size > 0)
        for (int i = 0; i < map->capacity; i++)
            for (NODE *e = tab[i]; e != NULL; e = e->next)
                if ((v = e->value) == value || (value != NULL && strcmp(value, v) == 0))
                    return 1;
    return 0;
}

void *MAP_get_or_default(MAP *map, char *key, void *default_value)
{
    NODE *e;
    return (e = MAP_get_node(map, key)) == NULL ? default_value : e->value;
}

void *MAP_put_if_absent(MAP *map, char *key, void *value)
{
    return MAP_put_val(map, hash(key, map->ignore_case), key, value, true);
}

void *MAP_replace(MAP *map, char *key, void *value)
{
    NODE *e;
    if ((e = MAP_get_node(map, key)) != NULL)
    {
        void *old_value = e->value;
        e->value = value;
        return old_value;
    }
    return NULL;
}