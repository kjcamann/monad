#pragma once

#include <stddef.h>

struct mem_zone;

struct mem_zone_config
{
    char const *name;
    size_t size;
    size_t align;
};

int mem_zone_create(struct mem_zone_config const *, void *, struct mem_zone **);

void mem_zone_destroy(struct mem_zone *);

int mem_zone_alloc(struct mem_zone *, void **);

void mem_zone_free(struct mem_zone *, void *);
