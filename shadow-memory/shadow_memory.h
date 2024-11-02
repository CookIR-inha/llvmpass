//shadow_memory.h

#ifndef SHADOW_MEMORY_H
#define SHADOW_MEMORY_H

#include <stdint.h>
#include <stddef.h>

void allocate_shadow_memory();

void free_shadow_memory();

static inline int8_t* get_shadow_address(void* addr);

static inline size_t get_shadow_block_offset(void* addr);

static inline size_t get_shadow_size(size_t size);

void* wrapper_malloc(size_t size);

void wrapper_free(void* addr, size_t size);

void report_error(void* addr, size_t size, int8_t enc);

void validate_memory_access(void* addr, int32_t size);

#endif