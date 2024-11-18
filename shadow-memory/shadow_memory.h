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

void set_shadow_enc_alloc(void* addr, size_t size);

void set_shadow_enc_free(void* addr, size_t size);

void after_malloc(void* addr, size_t size);

void after_calloc(void* addr, size_t num, size_t size);

void after_realloc(void* old_addr, void* new_addr, size_t old_size, size_t new_size);

void after_posix_memalign(int result, void* addr, size_t size);

void after_free(void* addr, size_t size);


//void* wrapper_malloc(size_t size);
//void* wrapper_calloc(size_t num, size_t size);

//void wrapper_free(void* addr, size_t size);

void report_error(void* start_address, size_t size, int8_t* faulty_shadow_addr);

void validate_memory_access(void* addr, int32_t size);

#endif