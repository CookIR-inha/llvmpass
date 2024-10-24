// shadow_memory.c
//아직 테스트되지 않음
//#include "shadow_memory.h"
#include <stdio.h>
#include <sys/mman.h>
#include <unistd.h>
#include <stdint.h>
#include <errno.h>
#include <string.h>

#define SHADOW_SCALE 3
#define SHADOW_OFFSET 0x100000000000ULL // 2^44
#define SHADOW_SIZE 1ULL << (47 - SHADOW_SCALE) // 2^44 bytes (16TiB)
//#define SHADOW_SIZE (1ULL << 32) //큰 사이즈 할당시 에러나서 일단 작은 사이즈로 대체

//섀도우 메모리 포인터
static int8_t* shadow_memory = (int8_t*)SHADOW_OFFSET;

void allocate_shadow_memory() {
    void* addr = mmap(
        shadow_memory,
        SHADOW_SIZE,
        PROT_READ | PROT_WRITE,
        MAP_PRIVATE | MAP_ANONYMOUS | MAP_NORESERVE | MAP_FIXED_NOREPLACE,
        -1,
        0
    );

    if (addr == MAP_FAILED) {
        fprintf(stderr, "%s[errno:%d]\n", strerror(errno), errno);
        _exit(1);
    }

    if (addr != shadow_memory) {
        fprintf(stderr, "Shadow memory mapped at wrong address.\n");
        munmap(addr, SHADOW_SIZE);
        _exit(1);
    }
}

//해제할 필요가 있는지 의문(프로세스 종료할때까지 사용할꺼니까..)
void free_shadow_memory() {
    munmap(shadow_memory, SHADOW_SIZE);
}

//프로그램 메모리 주소 받아서 섀도우 메모리 주소 계산
static inline int8_t* get_shadow_address(void* addr) {
    return shadow_memory + (((uintptr_t)addr) >> SHADOW_SCALE);
}

//프로그램 메모리 주소가 매핑된 섀도우 메모리 블록의 몇번째 요소인지 리턴(0~7)
static inline size_t get_shadow_block_offset(void* addr) {
    return ((uintptr_t)addr) & ((1 << SHADOW_SCALE) - 1);
}

//프로그램 메모리 크기를 섀도우 메모리 크기로 변환
static inline size_t get_shadow_size(size_t size) {
    return ((size - 1) >> SHADOW_SCALE) + 1;
}

//우선 malloc먼저 구현(calloc, realloc, aligned_alloc, valloc, posix_memalign??)
void* wrapper_malloc(size_t size) {
    void* addr = malloc(size); //8바이트 정렬된 주소로 할당
    if (addr) {
        int8_t* shadow_addr = get_shadow_address(addr);

        /*validate_memory_access의 논리를 그대로 가져오기.
        하지만 8바이트 정렬된 주소이기 때문에 좀 단순함
        앞부분은 8로 memset하면 되고
        마지막 영역은 8로 나눈 나머지만큼을 값 세팅
        예를들어 28바이트 할당이면
        24바이트에 해당하는 3바이트는 8로 채우고, 나머지 4바이트에 해당하는 1바이트는 4로 세팅*/

        //몫, 나머지
        size_t shadow_full_size = size >> SHADOW_SCALE;
        size_t shadow_remainder_size = size & ((1 << SHADOW_SCALE) - 1);

        if (shadow_full_size) memset(shadow_addr, 8, shadow_full_size);
        if (shadow_remainder_size) memset(shadow_addr + shadow_full_size, shadow_remainder_size, 1);
    }
    return addr;
}

//pass가 적용될 소스코드의 free함수에는 size가 전달되지 않음. softbound에 사용할 메타데이터를 이용해 size를 알아내야 할 듯
//double free도 감지 가능?
void wrapper_free(void* addr, size_t size) {
    free(addr);
    if (addr) {
        int8_t* shadow_addr = get_shadow_address(addr);
        size_t shadow_size = get_shadow_size(size);

        memset(shadow_addr, -1, shadow_size);
    }
}

void validate_memory_access(void* addr, size_t size) {
    int8_t* shadow_addr = get_shadow_address(addr);
    size_t shadow_block_offset = get_shadow_block_offset(addr);
    //size_t shadow_size = get_shadow_size(size); //필요없음

    //인코딩정의에 따른 처리
    //8이면 8바이트 전부 접근 가능
    //1~8이면 첫 k바이트만 접근 가능
    //k == 0이면 할당되지 않은 영역(접근 불가)
    //k == -1이면 해제된 영역(접근 불가)

    //addr이 몇 번째 바이트에 접근하는지도 고려해야 함
    
    //첫번째 블록에서 유효해야 하는 바이트 크기
    size_t first_bytes = shadow_block_offset + size;
    if (first_bytes > 8) first_bytes = 8;
    
    if (first_bytes > shadow_addr[0]) {
        fprintf(stderr, "Invalid memory access at %p\n", addr);
        _exit(1);
    }

    if (first_bytes == 8) {
        size = size - (8 - shadow_block_offset);
    }
    else {
        size = 0;
    }
    
    size_t i = 1;
    for (; size >= 8; i++, size -= 8) {
         if (shadow_addr[i] != 8) {
            fprintf(stderr, "Invalid memory access at %p\n", addr);
            _exit(1);
        }
    }

    if (size > shadow_addr[i]) {
        fprintf(stderr, "Invalid memory access at %p\n", addr);
        _exit(1);
    }
}
