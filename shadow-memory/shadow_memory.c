// shadow_memory.c
//아직 테스트되지 않음
#include "shadow_memory.h"
#include <stdio.h>
#include <sys/mman.h>
#include <unistd.h>
#include <errno.h>
#include <string.h>

#define SHADOW_SCALE 3
#define SHADOW_OFFSET 0x100000000000ULL // 2^44
#define SHADOW_SIZE 1ULL << (47 - SHADOW_SCALE) // 2^44 bytes (16TiB)
//#define SHADOW_SIZE (1ULL << 32) //큰 사이즈 할당시 에러나서 일단 작은 사이즈로 대체

//섀도우 메모리 포인터
static uint8_t* shadow_memory = (uint8_t*)SHADOW_OFFSET;

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

    //memset(shadow_memory, -1, SHADOW_SIZE);
    //메모리 사용량 많아서 프로세스 죽음(Killed 뜸). how?
    //일단 인코딩 정의 변경해봄.
}

//해제할 필요가 있는지 의문(프로세스 종료할때까지 사용할꺼니까..)
void free_shadow_memory() {
    munmap(shadow_memory, SHADOW_SIZE);
}

static inline uint8_t* get_shadow_address(void* addr) {
    return shadow_memory + (((uintptr_t)addr) >> SHADOW_SCALE);
}

static inline uint8_t get_shadow_block_offset(void* addr) {
    return ((uintptr_t)addr) & ((1 << SHADOW_OFFSET) - 1);
}

static inline size_t get_shadow_size(size_t size) {
    return ((size - 1) >> SHADOW_SCALE) + 1;
}

//우선 malloc먼저 구현(calloc, realloc, aligned_alloc, valloc, posix_memalign??)
void* wrapper_malloc(size_t size) {
    void* addr = malloc(size); //8바이트 정렬된 주소로 할당
    if (addr) {
        uint8_t* shadow_addr = get_shadow_address(addr);
        size_t shadow_size = get_shadow_size(size);


        //반복문 필요?
        uint8_t encoding =  size & ((1 << SHADOW_SCALE) - 1);
        memset(shadow_addr, 0, shadow_size);
    }
    return addr;
}

//pass가 적용될 소스코드의 free함수에는 size가 전달되지 않음. softbound에 사용할 메타데이터를 이용해 size를 알아내야 할 듯
void wrapper_free(void* addr, size_t size) {
    if (addr) {
        uint8_t* shadow_addr = get_shadow_address(addr);
        size_t shadow_size = get_shadow_size(size);

        //생각
        memset(shadow_addr, 0, shadow_size);
        free(addr);
    }
}

void validate_memory_access(void* addr, size_t size) {
    uint8_t* shadow_addr = get_shadow_address(addr);
    uint8_t shadow_block_offset = get_shadow_block_offset(addr);
    size_t shadow_size = get_shadow_size(size);

    //인코딩정의에 따른 처리
    //8이면 8바이트 전부 접근 가능
    //1~8이면 첫 k바이트만 접근 가능
    //k == 0이면 할당되지 않은 영역(접근 불가)
    //k == -1이면 해제된 영역(접근 불가)

    //addr이 몇 번째 바이트에 접근하는지도 고려해야 함
    //
    for (size_t i = 0; i < shadow_size - 1; i++) {
         if (shadow_addr[i] != 8) {
            fprintf(stderr, "Invalid memory access at %p\n", addr);
            _exit(1);
        }
    }
}
