//shadow_memory.c
//gcc -fPIC -shared -o libshadow_memory.so shadow_memory.c
#include "shadow_memory.h"
#include <stdio.h>
#include <sys/mman.h>
#include <unistd.h>
#include <errno.h>
#include <string.h>
#include <stdlib.h>

#define SHADOW_SCALE 3
#define SHADOW_OFFSET 0x100000000000ULL // 2^44
#define SHADOW_SIZE 1ULL << (47 - SHADOW_SCALE) // 2^44 bytes (16TiB)

//섀도우 메모리 포인터
static int8_t* shadow_memory = (int8_t*)SHADOW_OFFSET;

//섀도우 메모리 할당(초기에 호출되어야 함)
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

//섀도우 메모리 해제(프로그램 종료시에 호출. 어차피 종료할건데 호출할 필요가 있는지 모르겠음)
void free_shadow_memory() {
    munmap(shadow_memory, SHADOW_SIZE);
}

//프로그램 메모리 주소 받아서 섀도우 메모리 주소 계산
static inline int8_t* get_shadow_address(void* addr) {
    return shadow_memory + (((uintptr_t)addr) >> SHADOW_SCALE);
}

//프로그램 메모리 주소가 섀도우 메모리 블록의 8바이트 중 몇번째에 해당하는지 리턴(0~7)
//즉, 메모리 주소를 8로 나눈 나머지
static inline size_t get_shadow_block_offset(void* addr) {
    return ((uintptr_t)addr) & ((1 << SHADOW_SCALE) - 1);
}

//프로그램 메모리 크기를 섀도우 메모리 크기로 변환
//1-8이면 1, 9-16이면 2 ...
static inline size_t get_shadow_size(size_t size) {
    return ((size - 1) >> SHADOW_SCALE) + 1;
}

//우선 malloc먼저 구현(calloc, realloc, aligned_alloc, valloc, posix_memalign??)
void* wrapper_malloc(size_t size) {
    void* addr = malloc(size); //8바이트 정렬된 주소로 할당
    if (addr) {
        int8_t* shadow_addr = get_shadow_address(addr);

        //8로 나눈 몫과 나머지
        size_t shadow_full_size = size >> SHADOW_SCALE;
        size_t shadow_remainder_size = size & ((1 << SHADOW_SCALE) - 1);

        //완전한 8바이트 블록은 인코딩 값 8로 채우고, 나머지 한 블록은 남은 바이트 수가 인코딩 값임
        if (shadow_full_size) memset(shadow_addr, 8, shadow_full_size);
        if (shadow_remainder_size) shadow_addr[shadow_full_size] = shadow_remainder_size;

        /*예를들어 26바이트 할당인 경우
        26 = 8*3 + 2 이므로
        인코딩 값: [8, 8, 8, 2]*/
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
        
        //섀도우 메모리에 할당 해제됨을 표시
        memset(shadow_addr, -1, shadow_size);
    }
}


/*
인코딩 정의
섀도우 바이트의 값 k
k = 0이면 할당되지 않은 영역(접근 불가)
1 <= k <= 8이면 첫 k바이트만 접근 가능(8이면 8바이트 전체 접근 가능)
k = -1이면 해제된 영역(접근 불가)
*/

//메모리 접근을 검증(메모리 접근 명령어 앞에 삽입되어야 하는 함수)
void validate_memory_access(void* addr, int32_t size) {
    int8_t* shadow_addr = get_shadow_address(addr);
    size_t shadow_block_offset = get_shadow_block_offset(addr);
    
    /*
    메모리 접근은 할당과 달리 8바이트 정렬이 보장되지 않음
    다양한 메모리 접근 case가 있음(1블록 접근, 여러 블록 접근, 8바이트 정렬된 접근, 정렬되지 않은 접근..)
    따라서 일반화를 위해 첫 블록, 중간 블록, 마지막 블록으로 나누어 처리해야 함
    예시)
    섀도우 메모리 오프셋: 0x0
    메모리 접근 주소와 사이즈: 0x4, 32byte
    전체 접근 주소: 0x04-0x23 (32byte)
    첫 블록의 접근 주소: 0x4-0x7 (4byte)
    중간 블록의 접근 주소: 0x8-0xf, 0x10-0x17, 0x18-0x1f (24byte)
    마지막 블록의 접근 주소: 0x20-0x23 (4byte)

    이 경우 첫 블록에서는 마지막 4바이트만 접근하지만
    할당할 때 8바이트 정렬된 주소로부터 연속으로 할당되었으므로 해당 블록의 8바이트 전체가 유효해야만 접근 가능함
    중간 블록의 경우 항상 8바이트 전체가 유효해야 접근 가능함
    마지막 블록의 경우 첫 4바이트만 유효하면 접근 가능함
    */

    //첫 블록에서 유효해야 하는 바이트 크기
    int32_t first_bytes = shadow_block_offset + size;
    if (first_bytes > 8) first_bytes = 8;
    
    //접근 가능한지 확인
    if (first_bytes > shadow_addr[0]) {
        fprintf(stderr, "Invalid memory access at %p\n", addr);
        _exit(1);
    }

    //첫 블록에서 접근한 만큼 빼줌.
    if (first_bytes == 8) {
        size = size - (8 - shadow_block_offset);
    }
    else {//접근 영역 전체가 1블록을 초과하지 않는다면 더 이상 진행할 필요 없으므로 size = 0
        size = 0;
    }
    
    //중간 블록에 대해 접근 가능한지 확인
    size_t i = 1;
    for (; size >= 8; i++, size -= 8) {
         if (shadow_addr[i] != 8) {
            fprintf(stderr, "Invalid memory access at %p\n", addr);
            _exit(1);
        }
    }

    //마지막 블록에 대해 접근 가능한지 확인
    if (size > shadow_addr[i]) {
        fprintf(stderr, "Invalid memory access at %p\n", addr);
        _exit(1);
    }
}
