// memory_access_test.c
// gcc -o memory_access_test memory_access_test.c -L. -lshadow_memory
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "shadow_memory.h"

int main(int argc, char* argv[]) {
    if (argc != 5) {
        fprintf(stderr, "사용법: %s <할당 크기> <오프셋> <접근 크기> <free 여부 (0 또는 1)>\n", argv[0]);
        return 1;
    }

    size_t alloc_size = strtoull(argv[1], NULL, 0);
    size_t offset = strtoll(argv[2], NULL, 0); // 음수 오프셋을 위해 strtoll 사용
    size_t access_size = strtoull(argv[3], NULL, 0);
    int free_memory = atoi(argv[4]);

    // 섀도우 메모리 할당
    allocate_shadow_memory();

    // 메모리 할당
    void* base_addr = malloc(alloc_size);
    after_malloc(base_addr, alloc_size);

    if (free_memory) {
        // 메모리 해제
        free(base_addr);
        after_free(base_addr, alloc_size);
    }

    // 테스트할 주소 계산
    void* test_addr = (void*)((uintptr_t)base_addr + offset);

    // 접근 검사
    //printf("메모리 접근 검사: 할당 크기=%zu, 주소=%p, 크기=%zu\n", alloc_size, test_addr, access_size);
    validate_memory_access(test_addr, access_size);

    // 메모리 접근 (읽기/쓰기)
    //printf("메모리에 쓰기 시도...\n");
    memset(test_addr, 0xAA, access_size);

    //printf("메모리 접근 성공\n");

    // 프로그램 종료
    return 0;
}
