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

//섀도우 메모리에 인코딩 값 '할당됨'으로 설정(1-8)
void set_shadow_enc_alloc(void* addr, size_t size) {
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

//섀도우 메모리에 인코딩 값 '해제됨'으로 설정(-1)
void set_shadow_enc_free(void* addr, size_t size) {
    int8_t* shadow_addr = get_shadow_address(addr);
    size_t shadow_size = get_shadow_size(size);
        
    //섀도우 메모리에 할당 해제됨을 표시
    memset(shadow_addr, -1, shadow_size);
}

/*
메모리 할당, 해제 함수 호출 뒤에 삽입될 함수들
대상 소스코드의 할당, 해제 함수를 LLVM Pass를 이용해 감지하고 그 뒤에 삽입되어야 함
malloc, calloc, realloc, aligned_alloc, posix_memalign, free, new, new[], delete, delete[]에 대해 구현
valloc, pvalloc, memalign은 구식(obsolete)이기 때문에 구현하지 않음. 나중에 필요하다면 구현하면 됨
new, new[], delete, delete[]는 함수가 아니라 연산자
IR로 변환하면 @_Znwm, @_Znam, @_ZdlPv, @_ZdaPv 라는 함수호출로 변환됨
*/
//after malloc, aligned_alloc, @_Znwm(new), @_Znam(new[])
void after_malloc(void* addr, size_t size) {
    if (addr) {
        set_shadow_enc_alloc(addr, size);
    }
}

void after_calloc(void* addr, size_t num, size_t size) {
    if (addr) {
        set_shadow_enc_alloc(addr, num * size);
    }
}

//realloc은 기존 할당된 주소와 새로할당할 사이즈를 받아 재할당함
//shadow memory를 관리하기 위해서 기존 영역의 크기를 알아야 함
//realloc호출시 기존 영역의 크기는 전달되지 않으므로 after_realloc호출할 때 realloc으로 전달되는 포인터의 메타데이터 활용해서 크기(old_size) 전달해야 함
void after_realloc(void* old_addr, void* new_addr, size_t old_size, size_t new_size) {
    if (new_addr) {
        //재할당이므로 기존 영역은 해제됨으로 표시하고 새로 할당된 곳을 할당됨으로 표시 (같은 영역이어도 문제 없음)
        memset(get_shadow_address(old_addr), -1, get_shadow_size(old_size));
        set_shadow_enc_alloc(new_addr, new_size);
    }
}

void after_posix_memalign(int result, void* addr, size_t size) {
    if (result == 0) {
        set_shadow_enc_alloc(addr, size);
    }
}

//after free, @_ZdlPv(delete), @_ZdaPv(delete[])
//free호출시 기존 영역의 크기는 전달되지 않으므로 after_free호출할 때 free로 전달되는 포인터의 메타데이터 활용해서 크기 전달해야 함
void after_free(void* addr, size_t size) {
    if (addr) {
        set_shadow_enc_free(addr, size);
    }
}


/*할당 함수의 wrapper
대상 소스코드의 할당 함수를 LLVM Pass를 이용해 감지하고 wrapper함수로 변경
ex) malloc(size) -> wrapper_malloc(size)
malloc, calloc, realloc, aligned_alloc, posix_memalign을 구현
valloc, pvalloc, memalign은 구식(obsolete)이기 때문에 구현하지 않음. 나중에 필요하다면 구현하면 됨
C++의 new, new[] delete, delete[]는 어떻게?
함수가 아니라 연산자임, 근데 LLVM IR로 변환하면 @_Znwm, @_Znam, @_ZdlPv, @_ZdaPv 라는 심볼로 변환됨
void* wrapper_malloc(size_t size) {
    void* addr = malloc(size); //8바이트 정렬된 주소로 할당
    if (addr) {
        set_shadow_enc(addr, size);
    }
    return addr;
}

void* wrapper_calloc(size_t num, size_t size) {
    void* addr = calloc(num, size);
    if (addr) {
        set_shadow_enc(addr, size);
    }
    return addr;
}

//realloc은 기존 할당된 주소와 새로할당할 사이즈를 받아 재할당함
//shadow memory를 관리하기 위해서 기존 영역의 크기를 알아야 함
//realloc호출시 기존 영역의 크기는 전달되지 않으므로 realloc -> wrapper_realloc으로 변경하는 Pass 작성시 ptr의 메타데이터 활용해서 크기 전달해야 함
void* wrapper_realloc(void* ptr, size_t new_size, size_t old_size) {
    void* addr = realloc(ptr, new_size);
    if (addr) {
        //재할당이므로 기존 영역은 해제됨으로 표시하고 새로 할당된 곳을 할당됨으로 표시 (같은 영역이어도 문제 없음)
        memset(get_shadow_address(ptr), -1, get_shadow_size(old_size));
        set_shadow_enc(addr, new_size);
    }
    return addr;
}

void* wrapper_aligned_alloc(size_t alignment, size_t size) {
    void* addr = aligned_alloc(alignment, size);
    if (addr) {
        set_shadow_enc(addr, size);
    }
    return addr;
}

int wrapper_posix_memalign(void** memptr, size_t alignment, size_t size) {
    int result = posix_memalign(memptr, alignment, size);
    if (result == 0) {
        set_shadow_enc(*memptr, size);
    }
    return result;
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
*/






//validate_memory_access함수가 부적절한 메모리 접근을 감지하면 호출
void report_error(void* start_addr, size_t size, int8_t* faulty_shadow_addr) {

    fprintf(stderr, "\n=============================================================================================\n");
    int8_t enc = *faulty_shadow_addr;
    //enc == 0 이면 반드시 할당되지 않은 영역임
    //enc == -1 이면 해제된 영역임
    //enc > 0 이면 해제된 영역이거나, 할당되지 않은 영역임(예를들어, 앞의 4바이트만 할당된 경우 인코딩 값은 4이고, 뒤의 4바이트는 해제된 영역인지 할당되지 않은 영역인지 알 수 없음)
    char *error_type;
    if (enc == -1) {
        error_type = "Use-After-Free detected";
    } else if (enc == 0) {
        error_type = "Access to unallocated memory region";
    } else {
        error_type = "Invalid memory access detected (Unallocated or freed memory region)";
    }
    fprintf(stderr, "********** %s **********\n\n", error_type);

    //문제가 발생한 주소
    void* faulty_addr = (void*)(((uintptr_t)faulty_shadow_addr - (uintptr_t)shadow_memory) << SHADOW_SCALE);
    if (enc > 0) {
        faulty_addr = (void*)((uintptr_t)faulty_addr + enc);
    }
    if (start_addr > faulty_addr) {
        faulty_addr = start_addr;
    }

    fprintf(stderr, "Access address : %p\n", start_addr);
    fprintf(stderr, "Access size    : %zu bytes\n", size);
    fprintf(stderr, "Faulty address : %p\n", faulty_addr);

    //메모리 내용 출력
    fprintf(stderr, "\nMemory dump: \n\n%-19s   %-25s %s\n", "Address", "Content", "Status");

    void* faulty_addr_block = (void*)((uintptr_t)faulty_addr & ~0x7);

    int before_blocks = 6;
    int after_blocks = 6;

    uintptr_t last_digit = ((uintptr_t)faulty_addr_block) & 0xF;
    if (last_digit == 0x0) {
        after_blocks = 7;
    } else {
        before_blocks = 7;
    }
    
    void* start_addr_block = (void*)((uintptr_t)faulty_addr_block - before_blocks * 8);
    void* end_addr_block = (void*)((uintptr_t)faulty_addr_block + after_blocks * 8);

    for (void* cur_addr_block = start_addr_block; cur_addr_block <= end_addr_block; cur_addr_block += 8) {
        int8_t* cur_shadow_addr = get_shadow_address(cur_addr_block);
        int8_t shadow_enc = *cur_shadow_addr;

        // 주소 출력
        if (cur_addr_block == faulty_addr_block) {
            fprintf(stderr, "\033[32m%19p\033[0m |", cur_addr_block); //초록
        } else {
            fprintf(stderr, "%19p |", cur_addr_block);
        }

        // 메모리 내용 가져오기
        uint8_t mem_content[8];
        memcpy(mem_content, cur_addr_block, 8);

        if (shadow_enc > 0) {
            size_t i;
            for (i = 0; i < shadow_enc; i++) {
                fprintf(stderr, " %02X", mem_content[i]);
            }
            for (; i < 8; i++) {
                if (cur_addr_block + i == faulty_addr) { //이 비교 구문은 cur_addr_block == faulty_addr_block일 때만 실행되면 되지만, 성능 희생이 미미하고 가독성을 해치지 않기 위해 이렇게 유지함
                    fprintf(stderr, ">\033[33m%02X\033[0m", mem_content[i]); //노랑
                } else {
                    fprintf(stderr, " \033[33m%02X\033[0m", mem_content[i]); //노랑
                }
            }
        } else {
            if (shadow_enc == 0) {
                for (int i = 0; i < 8; i++) {
                    if (cur_addr_block + i == faulty_addr) {
                        fprintf(stderr, ">\033[35m%02X\033[0m", mem_content[i]); //보라
                    } else {
                        fprintf(stderr, " \033[35m%02X\033[0m", mem_content[i]); //보라
                    }
                }
            } else if (shadow_enc == -1) {
                for (int i = 0; i < 8; i++) {
                    if (cur_addr_block + i == faulty_addr) {
                        fprintf(stderr, ">\033[31m%02X\033[0m", mem_content[i]); //빨강
                    } else {
                        fprintf(stderr, " \033[31m%02X\033[0m", mem_content[i]); //빨강
                    }
                }
            }
        }
        fprintf(stderr, " | ");

        if (cur_addr_block == faulty_addr_block) {
            fprintf(stderr, "\033[32m"); //초록
        }

        if (shadow_enc == 0) {
            fprintf(stderr, "Unallocated\n\033[0m");
        } else if (shadow_enc == -1) {
            fprintf(stderr, "Freed\n\033[0m");
        } else if (shadow_enc == 8) {
            fprintf(stderr, "Valid\n\033[0m");
        } else {
            fprintf(stderr, "%d Valid/%d Invalid(unallocated or freed)\n\033[0m", shadow_enc, 8 - shadow_enc);
        }
    
    }

    fprintf(stderr, "\n=============================================================================================\n");


    _exit(1);
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
        report_error(addr, size, shadow_addr);
    }

    int32_t remaining_size = size;
    //첫 블록에서 접근한 만큼 빼줌.
    if (first_bytes == 8) {
        remaining_size = remaining_size - (8 - shadow_block_offset);
    }
    else {//접근 영역 전체가 1블록을 초과하지 않는다면 더 이상 진행할 필요 없으므로 size = 0
        remaining_size = 0;
    }
    
    //중간 블록에 대해 접근 가능한지 확인
    size_t i = 1;
    for (; remaining_size >= 8; i++, remaining_size -= 8) {
         if (shadow_addr[i] != 8) {
            report_error(addr, size, &shadow_addr[i]);
        }
    }

    //마지막 블록에 대해 접근 가능한지 확인
    if (remaining_size > shadow_addr[i]) {
        report_error(addr, size, &shadow_addr[i]);
    }
}
