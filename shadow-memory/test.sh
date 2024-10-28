#!/bin/bash

echo "메모리 접근 테스트 시작"

# 테스트 결과 요약을 저장할 변수
TEST_PASSED=0
TEST_FAILED=0

# 할당 크기: 1부터 32까지
for ALLOC_SIZE in {1..32}; do
    echo "============================"
    echo "할당 크기: $ALLOC_SIZE 바이트"
    echo "============================"

    # 할당 영역 앞쪽 접근 테스트
    for OFFSET in {-16..-1}; do
        for ACCESS_SIZE in {1..16}; do
            EXPECTED_RESULT="유효하지 않은 접근"
            TEST_CASE="$ALLOC_SIZE $OFFSET $ACCESS_SIZE 0"


            ./memory_access_test $TEST_CASE
            RESULT=$?

            if [ $RESULT -eq 0 ]; then
                ACTUAL_RESULT="유효한 접근"
            else
                ACTUAL_RESULT="유효하지 않은 접근"
            fi

            if [ "$ACTUAL_RESULT" == "$EXPECTED_RESULT" ]; then
                #echo "테스트 성공"
                TEST_PASSED=$((TEST_PASSED + 1))
            else
                echo "----------------------------------------"
                echo "테스트 케이스: $TEST_CASE"
                echo "예상 결과: $EXPECTED_RESULT"
                echo "실제 결과: $ACTUAL_RESULT"
                echo "테스트 실패"
                TEST_FAILED=$((TEST_FAILED + 1))
            fi
        done
    done

    # 할당된 영역 또는 해제된 영역 접근 테스트
    for FREE_MEMORY in 0 1; do
        if [ $FREE_MEMORY -eq 0 ]; then
            MEMORY_STATE="할당된"
        else
            MEMORY_STATE="해제된"
        fi

        # OFFSET을 0부터 ALLOC_SIZE - 1까지로 설정
        for OFFSET in $(seq 0 $((ALLOC_SIZE - 1))); do
            for ACCESS_SIZE in $(seq 1 $((ALLOC_SIZE + 16))); do
                # 접근 범위 계산
                START_ADDR=$OFFSET
                END_ADDR=$((OFFSET + ACCESS_SIZE - 1))

                if [ $FREE_MEMORY -eq 0 ] && [ $END_ADDR -lt $ALLOC_SIZE ]; then
                    EXPECTED_RESULT="유효한 접근"
                else
                    EXPECTED_RESULT="유효하지 않은 접근"
                fi

                TEST_CASE="$ALLOC_SIZE $OFFSET $ACCESS_SIZE $FREE_MEMORY"


                ./memory_access_test $TEST_CASE
                RESULT=$?

                if [ $RESULT -eq 0 ]; then
                    ACTUAL_RESULT="유효한 접근"
                else
                    ACTUAL_RESULT="유효하지 않은 접근"
                fi

                

                if [ "$ACTUAL_RESULT" == "$EXPECTED_RESULT" ]; then
                    #echo "테스트 성공"
                    TEST_PASSED=$((TEST_PASSED + 1))
                else
                    echo "----------------------------------------"
                    echo "테스트 케이스: $TEST_CASE"
                    echo "메모리 상태: $MEMORY_STATE 메모리"
                    echo "예상 결과: $EXPECTED_RESULT"
                    echo "실제 결과: $ACTUAL_RESULT"
                    echo "테스트 실패"
                    TEST_FAILED=$((TEST_FAILED + 1))
                fi
            done
        done
    done

    # 할당된 영역 뒤쪽 접근 테스트
    for FREE_MEMORY in 0 1; do
        if [ $FREE_MEMORY -eq 0 ]; then
            MEMORY_STATE="할당된"
        else
            MEMORY_STATE="해제된"
        fi

        for OFFSET in $(seq $ALLOC_SIZE $((ALLOC_SIZE + 16))); do
            for ACCESS_SIZE in {1..16}; do
                # 접근 범위 계산
                START_ADDR=$OFFSET
                END_ADDR=$((OFFSET + ACCESS_SIZE - 1))

                EXPECTED_RESULT="유효하지 않은 접근"

                TEST_CASE="$ALLOC_SIZE $OFFSET $ACCESS_SIZE $FREE_MEMORY"


                ./memory_access_test $TEST_CASE
                RESULT=$?

                if [ $RESULT -eq 0 ]; then
                    ACTUAL_RESULT="유효한 접근"
                else
                    ACTUAL_RESULT="유효하지 않은 접근"
                fi

                

                if [ "$ACTUAL_RESULT" == "$EXPECTED_RESULT" ]; then
                    #echo "테스트 성공"
                    TEST_PASSED=$((TEST_PASSED + 1))
                else
                    echo "----------------------------------------"
                    echo "테스트 케이스: $TEST_CASE"
                    echo "메모리 상태: $MEMORY_STATE 메모리"
                    echo "예상 결과: $EXPECTED_RESULT"
                    echo "실제 결과: $ACTUAL_RESULT"
                    echo "테스트 실패"
                    TEST_FAILED=$((TEST_FAILED + 1))
                fi
            done
        done
    done

done

echo "========================================"
echo "메모리 접근 테스트 완료"
echo "총 테스트 수: $((TEST_PASSED + TEST_FAILED))"
echo "성공한 테스트 수: $TEST_PASSED"
echo "실패한 테스트 수: $TEST_FAILED"
echo "========================================"
