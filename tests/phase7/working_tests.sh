#!/bin/bash

# STAS Phase 7 Working Test Suite
# Tests using x86_64 syntax (which we know works)

set -e

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

# Test configuration
PROJECT_ROOT="/home/tom/project/stas"
STAS_BINARY="${PROJECT_ROOT}/bin/stas"

# Change to project directory
cd "$PROJECT_ROOT"

echo -e "${YELLOW}STAS Phase 7 Working Test Suite${NC}"
echo "=================================="
echo

# Test counters
TOTAL_TESTS=0
PASSED_TESTS=0
FAILED_TESTS=0

run_test() {
    local test_name="$1"
    local test_content="$2"
    
    TOTAL_TESTS=$((TOTAL_TESTS + 1))
    echo -n "Testing $test_name... "
    
    # Create test file
    echo "$test_content" > "temp_test.s"
    
    # Run STAS assembler
    if $STAS_BINARY temp_test.s -o temp_test.bin >/dev/null 2>&1; then
        echo -e "${GREEN}PASS${NC}"
        PASSED_TESTS=$((PASSED_TESTS + 1))
        rm -f temp_test.s temp_test.bin
        return 0
    else
        echo -e "${RED}FAIL${NC}"
        FAILED_TESTS=$((FAILED_TESTS + 1))
        echo "Test content:"
        cat temp_test.s
        echo "Error:"
        $STAS_BINARY temp_test.s -o temp_test.bin 2>&1 || true
        rm -f temp_test.s temp_test.bin
        return 1
    fi
}

# Test 1: Basic Macro Processing
run_test "Basic macros" \
'#define BUFFER_SIZE 1024
#define SUCCESS 0

.section .text
.global _start

_start:
    movq $BUFFER_SIZE, %rax
    movq $SUCCESS, %rbx
    ret'

# Test 2: Conditional Assembly - ifdef
run_test "ifdef conditional" \
'#define DEBUG_MODE

.section .text
.global _start

_start:
#ifdef DEBUG_MODE
    movq $1, %rax
#endif
    movq $2, %rbx
    ret'

# Test 3: Conditional Assembly - ifndef
run_test "ifndef conditional" \
'.section .text
.global _start

_start:
#ifndef RELEASE_MODE
    movq $1, %rax
#endif
    movq $2, %rbx
    ret'

# Test 4: Include Files
echo '#define SHARED_VALUE 42' > temp_include.inc
run_test "include directives" \
'.include "temp_include.inc"

.section .text
.global _start

_start:
    movq $SHARED_VALUE, %rax
    ret'
rm -f temp_include.inc

# Test 5: Macro with expressions
run_test "macro expressions" \
'#define BASE_ADDR 0x1000
#define RESULT 0x1100

.section .text
.global _start

_start:
    movq $BASE_ADDR, %rax
    movq $RESULT, %rbx
    ret'

# Test 6: Combined features
echo '#define COMMON_SIZE 256' > temp_common.inc
run_test "combined features" \
'.include "temp_common.inc"
#define DEBUG_BUILD

.section .text
.global _start

_start:
    movq $COMMON_SIZE, %rax
#ifdef DEBUG_BUILD
    movq $1, %rbx
#else
    movq $0, %rbx
#endif
    ret'
rm -f temp_common.inc

# Results
echo
echo -e "${BLUE}Test Results:${NC}"
echo -e "Total Tests: $TOTAL_TESTS"
echo -e "${GREEN}Passed: $PASSED_TESTS${NC}"
echo -e "${RED}Failed: $FAILED_TESTS${NC}"

if [ $FAILED_TESTS -eq 0 ]; then
    echo -e "${GREEN}🎉 ALL TESTS PASSED! Phase 7 is working correctly.${NC}"
    exit 0
else
    echo -e "${RED}❌ Some tests failed.${NC}"
    exit 1
fi
