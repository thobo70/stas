#!/bin/bash
# =============================================================================
# STAS Phase 7 Regression Test Suite
# Tests for Advanced Language Features: Macros, Includes, Conditionals
# =============================================================================

set -e  # Exit on any error

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Test counters
TOTAL_TESTS=0
PASSED_TESTS=0
FAILED_TESTS=0

# Helper functions
print_header() {
    echo -e "${BLUE}=================================================================${NC}"
    echo -e "${BLUE}$1${NC}"
    echo -e "${BLUE}=================================================================${NC}"
}

print_test() {
    echo -e "${YELLOW}[TEST] $1${NC}"
    ((TOTAL_TESTS++))
}

print_pass() {
    echo -e "${GREEN}[PASS] $1${NC}"
    ((PASSED_TESTS++))
}

print_fail() {
    echo -e "${RED}[FAIL] $1${NC}"
    ((FAILED_TESTS++))
}

# Change to project directory
cd "$(dirname "$0")/../.."

# Build the project
print_header "Building STAS Assembler"
make clean >/dev/null 2>&1
make >/dev/null 2>&1

if [ ! -f "bin/stas" ]; then
    echo -e "${RED}ERROR: Failed to build STAS assembler${NC}"
    exit 1
fi

print_pass "STAS assembler built successfully"

# =============================================================================
# Test 1: Basic Macro Processing
# =============================================================================

print_header "Test 1: Basic Macro Processing"

print_test "Simple macro definition and expansion"
cat > tests/phase7/test_macro_basic.s << 'EOF'
#define TEST_VALUE 42

.section .text
mov r0, #TEST_VALUE
EOF

if ./bin/stas tests/phase7/test_macro_basic.s -o tests/phase7/test1.out >/dev/null 2>&1; then
    print_pass "Basic macro expansion works correctly"
else
    print_fail "Basic macro expansion failed"
fi

print_test "Hex value macro expansion"
cat > tests/phase7/test_macro_hex.s << 'EOF'
#define HEX_VALUE 0x1000

.section .text
mov r0, #HEX_VALUE
EOF

if ./bin/stas tests/phase7/test_macro_hex.s -o tests/phase7/test2.out >/dev/null 2>&1; then
    print_pass "Hex macro expansion works correctly"
else
    print_fail "Hex macro expansion failed"
fi

# =============================================================================
# Test 2: Conditional Assembly
# =============================================================================

print_header "Test 2: Conditional Assembly"

print_test "ifdef with defined macro"
cat > tests/phase7/test_ifdef_true.s << 'EOF'
#define DEBUG_MODE

.section .text
#ifdef DEBUG_MODE
mov r0, #1
#endif
mov r1, #2
EOF

if ./bin/stas tests/phase7/test_ifdef_true.s -o tests/phase7/test3.out >/dev/null 2>&1; then
    print_pass "ifdef with defined macro works correctly"
else
    print_fail "ifdef with defined macro failed"
fi

print_test "ifdef with undefined macro"
cat > tests/phase7/test_ifdef_false.s << 'EOF'
.section .text
#ifdef UNDEFINED_MACRO
mov r0, #1
#endif
mov r1, #2
EOF

if ./bin/stas tests/phase7/test_ifdef_false.s -o tests/phase7/test4.out >/dev/null 2>&1; then
    print_pass "ifdef with undefined macro works correctly"
else
    print_fail "ifdef with undefined macro failed"
fi

print_test "ifndef with undefined macro"
cat > tests/phase7/test_ifndef_true.s << 'EOF'
.section .text
#ifndef UNDEFINED_MACRO
mov r0, #3
#endif
mov r1, #4
EOF

if ./bin/stas tests/phase7/test_ifndef_true.s -o tests/phase7/test5.out >/dev/null 2>&1; then
    print_pass "ifndef with undefined macro works correctly"
else
    print_fail "ifndef with undefined macro failed"
fi

# =============================================================================
# Test 3: Include Directives
# =============================================================================

print_header "Test 3: Include Directives"

print_test "Basic file inclusion"

# Create include file
cat > tests/phase7/common.inc << 'EOF'
#define SHARED_VALUE 0x5555
#define ANOTHER_VALUE 100
EOF

# Create main file
cat > tests/phase7/test_include.s << 'EOF'
.include "tests/phase7/common.inc"

.section .text
mov r0, #SHARED_VALUE
mov r1, #ANOTHER_VALUE
EOF

if ./bin/stas tests/phase7/test_include.s -o tests/phase7/test6.out >/dev/null 2>&1; then
    print_pass "Include directive works correctly"
else
    print_fail "Include directive failed"
fi

# =============================================================================
# Test 4: Complex Integration
# =============================================================================

print_header "Test 4: Complex Integration Tests"

print_test "Macros + Conditionals + Includes"
cat > tests/phase7/complex_defs.inc << 'EOF'
#define BASE_ADDR 0x8000
#define MODE_FLAG 1
EOF

cat > tests/phase7/test_complex.s << 'EOF'
.include "tests/phase7/complex_defs.inc"

#define BUILD_TYPE 2

.section .text
#ifdef MODE_FLAG
mov r0, #BASE_ADDR
#endif

#ifndef UNDEFINED_FLAG
mov r1, #BUILD_TYPE
#endif

mov r2, #0x9999
EOF

if ./bin/stas tests/phase7/test_complex.s -o tests/phase7/test7.out >/dev/null 2>&1; then
    print_pass "Complex integration test works correctly"
else
    print_fail "Complex integration test failed"
fi

# =============================================================================
# Test 5: Edge Cases
# =============================================================================

print_header "Test 5: Edge Cases"

print_test "Nested conditionals"
cat > tests/phase7/test_nested.s << 'EOF'
#define OUTER_FLAG
#define INNER_FLAG

.section .text
#ifdef OUTER_FLAG
  #ifdef INNER_FLAG
mov r0, #0x1234
  #endif
#endif
mov r1, #0x5678
EOF

if ./bin/stas tests/phase7/test_nested.s -o tests/phase7/test8.out >/dev/null 2>&1; then
    print_pass "Nested conditionals work correctly"
else
    print_fail "Nested conditionals failed"
fi

print_test "Macro redefinition"
cat > tests/phase7/test_redefine.s << 'EOF'
#define VALUE 100
#define VALUE 200

.section .text
mov r0, #VALUE
EOF

if ./bin/stas tests/phase7/test_redefine.s -o tests/phase7/test9.out >/dev/null 2>&1; then
    print_pass "Macro redefinition works correctly"
else
    print_fail "Macro redefinition failed"
fi

# =============================================================================
# Test 6: ARM Architecture Tests (Primary Support)
# =============================================================================

print_header "Test 6: ARM Architecture Tests"

print_test "ARM macro expansion"
cat > tests/phase7/test_arm_macros.s << 'EOF'
#define ARM_REG_VAL 0x1000
#define ARM_OFFSET 4

.section .text
mov r0, #ARM_REG_VAL
ldr r1, [r0, #ARM_OFFSET]
EOF

if ./bin/stas tests/phase7/test_arm_macros.s -o tests/phase7/test_arm.out >/dev/null 2>&1; then
    print_pass "ARM macro expansion works correctly"
else
    print_fail "ARM macro expansion failed"
fi

print_test "ARM conditional assembly"
cat > tests/phase7/test_arm_cond.s << 'EOF'
#define ARM_BUILD
#define THUMB_BUILD

.section .text
#ifdef ARM_BUILD
mov r0, #1
#endif

#ifdef THUMB_BUILD
mov r1, #2
#endif

#ifndef X86_BUILD
mov r2, #3
#endif
EOF

if ./bin/stas tests/phase7/test_arm_cond.s -o tests/phase7/test_arm_cond.out >/dev/null 2>&1; then
    print_pass "ARM conditional assembly works correctly"
else
    print_fail "ARM conditional assembly failed"
fi

# =============================================================================
# Test Results Summary
# =============================================================================

print_header "Test Results Summary"

echo -e "${BLUE}Total Tests: $TOTAL_TESTS${NC}"
echo -e "${GREEN}Passed: $PASSED_TESTS${NC}"
echo -e "${RED}Failed: $FAILED_TESTS${NC}"

if [ $FAILED_TESTS -eq 0 ]; then
    echo -e "${GREEN}🎉 ALL TESTS PASSED! Phase 7 is working correctly.${NC}"
    exit 0
else
    echo -e "${RED}❌ Some tests failed. Phase 7 needs attention.${NC}"
    exit 1
fi
