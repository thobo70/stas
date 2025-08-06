#!/bin/bash
# =============================================================================
# STAS Phase 7 Regression Test Suite
# Tests for Advanced Language Features: Includes and Expressions
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
# Test 1: Include Directive Processing
# =============================================================================

print_header "Test 1: Include Directive Processing"

print_test "Basic file inclusion"

# Create include file with constants
cat > tests/phase7/constants.inc << 'EOF'
; Common constants for tests
CONSTANT_VALUE = 42
HEX_VALUE = 0x1000
EOF

# Create main file that includes constants
cat > tests/phase7/test_include_basic.s << 'EOF'
#include "tests/phase7/constants.inc"

.section .text
mov r0, #CONSTANT_VALUE
mov r1, #HEX_VALUE
EOF

if ./bin/stas tests/phase7/test_include_basic.s -o tests/phase7/test1.out >/dev/null 2>&1; then
    print_pass "Basic include directive works correctly"
else
    print_fail "Basic include directive failed"
fi

print_test "Nested includes"

# Create first level include
cat > tests/phase7/level1.inc << 'EOF'
#include "tests/phase7/constants.inc"
LEVEL1_VALUE = 200
EOF

# Create main file with nested includes
cat > tests/phase7/test_include_nested.s << 'EOF'
#include "tests/phase7/level1.inc"

.section .text
mov r0, #CONSTANT_VALUE
mov r1, #LEVEL1_VALUE
EOF

if ./bin/stas tests/phase7/test_include_nested.s -o tests/phase7/test2.out >/dev/null 2>&1; then
    print_pass "Nested includes work correctly"
else
    print_fail "Nested includes failed"
fi

# =============================================================================
# Test 2: Assembly Features Testing
# =============================================================================

print_header "Test 2: Core Assembly Features"

print_test "Complex assembly with includes"

# Create shared definitions
cat > tests/phase7/shared_defs.inc << 'EOF'
; Shared definitions
BASE_ADDR = 0x8000
MODE_FLAG = 1
EOF

# Create main test file
cat > tests/phase7/test_assembly.s << 'EOF'
#include "tests/phase7/shared_defs.inc"

.section .text
mov r0, #BASE_ADDR
mov r1, #MODE_FLAG
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

if ./bin/stas tests/phase7/test_assembly.s -o tests/phase7/test3.out >/dev/null 2>&1; then
    print_pass "Complex assembly with includes works correctly"
else
    print_fail "Complex assembly with includes failed"
fi

# =============================================================================
# Test 3: Multiple Architecture Support
# =============================================================================

print_header "Test 3: Architecture-Specific Assembly"

print_test "ARM64 assembly with includes"

# Create ARM-specific definitions
cat > tests/phase7/arm_defs.inc << 'EOF'
; ARM64 specific constants
ARM_REG_VAL = 0x1000
ARM_OFFSET = 4
EOF

cat > tests/phase7/test_arm.s << 'EOF'
#include "tests/phase7/arm_defs.inc"

.section .text
mov x0, #ARM_REG_VAL
ldr x1, [x0, #ARM_OFFSET]
EOF

if ./bin/stas tests/phase7/test_arm.s -o tests/phase7/test_arm.out >/dev/null 2>&1; then
    print_pass "ARM64 assembly with includes works correctly"
else
    print_fail "ARM64 assembly with includes failed"
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
