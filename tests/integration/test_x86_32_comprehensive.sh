#!/bin/bash

# Integration test for x86_32 enhanced instruction set
# Tests comprehensive i386 functionality including real/protected/V86 modes

STAS_BIN="${STAS_BIN:-./bin/stas}"
TEST_DIR="$(dirname "$0")"
TEMP_DIR="${TEST_DIR}/temp_x86_32_integration"

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

# Test results
TESTS_PASSED=0
TESTS_FAILED=0
TOTAL_TESTS=0

# Helper functions
log_info() {
    echo -e "${YELLOW}[INFO]${NC} $1"
}

log_success() {
    echo -e "${GREEN}[PASS]${NC} $1"
    ((TESTS_PASSED++))
}

log_failure() {
    echo -e "${RED}[FAIL]${NC} $1"
    ((TESTS_FAILED++))
}

run_test() {
    local test_name="$1"
    local source_file="$2"
    local expected_size="$3"
    
    ((TOTAL_TESTS++))
    log_info "Running test: $test_name"
    
    # Create temporary source file
    echo "$source_file" > "${TEMP_DIR}/${test_name}.s"
    
    # Assemble with STAS
    if "$STAS_BIN" -a x86_32 -f bin "${TEMP_DIR}/${test_name}.s" -o "${TEMP_DIR}/${test_name}.bin" 2>/dev/null; then
        # Check if output file exists and has expected size
        if [[ -f "${TEMP_DIR}/${test_name}.bin" ]]; then
            local actual_size=$(stat -c%s "${TEMP_DIR}/${test_name}.bin" 2>/dev/null || echo "0")
            if [[ "$actual_size" -eq "$expected_size" ]]; then
                log_success "$test_name (${actual_size} bytes)"
            else
                log_failure "$test_name - Size mismatch: expected $expected_size, got $actual_size"
            fi
        else
            log_failure "$test_name - Output file not created"
        fi
    else
        log_failure "$test_name - Assembly failed"
    fi
}

# Setup
log_info "Setting up x86_32 integration tests..."
mkdir -p "$TEMP_DIR"

# Check if STAS binary exists
if [[ ! -x "$STAS_BIN" ]]; then
    echo -e "${RED}Error: STAS binary not found at $STAS_BIN${NC}"
    exit 1
fi

log_info "Using STAS binary: $STAS_BIN"
echo

# Test 1: Basic 32-bit instructions
run_test "basic_32bit" ".code32
movl \$0x12345678, %eax
addl \$100, %eax
pushl %eax
popl %ebx
ret" 15

# Test 2: Mixed 16-bit and 32-bit in real mode  
run_test "mixed_real_mode" ".code16
cli
movw \$0x1000, %ax
movl \$0x80000001, %eax
sti
ret" 12

# Test 3: Protected mode transition simulation
run_test "protected_mode_sim" ".code16
cli
movw \$0x0008, %ax
movl \$0x80000001, %eax
.code32
movl \$0x12345678, %ebx
sti
ret" 17

# Test 4: System instructions
run_test "system_instructions" ".code32
cli
hlt
nop
sti
int \$0x80
ret" 7

# Test 5: Arithmetic operations
run_test "arithmetic_ops" ".code32
movl \$100, %eax
movl \$50, %ebx
addl %ebx, %eax
subl \$25, %eax
cmpl \$125, %eax
ret" 21

# Test 6: Control flow
run_test "control_flow" ".code32
movl \$1, %eax
cmpl \$1, %eax
je next
jmp end
next:
incl %eax
end:
ret" 15

# Test 7: Stack operations
run_test "stack_ops" ".code32
pushl \$0x12345678
pushl %eax
pushad
popad
popl %ebx
ret" 13

# Test 8: Flag operations
run_test "flag_ops" ".code32
clc
stc
cld
std
ret" 5

# Test 9: 8-bit operations
run_test "8bit_ops" ".code32
movb \$0x42, %al
movb \$0x24, %bl
addb %bl, %al
ret" 7

# Test 10: 16-bit operations in 32-bit mode
run_test "16bit_in_32bit" ".code32
movw \$0x1234, %ax
addw \$0x5678, %ax
ret" 8

# Test 11: Complete bootloader simulation
run_test "bootloader_complete" ".code16
cli
movw \$0x9000, %ax
movw %ax, %ds
movl \$0x80000001, %eax
.code32
movl \$0x10, %ebx
movl %ebx, %ds
sti
movl \$0x12345678, %eax
ret" 22

# Test 12: Virtual 8086 mode simulation
run_test "v86_mode_sim" ".code16
pushf
cli
movw \$0x2000, %ax
int \$0x21
popf
ret" 10

# Test 13: Advanced instruction validation
run_test "advanced_validation" ".code32
movl %eax, %ebx
addl %ecx, %edx
subl %esi, %edi
cmpl %esp, %ebp
ret" 9

# Test 14: Increment/decrement operations
run_test "inc_dec_ops" ".code32
incl %eax
incl %ebx
decl %ecx
decl %edx
ret" 5

# Test 15: Complex immediate addressing
run_test "complex_immediate" ".code32
movl \$0xFFFFFFFF, %eax
addl \$0x00000001, %eax
subl \$0x80000000, %eax
ret" 19

# Summary
echo
log_info "=== Test Summary ==="
echo "Total tests: $TOTAL_TESTS"
echo -e "Passed: ${GREEN}$TESTS_PASSED${NC}"
echo -e "Failed: ${RED}$TESTS_FAILED${NC}"

if [[ $TESTS_FAILED -eq 0 ]]; then
    echo -e "${GREEN}All tests passed!${NC}"
    EXIT_CODE=0
else
    echo -e "${RED}Some tests failed.${NC}"
    EXIT_CODE=1
fi

# Cleanup
log_info "Cleaning up temporary files..."
rm -rf "$TEMP_DIR"

echo
log_info "x86_32 integration test completed."
exit $EXIT_CODE
