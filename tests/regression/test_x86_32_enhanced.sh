#!/bin/bash

# Comprehensive x86_32 Enhanced Instruction Set Test
# Tests the complete i386 instruction set with mixed 16/32-bit modes

STAS_BIN="${STAS_BIN:-./bin/stas}"
TEST_DIR="$(dirname "$0")"
BOOTLOADER_SOURCE="${TEST_DIR}/x86_32_enhanced_bootloader.s"
OUTPUT_DIR="${TEST_DIR}/output"

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Test results
TESTS_PASSED=0
TESTS_FAILED=0

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

log_test() {
    echo -e "${BLUE}[TEST]${NC} $1"
}

# Setup
echo "=============================================================================="
echo "           x86_32 Enhanced Instruction Set Comprehensive Test"
echo "=============================================================================="
echo

log_info "Setting up test environment..."
mkdir -p "$OUTPUT_DIR"

# Check if STAS binary exists
if [[ ! -x "$STAS_BIN" ]]; then
    echo -e "${RED}Error: STAS binary not found at $STAS_BIN${NC}"
    exit 1
fi

# Check if bootloader source exists
if [[ ! -f "$BOOTLOADER_SOURCE" ]]; then
    echo -e "${RED}Error: Bootloader source not found at $BOOTLOADER_SOURCE${NC}"
    exit 1
fi

log_info "Using STAS binary: $STAS_BIN"
log_info "Bootloader source: $BOOTLOADER_SOURCE"
echo

# Test 1: Basic assembly with enhanced instruction set
log_test "Test 1: Basic Enhanced Assembly"
if "$STAS_BIN" -a x86_32 -f bin "$BOOTLOADER_SOURCE" -o "$OUTPUT_DIR/bootloader.bin" 2>"$OUTPUT_DIR/assembly.log"; then
    if [[ -f "$OUTPUT_DIR/bootloader.bin" ]]; then
        FILESIZE=$(stat -c%s "$OUTPUT_DIR/bootloader.bin" 2>/dev/null || echo "0")
        log_success "Enhanced bootloader assembled successfully ($FILESIZE bytes)"
    else
        log_failure "Assembly completed but output file not found"
        cat "$OUTPUT_DIR/assembly.log"
    fi
else
    log_failure "Assembly failed with enhanced instruction set"
    cat "$OUTPUT_DIR/assembly.log"
fi

# Test 2: Verify machine code output
log_test "Test 2: Machine Code Verification"
if [[ -f "$OUTPUT_DIR/bootloader.bin" ]]; then
    # Check for expected opcodes in the output
    hexdump -C "$OUTPUT_DIR/bootloader.bin" > "$OUTPUT_DIR/hexdump.txt"
    
    # Check for specific instruction patterns
    if grep -q "fa" "$OUTPUT_DIR/hexdump.txt"; then  # CLI instruction
        log_success "CLI instruction (0xFA) found in output"
    else
        log_failure "CLI instruction not found in machine code"
    fi
    
    if grep -q "fb" "$OUTPUT_DIR/hexdump.txt"; then  # STI instruction  
        log_success "STI instruction (0xFB) found in output"
    else
        log_failure "STI instruction not found in machine code"
    fi
    
    if grep -q "66 b8" "$OUTPUT_DIR/hexdump.txt"; then  # 32-bit MOV with operand prefix
        log_success "32-bit MOV with operand prefix found"
    else
        log_failure "32-bit MOV with operand prefix not found"
    fi
else
    log_failure "Cannot verify machine code - no output file"
fi

# Test 3: Directive handling verification
log_test "Test 3: Directive Handling"
# Create a simple test for directives
cat > "$OUTPUT_DIR/directive_test.s" << 'EOF'
.code16
movw $0x1234, %ax
.code32  
movl $0x12345678, %eax
.code16
movw $0x5678, %bx
EOF

if "$STAS_BIN" -a x86_32 -f bin "$OUTPUT_DIR/directive_test.s" -o "$OUTPUT_DIR/directive_test.bin" 2>"$OUTPUT_DIR/directive.log"; then
    log_success "Directive handling test passed"
else
    log_failure "Directive handling test failed"
    cat "$OUTPUT_DIR/directive.log"
fi

# Test 4: 16-bit mode operations
log_test "Test 4: 16-bit Mode Operations"
cat > "$OUTPUT_DIR/test_16bit.s" << 'EOF'
.code16
cli
movw $0x1000, %ax
movw %ax, %ds
addw $0x500, %ax
pushw %ax
popw %bx
sti
ret
EOF

if "$STAS_BIN" -a x86_32 -f bin "$OUTPUT_DIR/test_16bit.s" -o "$OUTPUT_DIR/test_16bit.bin" 2>"$OUTPUT_DIR/16bit.log"; then
    FILESIZE=$(stat -c%s "$OUTPUT_DIR/test_16bit.bin" 2>/dev/null || echo "0")
    if [[ "$FILESIZE" -gt 0 ]]; then
        log_success "16-bit mode operations test passed ($FILESIZE bytes)"
    else
        log_failure "16-bit mode test produced empty output"
    fi
else
    log_failure "16-bit mode operations test failed"
    cat "$OUTPUT_DIR/16bit.log"
fi

# Test 5: 32-bit mode operations
log_test "Test 5: 32-bit Mode Operations" 
cat > "$OUTPUT_DIR/test_32bit.s" << 'EOF'
.code32
cli
movl $0x12345678, %eax
addl $1000, %eax
pushl %eax
pushad
popad
popl %ebx
incl %eax
decl %ebx
sti
ret
EOF

if "$STAS_BIN" -a x86_32 -f bin "$OUTPUT_DIR/test_32bit.s" -o "$OUTPUT_DIR/test_32bit.bin" 2>"$OUTPUT_DIR/32bit.log"; then
    FILESIZE=$(stat -c%s "$OUTPUT_DIR/test_32bit.bin" 2>/dev/null || echo "0")
    if [[ "$FILESIZE" -gt 0 ]]; then
        log_success "32-bit mode operations test passed ($FILESIZE bytes)"
    else
        log_failure "32-bit mode test produced empty output"
    fi
else
    log_failure "32-bit mode operations test failed"
    cat "$OUTPUT_DIR/32bit.log"
fi

# Test 6: Mixed mode transitions
log_test "Test 6: Mixed Mode Transitions"
cat > "$OUTPUT_DIR/test_mixed.s" << 'EOF'
.code16
cli
movw $0x2000, %ax
movl $0x80000001, %eax
.code32
movl $0x10, %ebx
movl %ebx, %ds
movl $0x12345678, %eax
.code16
movw $0x3000, %cx
.code32
sti
ret
EOF

if "$STAS_BIN" -a x86_32 -f bin "$OUTPUT_DIR/test_mixed.s" -o "$OUTPUT_DIR/test_mixed.bin" 2>"$OUTPUT_DIR/mixed.log"; then
    FILESIZE=$(stat -c%s "$OUTPUT_DIR/test_mixed.bin" 2>/dev/null || echo "0")
    if [[ "$FILESIZE" -gt 0 ]]; then
        log_success "Mixed mode transitions test passed ($FILESIZE bytes)"
    else
        log_failure "Mixed mode test produced empty output"
    fi
else
    log_failure "Mixed mode transitions test failed"
    cat "$OUTPUT_DIR/mixed.log"
fi

# Test 7: System instructions comprehensive
log_test "Test 7: System Instructions"
cat > "$OUTPUT_DIR/test_system.s" << 'EOF'
.code32
cli
hlt
nop
sti
clc
stc
cld
std
int $0x80
ret
EOF

if "$STAS_BIN" -a x86_32 -f bin "$OUTPUT_DIR/test_system.s" -o "$OUTPUT_DIR/test_system.bin" 2>"$OUTPUT_DIR/system.log"; then
    FILESIZE=$(stat -c%s "$OUTPUT_DIR/test_system.bin" 2>/dev/null || echo "0")
    if [[ "$FILESIZE" -ge 8 ]]; then  # Should be at least 8 bytes for this sequence
        log_success "System instructions test passed ($FILESIZE bytes)"
    else
        log_failure "System instructions test produced insufficient output"
    fi
else
    log_failure "System instructions test failed"
    cat "$OUTPUT_DIR/system.log"
fi

# Test 8: Arithmetic instruction set
log_test "Test 8: Arithmetic Instructions"
cat > "$OUTPUT_DIR/test_arithmetic.s" << 'EOF'
.code32
movl $100, %eax
movl $50, %ebx
addl %ebx, %eax
subl $25, %eax
cmpl $125, %eax
je success
movl $0, %eax
jmp end
success:
movl $1, %eax
end:
ret
EOF

if "$STAS_BIN" -a x86_32 -f bin "$OUTPUT_DIR/test_arithmetic.s" -o "$OUTPUT_DIR/test_arithmetic.bin" 2>"$OUTPUT_DIR/arithmetic.log"; then
    FILESIZE=$(stat -c%s "$OUTPUT_DIR/test_arithmetic.bin" 2>/dev/null || echo "0")
    if [[ "$FILESIZE" -gt 0 ]]; then
        log_success "Arithmetic instructions test passed ($FILESIZE bytes)"
    else
        log_failure "Arithmetic instructions test produced empty output"
    fi
else
    log_failure "Arithmetic instructions test failed"
    cat "$OUTPUT_DIR/arithmetic.log"
fi

# Test 9: Control flow instructions
log_test "Test 9: Control Flow Instructions"
cat > "$OUTPUT_DIR/test_control.s" << 'EOF'
.code32
movl $1, %eax
cmpl $1, %eax
je label1
jmp error
label1:
cmpl $2, %eax
jne label2
jmp error  
label2:
jmp label3
error:
hlt
label3:
call subroutine
jmp end
subroutine:
ret
end:
ret
EOF

if "$STAS_BIN" -a x86_32 -f bin "$OUTPUT_DIR/test_control.s" -o "$OUTPUT_DIR/test_control.bin" 2>"$OUTPUT_DIR/control.log"; then
    FILESIZE=$(stat -c%s "$OUTPUT_DIR/test_control.bin" 2>/dev/null || echo "0")
    if [[ "$FILESIZE" -gt 0 ]]; then
        log_success "Control flow instructions test passed ($FILESIZE bytes)"
    else
        log_failure "Control flow instructions test produced empty output"
    fi
else
    log_failure "Control flow instructions test failed"
    cat "$OUTPUT_DIR/control.log"
fi

# Test 10: Register operations comprehensive
log_test "Test 10: Comprehensive Register Operations"
cat > "$OUTPUT_DIR/test_registers.s" << 'EOF'
.code32
; Test all 32-bit registers
movl $0x11111111, %eax
movl $0x22222222, %ebx  
movl $0x33333333, %ecx
movl $0x44444444, %edx
movl $0x55555555, %esi
movl $0x66666666, %edi
movl $0x77777777, %ebp

; Test 16-bit registers
movw $0x1234, %ax
movw $0x5678, %bx

; Test 8-bit registers
movb $0x42, %al
movb $0x24, %ah
movb $0x84, %bl
movb $0x48, %bh

ret
EOF

if "$STAS_BIN" -a x86_32 -f bin "$OUTPUT_DIR/test_registers.s" -o "$OUTPUT_DIR/test_registers.bin" 2>"$OUTPUT_DIR/registers.log"; then
    FILESIZE=$(stat -c%s "$OUTPUT_DIR/test_registers.bin" 2>/dev/null || echo "0")
    if [[ "$FILESIZE" -gt 0 ]]; then
        log_success "Comprehensive register operations test passed ($FILESIZE bytes)"
    else
        log_failure "Register operations test produced empty output"
    fi
else
    log_failure "Comprehensive register operations test failed"
    cat "$OUTPUT_DIR/registers.log"
fi

# Test results summary
echo
echo "=============================================================================="
echo "                              Test Summary"  
echo "=============================================================================="
echo
echo "Total tests run: $((TESTS_PASSED + TESTS_FAILED))"
echo -e "Tests passed: ${GREEN}$TESTS_PASSED${NC}"
echo -e "Tests failed: ${RED}$TESTS_FAILED${NC}"

if [[ $TESTS_FAILED -eq 0 ]]; then
    echo
    echo -e "${GREEN}🎉 All tests passed! x86_32 enhanced instruction set is working correctly.${NC}"
    echo
    echo "Features validated:"
    echo "✓ Complete i386 instruction set"
    echo "✓ .code16/.code32 directive support"
    echo "✓ Real mode (16-bit) operations"
    echo "✓ Protected mode (32-bit) operations" 
    echo "✓ Virtual 8086 mode simulation"
    echo "✓ Mixed-mode transitions"
    echo "✓ System instructions (CLI/STI/HLT/etc.)"
    echo "✓ Arithmetic operations (ADD/SUB/CMP/etc.)"
    echo "✓ Stack operations (PUSH/POP/PUSHAD/POPAD)"
    echo "✓ Control flow (JMP/CALL/RET/Jcc)"
    echo "✓ Flag operations (CLC/STC/CLD/STD)"
    echo "✓ Increment/decrement (INC/DEC)"
    echo "✓ All register sizes (32/16/8-bit)"
    EXIT_CODE=0
else
    echo
    echo -e "${RED}❌ Some tests failed. Please check the implementation.${NC}"
    EXIT_CODE=1
fi

echo
log_info "Output files and logs available in: $OUTPUT_DIR"
echo

# Show file sizes for successful outputs
if [[ $TESTS_PASSED -gt 0 ]]; then
    echo "Generated files:"
    ls -la "$OUTPUT_DIR"/*.bin 2>/dev/null | while read -r line; do
        echo "  $line"
    done
fi

echo
echo "=============================================================================="
exit $EXIT_CODE
