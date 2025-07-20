#!/bin/bash

# End-to-End Assembly Testing
# Tests complete assembly workflows for all architectures

set -e

# Setup logs directory
LOGS_DIR="logs"
mkdir -p "$LOGS_DIR"

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m'

log_info() {
    echo -e "${YELLOW}[INFO]${NC} $1"
}

log_success() {
    echo -e "${GREEN}[PASS]${NC} $1"
}

log_error() {
    echo -e "${RED}[FAIL]${NC} $1"
}

# Test counter
TOTAL_TESTS=0
PASSED_TESTS=0

test_assembly_workflow() {
    local arch=$1
    local test_name=$2
    local asm_content=$3
    local expected_size_min=${4:-1}
    
    ((TOTAL_TESTS++))
    
    log_info "Testing $arch assembly: $test_name"
    
    # Create test file
    local test_file="test_${arch}_${test_name}.s"
    echo "$asm_content" > "$test_file"
    
    # Assemble the file
    local output_file="test_${arch}_${test_name}.out"
    if timeout 30s ./bin/stas "$test_file" -o "$output_file" > "$LOGS_DIR/assembly_${arch}_${test_name}.log" 2>&1; then
        # Check output file
        if [ -f "$output_file" ] && [ -s "$output_file" ]; then
            local file_size=$(stat -c%s "$output_file")
            if [ "$file_size" -ge "$expected_size_min" ]; then
                log_success "$arch $test_name: Assembly successful (${file_size} bytes)"
                ((PASSED_TESTS++))
                
                # Cleanup
                rm -f "$test_file" "$output_file" "$LOGS_DIR/assembly_${arch}_${test_name}.log"
                return 0
            else
                log_error "$arch $test_name: Output too small (${file_size} bytes)"
            fi
        else
            log_error "$arch $test_name: No output generated"
        fi
    else
        log_error "$arch $test_name: Assembly failed"
        cat "$LOGS_DIR/assembly_${arch}_${test_name}.log"
    fi
    
    # Cleanup on failure
    rm -f "$test_file" "$output_file" "$LOGS_DIR/assembly_${arch}_${test_name}.log"
    return 1
}

# Ensure STAS is built
if [ ! -f "bin/stas" ]; then
    log_info "Building STAS..."
    if ! make all; then
        log_error "Failed to build STAS"
        exit 1
    fi
fi

echo "========================================"
echo "STAS End-to-End Assembly Testing"
echo "========================================"

# x86-16 Tests
log_info "=== x86-16 Architecture Tests ==="

test_assembly_workflow "x86_16" "basic_mov" '
.code16
mov ax, 0x1234
mov bx, ax
nop
' 5

test_assembly_workflow "x86_16" "arithmetic" '
.code16
mov ax, 10
mov bx, 5
add ax, bx
sub ax, 3
inc cx
dec dx
' 10

test_assembly_workflow "x86_16" "stack_ops" '
.code16
push ax
push bx
pop cx
pop dx
' 8

test_assembly_workflow "x86_16" "labels_jumps" '
.code16
start:
    mov ax, 1
    jmp end
    mov bx, 2
end:
    nop
' 8

# x86-32 Tests
log_info "=== x86-32 Architecture Tests ==="

test_assembly_workflow "x86_32" "basic_mov" '
.code32
movl $0x12345678, %eax
movl %eax, %ebx
nop
' 10

test_assembly_workflow "x86_32" "arithmetic" '
.code32
movl $100, %eax
movl $50, %ebx
addl %ebx, %eax
subl $25, %eax
incl %ecx
decl %edx
' 20

test_assembly_workflow "x86_32" "memory_ops" '
.code32
movl $0x1234, %eax
movl %eax, (%esp)
movl (%esp), %ebx
' 12

# x86-64 Tests
log_info "=== x86-64 Architecture Tests ==="

test_assembly_workflow "x86_64" "basic_mov" '
.code64
movq $0x123456789ABCDEF0, %rax
movq %rax, %rbx
nop
' 15

test_assembly_workflow "x86_64" "arithmetic" '
.code64
movq $1000, %rax
movq $500, %rbx
addq %rbx, %rax
subq $100, %rax
incq %rcx
decq %rdx
' 25

test_assembly_workflow "x86_64" "extended_regs" '
.code64
movq $1, %r8
movq $2, %r9
movq $3, %r10
movq %r8, %r11
addq %r9, %r10
' 20

# ARM64 Tests
log_info "=== ARM64 Architecture Tests ==="

test_assembly_workflow "arm64" "basic_mov" '
.text
mov x0, #0x1234
mov x1, x0
nop
' 12

test_assembly_workflow "arm64" "arithmetic" '
.text
mov x0, #100
mov x1, #50
add x0, x0, x1
sub x0, x0, #25
' 16

test_assembly_workflow "arm64" "memory_ops" '
.text
mov x0, #0x1234
str x0, [sp]
ldr x1, [sp]
' 12

# RISC-V Tests
log_info "=== RISC-V Architecture Tests ==="

test_assembly_workflow "riscv" "basic_mov" '
.text
li x1, 0x1234
mv x2, x1
nop
' 12

test_assembly_workflow "riscv" "arithmetic" '
.text
li x1, 100
li x2, 50
add x1, x1, x2
addi x1, x1, -25
' 16

test_assembly_workflow "riscv" "memory_ops" '
.text
li x1, 0x1234
sw x1, 0(sp)
lw x2, 0(sp)
' 12

# Complex multi-architecture test
log_info "=== Complex Program Tests ==="

test_assembly_workflow "x86_64" "complex_program" '
.code64
.global _start

.data
message: .ascii "Hello"
number: .quad 42

.text
_start:
    movq $1, %rax
    movq $2, %rbx
    addq %rbx, %rax
    
    ; Loop example
    movq $5, %rcx
loop:
    decq %rcx
    jnz loop
    
    ; Memory access
    movq number(%rip), %rdx
    incq %rdx
    
    ; Function call simulation
    pushq %rax
    call function
    popq %rbx
    
    movq $60, %rax
    syscall

function:
    movq $100, %rax
    ret
' 50

# Test error handling
log_info "=== Error Handling Tests ==="

# Test invalid instruction (should fail gracefully)
log_info "Testing error handling for invalid instruction"
echo "invalid_instruction eax, ebx" > test_error.s
if ./bin/stas test_error.s -o test_error.out > "$LOGS_DIR/error_test.log" 2>&1; then
    log_error "Error test: Should have failed for invalid instruction"
else
    log_success "Error test: Correctly rejected invalid instruction"
    ((PASSED_TESTS++))
fi
((TOTAL_TESTS++))
rm -f test_error.s test_error.out "$LOGS_DIR/error_test.log"

# Test empty file
log_info "Testing empty file handling"
touch test_empty.s
if ./bin/stas test_empty.s -o test_empty.out > "$LOGS_DIR/empty_test.log" 2>&1; then
    log_success "Error test: Empty file handled correctly"
    ((PASSED_TESTS++))
else
    log_error "Error test: Failed to handle empty file"
fi
((TOTAL_TESTS++))
rm -f test_empty.s test_empty.out "$LOGS_DIR/empty_test.log"

# Results
echo ""
echo "========================================"
echo "End-to-End Assembly Test Results"
echo "========================================"
echo "Total tests: $TOTAL_TESTS"
echo "Passed: $PASSED_TESTS"
echo "Failed: $((TOTAL_TESTS - PASSED_TESTS))"

if [ $PASSED_TESTS -eq $TOTAL_TESTS ]; then
    log_success "🎉 All end-to-end assembly tests passed!"
    echo ""
    echo "✅ x86-16 assembly: Working"
    echo "✅ x86-32 assembly: Working"
    echo "✅ x86-64 assembly: Working"
    echo "✅ ARM64 assembly: Working"
    echo "✅ RISC-V assembly: Working"
    echo "✅ Error handling: Working"
    exit 0
else
    log_error "❌ Some end-to-end tests failed!"
    echo "Failed: $((TOTAL_TESTS - PASSED_TESTS))/$TOTAL_TESTS tests"
    exit 1
fi
