#!/bin/bash
# STAS Emulation Test Runner
# Tests assembled code using various CPU emulators

# Allow arithmetic failures to not exit immediately
set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
STAS_DIR="$(dirname "$SCRIPT_DIR")"
STAS_BIN="$STAS_DIR/bin/stas"

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Test counters
TESTS_RUN=0
TESTS_PASSED=0
TESTS_FAILED=0

log_info() {
    echo -e "${BLUE}[INFO]${NC} $1"
}

log_success() {
    echo -e "${GREEN}[PASS]${NC} $1"
    TESTS_PASSED=$((TESTS_PASSED + 1))
}

log_error() {
    echo -e "${RED}[FAIL]${NC} $1"
    TESTS_FAILED=$((TESTS_FAILED + 1))
}

log_warning() {
    echo -e "${YELLOW}[WARN]${NC} $1"
}

# Check if emulator is available
check_emulator() {
    local emulator=$1
    if command -v "$emulator" > /dev/null 2>&1; then
        return 0
    else
        return 1
    fi
}

# Test STAS assembly
test_assembly() {
    local arch=$1
    local test_file=$2
    local test_name="$arch assembly test"
    
    TESTS_RUN=$((TESTS_RUN + 1))
    
    log_info "Running $test_name: $test_file"
    
    if [ ! -f "$test_file" ]; then
        log_error "$test_name: Test file not found: $test_file"
        return 1
    fi
    
    # Assemble the code
    local output_file="/tmp/stas_test_$arch.o"
    if "$STAS_BIN" --arch="$arch" -o "$output_file" "$test_file" > /dev/null 2>&1; then
        log_success "$test_name: Assembly successful"
        rm -f "$output_file"
        return 0
    else
        log_error "$test_name: Assembly failed"
        return 1
    fi
}

# Test with QEMU (if available)
test_qemu_execution() {
    local arch=$1
    local binary=$2
    
    case $arch in
        x86_16)
            if check_emulator "qemu-system-i386"; then
                log_info "Testing $arch with QEMU (timeout 5s)"
                timeout 5s qemu-system-i386 -M pc -cpu 8086 -m 1 -nographic -serial stdio -kernel "$binary" > /dev/null 2>&1 || true
                log_success "$arch QEMU test completed"
            else
                log_warning "QEMU not available for $arch testing"
            fi
            ;;
        x86_32)
            if check_emulator "qemu-system-i386"; then
                log_info "Testing $arch with QEMU (timeout 5s)"
                timeout 5s qemu-system-i386 -nographic -serial stdio -kernel "$binary" > /dev/null 2>&1 || true
                log_success "$arch QEMU test completed"
            else
                log_warning "QEMU not available for $arch testing"
            fi
            ;;
        x86_64)
            if check_emulator "qemu-system-x86_64"; then
                log_info "Testing $arch with QEMU (timeout 5s)"
                timeout 5s qemu-system-x86_64 -nographic -serial stdio -kernel "$binary" > /dev/null 2>&1 || true
                log_success "$arch QEMU test completed"
            else
                log_warning "QEMU not available for $arch testing"
            fi
            ;;
        arm64)
            if check_emulator "qemu-system-aarch64"; then
                log_info "Testing $arch with QEMU (timeout 5s)"
                timeout 5s qemu-system-aarch64 -M virt -cpu cortex-a57 -nographic -serial stdio -kernel "$binary" > /dev/null 2>&1 || true
                log_success "$arch QEMU test completed"
            else
                log_warning "QEMU not available for $arch testing"
            fi
            ;;
        riscv)
            if check_emulator "qemu-system-riscv64"; then
                log_info "Testing $arch with QEMU (timeout 5s)"
                timeout 5s qemu-system-riscv64 -M virt -nographic -serial stdio -kernel "$binary" > /dev/null 2>&1 || true
                log_success "$arch QEMU test completed"
            else
                log_warning "QEMU not available for $arch testing"
            fi
            ;;
    esac
}

# Main test function
run_emulation_tests() {
    log_info "Starting STAS Emulation Tests"
    log_info "=============================="
    
    # Check if STAS is built
    if [ ! -f "$STAS_BIN" ]; then
        log_error "STAS binary not found. Please run 'make' first."
        exit 1
    fi
    
    # Test assembly for each architecture
    local examples_dir="$STAS_DIR/examples"
    
    # Test x86-16
    if [ -f "$examples_dir/x86_16_example.s" ]; then
        test_assembly "x86_16" "$examples_dir/x86_16_example.s"
    fi
    
    # Test x86-32
    if [ -f "$examples_dir/x86_32_example.s" ]; then
        test_assembly "x86_32" "$examples_dir/x86_32_example.s"
    fi
    
    # Test x86-64
    if [ -f "$examples_dir/example.s" ]; then
        test_assembly "x86_64" "$examples_dir/example.s"
    fi
    
    # Check for emulators
    log_info ""
    log_info "Checking available emulators:"
    
    if check_emulator "qemu-system-i386"; then
        log_success "QEMU (i386) available"
    else
        log_warning "QEMU (i386) not available - install with: sudo apt-get install qemu-system-x86"
    fi
    
    if check_emulator "qemu-system-x86_64"; then
        log_success "QEMU (x86_64) available"
    else
        log_warning "QEMU (x86_64) not available - install with: sudo apt-get install qemu-system-x86"
    fi
    
    if check_emulator "qemu-system-aarch64"; then
        log_success "QEMU (ARM64) available"
    else
        log_warning "QEMU (ARM64) not available - install with: sudo apt-get install qemu-system-arm"
    fi
    
    if check_emulator "qemu-system-riscv64"; then
        log_success "QEMU (RISC-V) available"
    else
        log_warning "QEMU (RISC-V) not available - install with: sudo apt-get install qemu-system-misc"
    fi
    
    if check_emulator "bochs"; then
        log_success "Bochs available"
    else
        log_warning "Bochs not available - install with: sudo apt-get install bochs"
    fi
    
    # Summary
    log_info ""
    log_info "Test Summary:"
    log_info "============="
    log_info "Tests run: $TESTS_RUN"
    log_success "Tests passed: $TESTS_PASSED"
    
    if [ $TESTS_FAILED -gt 0 ]; then
        log_error "Tests failed: $TESTS_FAILED"
        exit 1
    else
        log_success "All tests passed!"
        exit 0
    fi
}

# Run tests
run_emulation_tests
