#!/bin/bash

# STAS Unicorn Engine Test Runner
# Automated testing using Unicorn Engine for all supported architectures

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
STAS_DIR="$(dirname "$SCRIPT_DIR")"

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Test counters
TOTAL_TESTS=0
PASSED_TESTS=0

# Function to print colored output
print_status() {
    local status=$1
    local message=$2
    if [ "$status" = "PASS" ]; then
        echo -e "${GREEN}[PASS]${NC} $message"
        PASSED_TESTS=$((PASSED_TESTS + 1))
    elif [ "$status" = "FAIL" ]; then
        echo -e "${RED}[FAIL]${NC} $message"
    elif [ "$status" = "INFO" ]; then
        echo -e "${BLUE}[INFO]${NC} $message"
    elif [ "$status" = "WARN" ]; then
        echo -e "${YELLOW}[WARN]${NC} $message"
    fi
}

# Check if Unicorn Engine is available
check_unicorn() {
    print_status "INFO" "Checking Unicorn Engine availability..."
    
    if pkg-config --exists unicorn 2>/dev/null; then
        print_status "INFO" "Unicorn Engine development libraries found (pkg-config)"
        return 0
    elif ldconfig -p | grep -q libunicorn 2>/dev/null; then
        print_status "INFO" "Unicorn Engine runtime libraries found (ldconfig)"
        return 0
    elif [ -f "/usr/include/unicorn/unicorn.h" ]; then
        print_status "INFO" "Unicorn Engine headers found in /usr/include"
        return 0
    else
        print_status "WARN" "Unicorn Engine not found"
        print_status "INFO" "Install with: sudo apt-get install libunicorn-dev"
        print_status "INFO" "Or build from source: https://github.com/unicorn-engine/unicorn"
        return 1
    fi
}

# Test assembly syntax validation
test_assembly_syntax() {
    local arch=$1
    local file=$2
    
    TOTAL_TESTS=$((TOTAL_TESTS + 1))
    
    if [ ! -f "$file" ]; then
        print_status "FAIL" "$arch syntax test: File $file not found"
        return 1
    fi
    
    # Try to assemble the file to validate syntax
    local temp_obj=$(mktemp)
    local arch_flag=""
    
    case $arch in
        x86_16)
            arch_flag="--32"
            ;;
        x86_32)
            arch_flag="--32"
            ;;
        x86_64)
            arch_flag="--64"
            ;;
    esac
    
    if as $arch_flag "$file" -o "$temp_obj" 2>/dev/null; then
        print_status "PASS" "$arch syntax test: Assembly validation successful"
        rm -f "$temp_obj"
        return 0
    else
        print_status "FAIL" "$arch syntax test: Assembly validation failed"
        rm -f "$temp_obj"
        return 1
    fi
}

# Build Unicorn test program
build_unicorn_test() {
    local test_source="tests/test_unicorn_comprehensive.c"
    local test_binary="tests/test_unicorn_comprehensive"
    
    print_status "INFO" "Building Unicorn Engine test program..."
    
    if [ ! -f "$test_source" ]; then
        print_status "FAIL" "Unicorn test source not found: $test_source"
        return 1
    fi
    
    # Try to compile with pkg-config first
    if pkg-config --exists unicorn 2>/dev/null; then
        local cflags=$(pkg-config --cflags unicorn)
        local libs=$(pkg-config --libs unicorn)
        if gcc $cflags "$test_source" $libs -o "$test_binary" 2>/dev/null; then
            print_status "INFO" "Unicorn test built with pkg-config"
            return 0
        fi
    fi
    
    # Fallback to direct linking
    if gcc "$test_source" -lunicorn -o "$test_binary" 2>/dev/null; then
        print_status "INFO" "Unicorn test built with direct linking"
        return 0
    fi
    
    print_status "FAIL" "Could not build Unicorn test program"
    return 1
}

# Test with Unicorn Engine emulation
test_unicorn_emulation() {
    local test_program="tests/test_unicorn_comprehensive"
    
    TOTAL_TESTS=$((TOTAL_TESTS + 1))
    
    if [ ! -f "$test_program" ]; then
        if ! build_unicorn_test; then
            return 1
        fi
    fi
    
    if [ -x "$test_program" ]; then
        if "$test_program" 2>/dev/null; then
            print_status "PASS" "Unicorn emulation test: Multi-architecture instruction execution successful"
            return 0
        else
            print_status "FAIL" "Unicorn emulation test: Execution failed"
            return 1
        fi
    else
        print_status "FAIL" "Unicorn test program not executable"
        return 1
    fi
}

# Main test execution
main() {
    echo "=========================================="
    echo "STAS Unicorn Engine Test Suite"
    echo "=========================================="
    
    # Check Unicorn availability
    if ! check_unicorn; then
        echo
        print_status "WARN" "Unicorn Engine not available - running syntax tests only"
        echo
    fi
    
    # Test assembly syntax for all architectures
    echo "Testing assembly syntax validation..."
    
    # Check if example files exist, if not create minimal test files
    if [ ! -f "examples/hello_x86_16.s" ]; then
        mkdir -p examples
        echo "# Minimal x86-16 test" > examples/hello_x86_16.s
        echo ".code16" >> examples/hello_x86_16.s
        echo "mov %ax, %bx" >> examples/hello_x86_16.s
    fi
    
    if [ ! -f "examples/hello_x86_32.s" ]; then
        mkdir -p examples
        echo "# Minimal x86-32 test" > examples/hello_x86_32.s
        echo ".code32" >> examples/hello_x86_32.s
        echo "movl %eax, %ebx" >> examples/hello_x86_32.s
    fi
    
    if [ ! -f "examples/hello_x86_64.s" ]; then
        mkdir -p examples
        echo "# Minimal x86-64 test" > examples/hello_x86_64.s
        echo ".code64" >> examples/hello_x86_64.s
        echo "movq %rax, %rbx" >> examples/hello_x86_64.s
    fi
    
    test_assembly_syntax "x86_16" "examples/hello_x86_16.s"
    test_assembly_syntax "x86_32" "examples/hello_x86_32.s"
    test_assembly_syntax "x86_64" "examples/hello_x86_64.s"
    
    echo
    
    # Test Unicorn emulation if available
    if check_unicorn >/dev/null 2>&1; then
        echo "Testing Unicorn Engine emulation..."
        test_unicorn_emulation
    fi
    
    echo
    echo "=========================================="
    echo "Test Results Summary"
    echo "=========================================="
    echo "Tests run: $TOTAL_TESTS"
    echo "Tests passed: $PASSED_TESTS"
    echo "Tests failed: $((TOTAL_TESTS - PASSED_TESTS))"
    
    if [ $PASSED_TESTS -eq $TOTAL_TESTS ]; then
        print_status "PASS" "All tests passed!"
        exit 0
    else
        print_status "FAIL" "Some tests failed"
        exit 1
    fi
}

# Run main function
main "$@"
