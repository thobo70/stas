#!/bin/bash

# STAS Build Variant Testing Script
# Tests all build configurations to ensure they work correctly

# Setup logs directory
LOGS_DIR="logs"
mkdir -p "$LOGS_DIR"

BUILD_VARIANTS=(
    "dynamic:all"
    "static:x86_16"
    "static:x86_32"
    "static:x86_64"
    "static:arm64"
    "static:riscv"
    "debug:all"
)

ARCHITECTURES=(
    "x86_16"
    "x86_32"
    "x86_64"
    "arm64"
    "riscv"
)

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

# Counters
TOTAL_TESTS=0
PASSED_TESTS=0
FAILED_TESTS=0

log_info() {
    echo -e "${YELLOW}[INFO]${NC} $1"
}

log_success() {
    echo -e "${GREEN}[PASS]${NC} $1"
}

log_error() {
    echo -e "${RED}[FAIL]${NC} $1"
}

test_build_variant() {
    local variant=$1
    local arch=$2
    
    ((TOTAL_TESTS++))
    
    log_info "Testing build variant: $variant for architecture: $arch"
    
    # Clean previous builds
    make clean > /dev/null 2>&1
    
    # Build the variant
    local build_success=false
    case $variant in
        "dynamic")
            if make all > "$LOGS_DIR/build_${variant}_${arch}.log" 2>&1; then
                build_success=true
            fi
            ;;
        "static")
            if make static-$arch > "$LOGS_DIR/build_${variant}_${arch}.log" 2>&1; then
                build_success=true
            fi
            ;;
        "debug")
            if make debug > "$LOGS_DIR/build_${variant}_${arch}.log" 2>&1; then
                build_success=true
            fi
            ;;
    esac
    
    if [ "$build_success" = true ]; then
        log_success "Build successful: $variant-$arch"
        
        # Test the built binary (simplified)
        if test_binary_basic "$variant" "$arch"; then
            ((PASSED_TESTS++))
            return 0
        else
            ((FAILED_TESTS++))
            return 1
        fi
    else
        log_error "Build failed: $variant-$arch"
        ((FAILED_TESTS++))
        return 1
    fi
}

test_binary_basic() {
    local variant=$1
    local arch=$2
    
    # Get the appropriate binary
    local binary
    case $variant in
        "dynamic"|"debug")
            binary="bin/stas"
            ;;
        "static")
            binary="bin/stas-$arch-static"
            ;;
    esac
    
    # Test basic help functionality
    if timeout 5s "$binary" --help >/dev/null 2>&1; then
        log_success "Binary test passed: $variant-$arch"
        return 0
    else
        log_error "Binary test failed: $variant-$arch"
        return 1
    fi
}

test_build_configuration() {
    log_info "Testing build system configuration"
    
    # Check for required files
    if [ ! -f "Makefile" ]; then
        log_error "Makefile not found"
        return 1
    fi
    
    if [ ! -d "src" ]; then
        log_error "Source directory not found"
        return 1
    fi
    
    if [ ! -d "include" ]; then
        log_error "Include directory not found"
        return 1
    fi
    
    # Ensure output directories exist
    mkdir -p bin
    
    log_success "Build configuration verified"
    return 0
}

main() {
    echo "========================================"
    echo "STAS Build Variant Testing"
    echo "========================================"
    
    # Test build configuration first
    if ! test_build_configuration; then
        return 1
    fi
    
    # Test each variant
    for variant_spec in "${BUILD_VARIANTS[@]}"; do
        IFS=':' read -r variant target_arch <<< "$variant_spec"
        
        if [ "$target_arch" = "all" ]; then
            # Test all architectures for this variant
            for arch in "${ARCHITECTURES[@]}"; do
                test_build_variant "$variant" "$arch"
            done
        else
            # Test specific architecture
            test_build_variant "$variant" "$target_arch"
        fi
    done
    
    # Clean up build logs (they're now in logs/ directory and will be managed by git ignore)
    # rm -f $LOGS_DIR/build_*.log 2>/dev/null
    
    echo "========================================"
    echo "Build Variant Test Results"
    echo "========================================"
    echo "Total tests: $TOTAL_TESTS"
    echo "Passed: $PASSED_TESTS"
    echo "Failed: $FAILED_TESTS"
    
    if [ $FAILED_TESTS -eq 0 ]; then
        log_success "✅ All build variants passed!"
        return 0
    else
        log_error "❌ Some build variants failed!"
        return 1
    fi
}

# Run main function
main "$@"
