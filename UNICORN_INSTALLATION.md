# Unicorn Engine Installation Guide for STAS

## Overview

Unicorn Engine is a lightweight, multi-platform, multi-architecture CPU emulator framework based on QEMU. STAS uses Unicorn Engine for automated testing and validation of assembled code across all supported architectures.

## Quick Installation (Recommended)

**For most users, package manager installation is preferred over building from Git source.**

### Ubuntu/Debian (Recommended)
```bash
# Install from package manager (stable, tested, easy updates)
sudo apt-get update
sudo apt-get install libunicorn-dev

# Verify installation
pkg-config --exists unicorn && echo "Unicorn Engine installed successfully"
```

### Fedora/CentOS/RHEL
```bash
# Fedora
sudo dnf install unicorn-devel

# CentOS/RHEL (requires EPEL)
sudo yum install epel-release
sudo yum install unicorn-devel
```

### Arch Linux
```bash
sudo pacman -S unicorn
```

### macOS (Homebrew)
```bash
brew install unicorn
```

## Building from Source (Git) - Advanced Users Only

**⚠️ Only use this method if:**
- You need features from the latest version (2.1.3+)
- Package manager version doesn't work for your system
- You're contributing to Unicorn Engine development

**For STAS testing, the package manager version (2.0.1+) is sufficient and recommended.**

## Installation Method Comparison

| Method | Pros | Cons | Recommended For |
|--------|------|------|-----------------|
| **Package Manager** | ✅ Fast installation<br>✅ Automatic updates<br>✅ Dependency management<br>✅ System integration<br>✅ Security updates | ❌ Slightly older version | **Most users, production** |
| **Git Source** | ✅ Latest features<br>✅ Latest bug fixes<br>✅ Custom build options | ❌ Longer installation<br>❌ Manual dependency management<br>❌ No automatic updates<br>❌ Compilation can fail | **Developers, bleeding-edge needs** |

**Current Versions:**
- Package Manager: 2.0.1 (stable, tested)
- Git Latest: 2.1.3 (newer, but 2.0.1 works fine for STAS)

### Prerequisites
```bash
# Ubuntu/Debian
sudo apt-get install build-essential cmake python3-dev

# Fedora
sudo dnf groupinstall "Development Tools"
sudo dnf install cmake python3-devel

# macOS
xcode-select --install
brew install cmake
```

### Build Steps
```bash
# Clone the repository
git clone https://github.com/unicorn-engine/unicorn.git
cd unicorn

# Build and install
make
sudo make install

# Update library cache (Linux only)
sudo ldconfig

# Verify installation
pkg-config --exists unicorn && echo "Unicorn Engine built and installed successfully"
```

## Verification and Testing

### Check Installation
```bash
# Method 1: Using pkg-config
pkg-config --exists unicorn
echo $?  # Should output 0 if installed

# Method 2: Check library files
ldconfig -p | grep unicorn

# Method 3: Check header files
ls /usr/include/unicorn/ 2>/dev/null || ls /usr/local/include/unicorn/
```

### Test with STAS
```bash
# Navigate to STAS project directory
cd /path/to/stas

# Run Unicorn Engine tests
make test-unicorn

# Expected output with Unicorn installed:
# ==========================================
# STAS Unicorn Engine Test Suite
# ==========================================
# [INFO] Unicorn Engine development libraries found (pkg-config)
# Testing assembly syntax validation...
# [PASS] x86_16 syntax test: Assembly validation successful
# [PASS] x86_32 syntax test: Assembly validation successful
# [PASS] x86_64 syntax test: Assembly validation successful
# Testing Unicorn Engine emulation...
# [PASS] Unicorn emulation test: Multi-architecture instruction execution successful
```

### Manual Test Program
Create a simple test to verify Unicorn works:

```bash
# Create test file
cat > test_unicorn_install.c << 'EOF'
#include <stdio.h>
#include <unicorn/unicorn.h>

int main() {
    uc_engine *uc;
    uc_err err;
    
    printf("Testing Unicorn Engine installation...\n");
    
    // Try to initialize x86-64 emulator
    err = uc_open(UC_ARCH_X86, UC_MODE_64, &uc);
    if (err != UC_ERR_OK) {
        printf("FAIL: Cannot initialize Unicorn Engine: %s\n", uc_strerror(err));
        return 1;
    }
    
    printf("SUCCESS: Unicorn Engine is working correctly!\n");
    printf("Version: %u.%u.%u\n", 
           (uc_version(NULL) >> 8) & 0xff,
           uc_version(NULL) & 0xff,
           (uc_version(NULL) >> 16) & 0xff);
    
    uc_close(uc);
    return 0;
}
EOF

# Compile and run test
gcc test_unicorn_install.c -lunicorn -o test_unicorn_install
./test_unicorn_install

# Clean up
rm test_unicorn_install.c test_unicorn_install
```

## Troubleshooting

### Common Issues and Solutions

#### 1. **"Package unicorn was not found"**
```bash
# Solution 1: Update package cache
sudo apt-get update

# Solution 2: Install development package
sudo apt-get install libunicorn-dev

# Solution 3: Check if library is installed but pkg-config file missing
ls /usr/lib/*/libunicorn* || ls /usr/local/lib/libunicorn*
# If files exist, try building from source
```

#### 2. **"unicorn/unicorn.h: No such file or directory"**
```bash
# Install development headers
sudo apt-get install libunicorn-dev

# Or check alternative locations
find /usr -name "unicorn.h" 2>/dev/null
```

#### 3. **"undefined reference to uc_open"**
```bash
# Make sure to link with -lunicorn
gcc myprogram.c -lunicorn -o myprogram

# Check if library is available
ldconfig -p | grep unicorn
```

#### 4. **"error while loading shared libraries: libunicorn.so.2"**
```bash
# Update library cache
sudo ldconfig

# Check library path
export LD_LIBRARY_PATH=/usr/local/lib:$LD_LIBRARY_PATH
```

#### 5. **macOS: "library not found for -lunicorn"**
```bash
# Reinstall with Homebrew
brew uninstall unicorn
brew install unicorn

# Add to path if needed
export CPATH=/opt/homebrew/include:$CPATH
export LIBRARY_PATH=/opt/homebrew/lib:$LIBRARY_PATH
```

### Version Compatibility

STAS has been tested with:
- **Unicorn Engine 2.0.x** (Recommended)
- **Unicorn Engine 1.0.x** (Supported)

Check your version:
```bash
pkg-config --modversion unicorn
```

## Using Unicorn with STAS

### Running Tests
```bash
# Basic test suite
make test-unicorn

# Build comprehensive test program
make test-unicorn-build

# Run all tests including Unicorn
make test-all
```

### Without Unicorn Engine
If Unicorn Engine is not available, STAS will still work but with limited testing:

```bash
$ make test-unicorn
# [WARN] Unicorn Engine not available - running syntax tests only
# [PASS] x86_16 syntax test: Assembly validation successful
# [PASS] x86_32 syntax test: Assembly validation successful  
# [PASS] x86_64 syntax test: Assembly validation successful
```

### Build Integration
The STAS Makefile automatically detects Unicorn Engine:

```makefile
# From Makefile
test-unicorn-build:
	@if pkg-config --exists unicorn 2>/dev/null; then \
		gcc $(CFLAGS) `pkg-config --cflags unicorn` tests/test_unicorn_comprehensive.c `pkg-config --libs unicorn` -o tests/test_unicorn_comprehensive; \
	else \
		gcc $(CFLAGS) tests/test_unicorn_comprehensive.c -lunicorn -o tests/test_unicorn_comprehensive; \
	fi
```

## Docker Installation

For containerized environments:

```dockerfile
# Ubuntu-based container
FROM ubuntu:22.04

RUN apt-get update && apt-get install -y \
    build-essential \
    libunicorn-dev \
    pkg-config \
    && rm -rf /var/lib/apt/lists/*

# Copy STAS project
COPY . /stas
WORKDIR /stas

# Build and test
RUN make && make test-unicorn
```

## Performance Notes

- **Unicorn Engine** is designed for CPU emulation, not full system simulation
- **Memory usage**: Minimal overhead compared to full emulators like QEMU
- **Speed**: Fast enough for continuous integration and automated testing
- **Architecture support**: Same architectures as STAS (x86-16/32/64, ARM64, RISC-V)

## Integration Benefits

With Unicorn Engine installed, STAS provides:

1. **✅ Instruction-level validation** - Verify assembled code executes correctly
2. **✅ Register state checking** - Confirm expected register values after execution  
3. **✅ Memory operation testing** - Validate memory reads/writes
4. **✅ Cross-architecture testing** - Same test framework across all architectures
5. **✅ Automated CI/CD integration** - Reliable testing in build pipelines

## Next Steps

After installing Unicorn Engine:

1. **Run the test suite**: `make test-all`
2. **Check the comprehensive tests**: `make test-unicorn-build && tests/test_unicorn_comprehensive`
3. **Integrate with your development workflow**: Use `make test-unicorn` during development
4. **Read the implementation details**: See `UNICORN_IMPLEMENTATION.md` for technical details

## Support

- **Unicorn Engine Documentation**: https://www.unicorn-engine.org/docs/
- **GitHub Repository**: https://github.com/unicorn-engine/unicorn
- **STAS Integration**: See `tests/test_unicorn_comprehensive.c` for usage examples
