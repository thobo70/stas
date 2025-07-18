# STAS Static Builds

## Overview

STAS supports building **static, architecture-specific assemblers** for deployment on resource-constrained systems. These builds contain only the functionality needed for a single target architecture, reducing complexity and dependencies.

## Benefits of Static Builds

### 🎯 **Resource Efficiency**
- **Single-architecture focus**: Only includes code for target architecture
- **No dynamic loading**: Eliminates plugin system overhead  
- **Reduced memory footprint**: Static builds don't load unused architecture modules
- **Faster startup**: No plugin discovery and loading

### 📦 **Deployment Advantages**
- **Self-contained executables**: No external dependencies
- **Portable**: Runs on any compatible Linux system without libraries
- **Embedded-friendly**: Perfect for embedded development environments
- **Cross-platform deployment**: Build once, deploy anywhere

### 🔧 **Simplified Interface**
- **Streamlined CLI**: No architecture selection needed
- **Focused functionality**: Specialized for single architecture
- **Reduced binary size**: No unused code paths

## Available Static Builds

| Target | Architecture | Use Case |
|--------|-------------|----------|
| `stas-x86_16-static` | Intel 8086/80286 | Legacy/embedded x86 systems |
| `stas-x86_32-static` | Intel 80386+ (IA-32) | 32-bit x86 systems |
| `stas-x86_64-static` | Intel/AMD 64-bit | Modern x86 systems |
| `stas-arm64-static` | ARM 64-bit (AArch64) | ARM-based embedded systems |
| `stas-riscv-static` | RISC-V 64-bit | RISC-V development |

## Building Static Assemblers

### Build Individual Architecture
```bash
# x86-64 only assembler
make static-x86_64

# ARM64 only assembler  
make static-arm64

# x86-16 only assembler (for legacy/embedded)
make static-x86_16

# x86-32 only assembler
make static-x86_32

# RISC-V only assembler
make static-riscv
```

### Build All Static Variants
```bash
make static-all
```

### Clean Static Builds
```bash
make clean  # Removes all builds including static ones
```

## Usage Examples

### Static x86-64 Assembler
```bash
./bin/stas-x86_64-static --help
# Usage: ./bin/stas-x86_64-static [options] input.s
# Options:
#   -o, --output=FILE    Output object file
#   -v, --verbose        Verbose output
#   -d, --debug          Debug mode
#   -h, --help           Show this help message
# 
# This is a static build for Intel/AMD 64-bit architecture only.
# Target architecture: x86_64

# Assemble a file
./bin/stas-x86_64-static -o program.o program.s
```

### Static ARM64 Assembler
```bash
./bin/stas-arm64-static --version
# STAS - STIX Modular Assembler v0.0.1 (Static Build - ARM 64-bit (AArch64))
# Specialized assembler for arm64 architecture

./bin/stas-arm64-static -v -o firmware.o firmware.s
```

## Size Comparison

```bash
$ ls -lah bin/
total 2.5M
-rwxr-xr-x 1 tom tom  31K stas                    # Dynamic build
-rwxr-xr-x 1 tom tom 829K stas-arm64-static      # Static ARM64
-rwxr-xr-x 1 tom tom 829K stas-x86_16-static     # Static x86-16
-rwxr-xr-x 1 tom tom 829K stas-x86_64-static     # Static x86-64
```

**Analysis:**
- **Dynamic build**: 31KB - Requires shared libraries and runtime loading
- **Static builds**: ~829KB each - Self-contained, no external dependencies
- **Trade-off**: ~27x larger but completely portable and dependency-free

## Implementation Details

### Compile-Time Architecture Selection

Static builds use preprocessor directives to include only relevant code:

```c
#ifdef STATIC_BUILD
  #ifdef ARCH_X86_64_ONLY
    #define STATIC_ARCH "x86_64"
    #define STATIC_ARCH_NAME "Intel/AMD 64-bit"
  #endif
#endif
```

### Disabled Features in Static Builds

- **No plugin loading**: `dlopen()` calls are conditionally compiled out
- **No architecture selection**: `-a/--arch` option not available
- **No architecture listing**: `-l/--list-archs` option not available
- **Fixed target**: Architecture determined at compile time

### Build Configuration

```makefile
# Static build flags
STATIC_CFLAGS = -std=c99 -Wall -Wextra -Wpedantic -O2 -static -DSTATIC_BUILD
STATIC_LDFLAGS = 

# Architecture-specific defines
ARCH_X86_64_CFLAGS = -DARCH_X86_64_ONLY
```

## Use Cases

### 1. **Embedded Development**
```bash
# Copy static assembler to embedded development board
scp bin/stas-arm64-static user@embedded-board:/usr/local/bin/
```

### 2. **Legacy System Support**
```bash
# x86-16 assembler for 8086/80286 development
./bin/stas-x86_16-static -o bootloader.o boot.s
```

### 3. **Containerized Builds**
```dockerfile
# Docker multi-stage build
FROM alpine AS build
COPY bin/stas-x86_64-static /usr/local/bin/stas
# No additional dependencies needed
```

### 4. **Cross-Platform Development**
```bash
# Build on development machine, deploy to target
make static-arm64
scp bin/stas-arm64-static target-device:/tools/
```

## Integration with Build Systems

### Makefile Integration
```makefile
# Use static assembler in project builds
ASM_STATIC = bin/stas-x86_64-static

%.o: %.s
	$(ASM_STATIC) -o $@ $<
```

### CI/CD Pipeline
```yaml
# GitHub Actions example
- name: Build static assemblers
  run: make static-all
  
- name: Test static builds
  run: |
    ./bin/stas-x86_64-static --version
    ./bin/stas-arm64-static --version
```

## Future Enhancements

### Planned Features
1. **Cross-compilation support**: Build ARM64 assembler on x86 host
2. **Size optimization**: Strip unnecessary symbols and sections
3. **Architecture bundles**: Multi-architecture static builds
4. **Alpine Linux packages**: Minimal static distribution packages

### Optimization Opportunities
1. **Link-time optimization**: `-flto` for smaller binaries
2. **Symbol stripping**: `strip` command for deployment builds
3. **Compression**: UPX packing for even smaller binaries

## Conclusion

Static builds provide STAS with:

- ✅ **Deployment flexibility** - Self-contained, portable executables
- ✅ **Resource efficiency** - Single-architecture focus reduces overhead
- ✅ **Simplified deployment** - No dependency management required
- ✅ **Embedded-system friendly** - Perfect for resource-constrained environments

This makes STAS suitable for a wide range of deployment scenarios, from embedded development to legacy system support, while maintaining the full power of the modular assembler architecture.
