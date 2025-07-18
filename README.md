# STAS - STIX Modular Assembler

A modular, multi-architecture assembler supporting AT&T syntax for various CPU architectures including x86-64, ARM64, and RISC-V.

## Project Status

**Current Version**: v0.0.1 (Foundation Complete)

📊 **[Project State Analysis](PROJECT_STATE_ANALYSIS.md)** - Comprehensive technical analysis and development roadmap

**Status**: 🟡 **Foundation Complete - Ready for Core Implementation**
- ✅ **Architecture & Design**: Comprehensive and well-documented  
- ✅ **Build System**: Production-ready with static builds and testing
- ✅ **Lexical Analysis**: Complete AT&T syntax tokenizer
- ✅ **Testing Framework**: Unicorn Engine integration working
- 🟡 **Parser**: Interface defined, implementation needed
- 🔴 **Code Generation**: Not implemented
- 🔴 **Architecture Modules**: Not implemented

## Documentation

- 📋 **[Project State Analysis](PROJECT_STATE_ANALYSIS.md)** - Current status and development roadmap
- 🏗️ **[Architecture Design](ARCHITECTURE.md)** - Detailed technical design
- 📦 **[Static Builds](STATIC_BUILDS.md)** - Resource-constrained deployment
- 🧪 **[Unicorn Installation](UNICORN_INSTALLATION.md)** - Testing framework setup
- 📈 **[Implementation Status](IMPLEMENTATION_STATUS.md)** - Current progress details

## Quick Start

```bash
# Clone and build
git clone <repository-url>
cd stas
make

# Test the assembler
make test

# Install Unicorn Engine for testing (optional)
sudo apt-get install libunicorn-dev
make test-unicorn

# Create a static build for deployment
make static-x86_64
```

## Project Structure

```
stas/
├── src/           # Source files (.c)
│   ├── core/      # Core assembler engine
│   ├── arch/      # Architecture-specific modules
│   ├── formats/   # Object file format handlers
│   └── utils/     # Utility functions
├── include/       # Header files (.h)
├── obj/           # Object files (generated)
├── bin/           # Executable files (generated)
├── Makefile       # Build configuration
├── README.md      # This file
└── ARCHITECTURE.md # Detailed design documentation
```

## Requirements

- GCC compiler with C99 support
- Make utility
- POSIX-compliant system for dynamic loading (dlopen)

### Optional (for testing):
- Unicorn Engine (multi-architecture instruction emulation)

**Installation**: See `UNICORN_INSTALLATION.md` for detailed setup instructions.

Quick install on Ubuntu/Debian:
```bash
sudo apt-get install libunicorn-dev
```

## Features

- **Multi-Architecture Support**: x86-16, x86-32, x86-64, ARM64, RISC-V with plugin architecture
- **AT&T Syntax**: Consistent AT&T-style assembly syntax across all architectures
- **Modular Design**: Each architecture implemented as separate module
- **Extensible**: Easy to add new CPU architectures
- **Standard Compliance**: Generates standard object file formats (ELF, Mach-O, PE, COFF)

## Usage

### Basic Assembly
```bash
# Assemble for x86-16 (16-bit mode)
./bin/stas --arch=x86_16 -o output.o input.s

# Assemble for x86-32 (32-bit mode)
./bin/stas --arch=x86_32 -o output.o input.s

# Assemble for x86-64 (64-bit mode)
./bin/stas --arch=x86_64 -o output.o input.s

# Assemble for ARM64
./bin/stas --arch=arm64 -o output.o input.s

# Assemble for RISC-V
./bin/stas --arch=riscv -o output.o input.s
```

### Example AT&T Syntax
```assembly
.section .text
.global _start

_start:
    movq $message, %rdi     # Load message address
    movq $14, %rsi          # Message length
    movq $1, %rax           # sys_write
    syscall
    
    movq $60, %rax          # sys_exit
    movq $0, %rdi           # Exit status
    syscall

.section .data
message: .ascii "Hello, World!\n"
```

## Building

### Build the project:
```bash
make
```

### Build with debug symbols:
```bash
make debug
```

## Static Builds for Resource-Constrained Systems

STAS supports building **static, architecture-specific assemblers** perfect for embedded systems and deployment scenarios with limited resources.

### Quick Start
```bash
# Build static x86-64 assembler (829KB, self-contained)
make static-x86_64

# Use the static assembler
./bin/stas-x86_64-static --help
./bin/stas-x86_64-static -o program.o program.s
```

### Benefits
- ✅ **Self-contained**: No external dependencies
- ✅ **Single-architecture**: Only includes needed functionality  
- ✅ **Portable**: Runs on any compatible system
- ✅ **Embedded-friendly**: Perfect for resource-constrained environments

See **[Static Builds Documentation](STATIC_BUILDS.md)** for complete setup and usage guide.

### Build and run:
```bash
make run
```

## Available Make Targets

- `make` or `make all` - Build the project
- `make test` - Build and test with sample assembly
- `make test-unicorn` - Run Unicorn Engine emulation tests
- `make test-unicorn-build` - Build Unicorn test program
- `make test-all` - Run all tests (syntax + emulation)
- `make static-x86_16` - Build static x86-16 only assembler
- `make static-x86_32` - Build static x86-32 only assembler
- `make static-x86_64` - Build static x86-64 only assembler
- `make static-arm64` - Build static ARM64 only assembler
- `make static-riscv` - Build static RISC-V only assembler
- `make static-all` - Build all static architecture variants
- `make clean` - Remove object files and executable
- `make distclean` - Remove all generated files and directories
- `make run` - Build and run the program
- `make install` - Install the program to /usr/local/bin (requires sudo)
- `make uninstall` - Remove the program from /usr/local/bin (requires sudo)
- `make help` - Show available targets

## Compiler Flags

The project uses the following C99-compliant compiler flags:

- `-std=c99` - Use C99 standard
- `-Wall` - Enable all common warnings
- `-Wextra` - Enable extra warnings
- `-Wpedantic` - Enable pedantic warnings for strict standard compliance
- `-O2` - Optimization level 2 (release builds)
- `-g` - Include debug symbols (debug builds)
- `-DDEBUG` - Define DEBUG macro (debug builds)

## Adding New Files

1. Add core source files (.c) to the `src/core/` directory
2. Add architecture modules to `src/arch/<architecture>/` directories
3. Add header files (.h) to the `include/` directory
4. The Makefile will automatically detect and compile new source files

## Architecture Support

Currently planned architectures:
- **x86-16**: Intel 8086/80286 16-bit instruction set
- **x86-32**: Intel 80386+ 32-bit instruction set (IA-32)
- **x86-64**: Full Intel/AMD 64-bit instruction set
- **ARM64**: AArch64 instruction set
- **RISC-V**: RV64I base instruction set

### Related Documentation
- 📋 **[Project State Analysis](PROJECT_STATE_ANALYSIS.md)** - Development priorities and roadmap
- 🏗️ **[Architecture Design](ARCHITECTURE.md)** - Detailed technical specifications
- 🧪 **[Unicorn Engine Setup](UNICORN_INSTALLATION.md)** - Testing framework installation

## Development

### Next Steps (Phase 1)
Based on the **[Project State Analysis](PROJECT_STATE_ANALYSIS.md)**, the immediate priority is:

1. **Parser Implementation** (`src/parser.c` - 800-1200 lines estimated)
   - AST generation from tokens
   - Expression evaluation
   - Symbol resolution
   - Error reporting integration

2. **Symbol Table Implementation** (`src/symbols.c` - 400-600 lines estimated)
   - Symbol definition and storage  
   - Forward reference resolution
   - Scope management

3. **x86-64 Architecture Module** (`src/arch/x86_64.c` - 600-800 lines estimated)
   - Basic instruction encoding
   - Register validation
   - Addressing mode handling

### Adding a New Architecture

1. Create a new directory in `src/arch/<new_arch>/`
2. Implement the architecture interface defined in `include/arch_interface.h`
3. Add instruction encoding, register handling, and addressing modes
4. Update the build system to include the new module
5. Add test cases in `tests/<new_arch>/`

### Plugin Development

Each architecture is implemented as a plugin that exports the `get_arch_ops()` function:

```c
arch_ops_t *get_arch_ops(void) {
    static arch_ops_t my_arch_ops = {
        .name = "my_arch",
        .init = my_arch_init,
        .parse_instruction = my_arch_parse_instruction,
        .encode_instruction = my_arch_encode_instruction,
        // ... other function pointers
    };
    return &my_arch_ops;
}
```

## License

STAS is designed as a modular assembler framework. Add your own license as needed.
