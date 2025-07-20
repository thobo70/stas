# STAS - STIX Modular Assembler

A modular, multi-architecture assembler supporting AT&T syntax for various CPU architectures including x86-64, x86-32, x86-16, ARM64, and RISC-V.

## Project Status

**Current Version**: v0.7.0 (Phase 7 Complete - Advanced Language Features)

📊 **[Project Status](PROJECT_STATUS.md)** - Comprehensive technical status and development roadmap

**Status**: ✅ **Phase 7 Advanced Language Features Complete**
- ✅ **Macro Processing**: Complete C-style macro system with #define support
- ✅ **Include Directives**: Full .include functionality for file inclusion
- ✅ **Conditional Assembly**: Complete preprocessor with #ifdef/#ifndef/#else/#endif
- ✅ **Advanced Expressions**: Complex expression evaluation in immediate values
- ✅ **Architecture Support**: 5 complete architectures (x86_16, x86_32, x86_64, ARM64, RISC-V)
- ✅ **Output Formats**: 6 complete formats including Intel HEX and Motorola S-Record
- ✅ **Regression Testing**: Comprehensive Phase 7 test suite with 100% pass rate

## Documentation

- 📖 **[User Guide](USER_GUIDE.md)** - Comprehensive user manual with command-line options, mnemonics, and format details
- ⚡ **[Quick Reference](QUICK_REFERENCE.md)** - Command-line quick reference and examples
- 📊 **[Project Status](PROJECT_STATUS.md)** - Comprehensive technical status and implementation details
- 🏗️ **[Architecture Design](ARCHITECTURE.md)** - Detailed technical design
- 🎯 **[Phase Milestones](PROJECT_STATUS.md#milestones)** - All phase completion records
- 📦 **[Static Builds](STATIC_BUILDS.md)** - Resource-constrained deployment
- 🧪 **[Unicorn Installation](UNICORN_INSTALLATION.md)** - Testing framework setup

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

## x86_16 Architecture - Complete Implementation

🎯 **FULLY IMPLEMENTED**: Complete 16-bit Intel 8086/80286 instruction set support

### ✅ Supported Instructions
- **Data Movement**: MOV (register/immediate/memory)
- **Arithmetic**: ADD, SUB, CMP (register/immediate combinations)
- **Stack Operations**: PUSH, POP (all 16-bit registers)
- **Control Flow**: JMP, CALL, RET, conditional jumps (JE, JNE, JL, JG)
- **System**: INT (DOS interrupts), HLT, NOP

### ✅ Output Formats (All Architectures)
- **Flat Binary** (`-f bin`): Raw machine code output (default)
- **DOS .COM** (`-f com`): MS-DOS executable format (x86_16 only)
- **ELF32** (`-f elf32`): 32-bit ELF object files (x86_32, arm64)
- **ELF64** (`-f elf64`): 64-bit ELF object files (x86_64, arm64)
- **Intel HEX** (`-f hex`): Embedded programming format with checksum validation
- **Motorola S-Record** (`-f srec`): Microcontroller programming format with multiple address sizes

### ✅ Validation & Testing
- **CPU Emulation**: Unicorn Engine validates generated machine code for all architectures
- **Comprehensive Test Suites**: Phase-based testing from parsing to code generation
- **Real Machine Code**: Produces actual executable assembly for x86_16, x86_32, x86_64, ARM64
- **Format Verification**: All output formats tested and validated

### 🔧 Command Line Examples
```bash
# Generate DOS .COM file
./bin/stas -a x86_16 -f com -o hello.com hello.s

# Generate raw binary at specific address
./bin/stas -a x86_16 -f flat -b 0x7C00 -o boot.bin boot.s

# Generate flat binary (default)
./bin/stas -a x86_16 -o program.bin program.s
```

## Project Structure

```
stas/
├── src/                 # Source files (.c)
│   ├── core/            # Core assembler engine
│   │   ├── parser.c     # Main parser with AST management
│   │   ├── expr.c       # Expression parser with operator precedence
│   │   └── output_format.c  # Output format interface manager
│   ├── arch/            # Architecture-specific modules
│   │   ├── arch_interface.h  # Architecture plugin interface
│   │   ├── x86_16/      # Complete x86-16 implementation
│   │   ├── x86_32/      # Complete x86-32 implementation  
│   │   ├── x86_64/      # Complete x86-64 implementation
│   │   ├── arm64/       # Complete ARM64/AArch64 implementation
│   │   └── riscv/       # RISC-V implementation (planned)
│   ├── formats/         # Output format implementations
│   │   ├── elf.c        # ELF32/ELF64 object file format
│   │   ├── flat_binary.c  # Flat binary format
│   │   ├── com_format.c   # DOS .COM format
│   │   ├── intel_hex.c    # Intel HEX format (placeholder)
│   │   └── motorola_srec.c  # Motorola S-Record format (placeholder)
│   ├── utils/           # Utility functions
│   │   └── utils.c      # Enhanced utilities (string, memory, numbers)
│   ├── lexer.c          # Lexical analysis and tokenization
│   ├── main.c           # Main program entry point
│   └── symbols.c        # Symbol table management
├── include/             # Header files (.h)
│   ├── formats/         # Output format headers
│   │   ├── elf.h        # ELF format interface
│   │   ├── flat_binary.h  # Flat binary format interface
│   │   ├── com_format.h   # DOS .COM format interface
│   │   ├── intel_hex.h    # Intel HEX format interface
│   │   └── motorola_srec.h  # S-Record format interface
│   ├── arch_interface.h # Architecture plugin interface
│   ├── parser.h         # Parser interface
│   ├── expr.h           # Expression parser interface
│   ├── codegen.h        # Code generation interface
│   ├── lexer.h          # Lexical analysis interface
│   ├── symbols.h        # Symbol table interface
│   ├── utils.h          # Utility function declarations
│   ├── x86_16.h         # x86-16 architecture interface
│   ├── x86_32.h         # x86-32 architecture interface
│   └── x86_64.h         # x86-64 architecture interface
├── tests/               # Comprehensive test suites
│   ├── test_phase1_parser.c  # Phase 1 parser validation
│   ├── test_phase2_advanced_parsing.c  # Phase 2 expression parsing (6/6 pass)
│   ├── test_phase3_*.c       # Phase 3 symbol resolution tests
│   ├── test_phase4_*.c       # Phase 4 code generation tests
│   ├── test_phase5_elf.c     # Phase 5 ELF format tests
│   ├── test_x86_16_comprehensive.c  # x86-16 CPU emulation tests
│   ├── unicorn_*.c           # Unicorn Engine integration tests
│   └── unity.*               # Unity test framework
├── examples/            # Assembly code examples
│   ├── hello_x86_16.s   # x86-16 DOS hello world
│   ├── hello_x86_32.s   # x86-32 hello world
│   ├── hello_x86_64.s   # x86-64 hello world
│   └── *.s              # Various architecture examples
├── obj/                 # Object files (generated)
├── bin/                 # Executable files (generated)
├── testbin/             # Test output files (generated)
├── tmp/                 # Temporary files and reports
├── Makefile             # Build configuration with architecture support
├── README.md            # This file
├── PROJECT_STATUS.md    # Comprehensive technical status
├── ARCHITECTURE.md      # Detailed design documentation
├── STATIC_BUILDS.md     # Static build documentation
├── UNICORN_INSTALLATION.md  # Testing framework setup
└── MILESTONE_*.md       # Phase completion documentation
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

- **✅ Multi-Architecture Support**: Complete implementations for x86_16, x86_32, x86_64, and ARM64
- **✅ Advanced Expression Parser**: Complete arithmetic, bitwise, and symbol expression evaluation
- **✅ Modular Architecture**: Clean separation with dedicated architecture and format modules
- **✅ Comprehensive Output Formats**: 6 formats (bin, com, elf32, elf64, hex, srec) with modular organization
- **✅ Real Machine Code Generation**: Produces actual executable bytes for all supported architectures
- **✅ Symbol Resolution**: Forward references, immediate expressions, complex symbol evaluation
- **✅ CPU Emulation Testing**: Unicorn Engine integration validates generated machine code
- **✅ Static Build Support**: Self-contained, architecture-specific assembler variants
- **AT&T Syntax**: Consistent AT&T-style assembly syntax across all architectures
- **Modular Design**: Each architecture and format implemented as separate, focused module
- **Extensible Framework**: Easy to add new CPU architectures and output formats
- **Standard Compliance**: Generates industry-standard object file formats

## Usage

### ✅ Multi-Architecture Assembly (Fully Implemented)

#### x86_16 (16-bit Intel 8086/80286)
```bash
# Create DOS .COM executable
./bin/stas -a x86_16 -f com -o hello.com hello.s

# Create raw binary with custom base address  
./bin/stas -a x86_16 -f flat -b 0x7C00 -o bootloader.bin boot.s

# Create flat binary (default format)
./bin/stas -a x86_16 -o program.bin program.s
```

#### x86_32 (32-bit Intel IA-32)
```bash
# Create ELF32 object file
./bin/stas -a x86_32 -f elf32 -o program.o program.s

# Create flat binary
./bin/stas -a x86_32 -f bin -o program.bin program.s
```

#### x86_64 (64-bit Intel/AMD)
```bash
# Create ELF64 object file
./bin/stas -a x86_64 -f elf64 -o program.o program.s

# Create flat binary
./bin/stas -a x86_64 -f bin -o program.bin program.s
```

#### ARM64 (AArch64)
```bash
# Create ELF64 object file
./bin/stas -a arm64 -f elf64 -o program.o program.s

# Create flat binary
./bin/stas -a arm64 -f bin -o program.bin program.s
```

### x86_16 Assembly Example
```assembly
# DOS "Hello World" program
mov ax, 0x4C00    # DOS exit function
int 0x21          # Call DOS interrupt

# Arithmetic with expressions
mov ax, $(10 + 5)     # AX = 15
mov bx, $(20 * 2)     # BX = 40  
add ax, $(bx + 10)    # Complex immediate expressions

# Bitwise operations in expressions  
mov cx, $(0xFF & 0x0F)  # CX = 0x0F
mov dx, $(0xF0 | 0x0F)  # DX = 0xFF

# Symbol references in expressions
mov ax, $(start + 10)   # Address arithmetic
jmp $(end - start)      # Relative addressing

# Stack operations
mov ax, 0x5678    # Load value
push ax           # Save to stack
mov ax, 0x1234    # Change AX
pop ax            # Restore AX = 0x5678

# Conditional jumps
mov ax, 5         # Load test value
cmp ax, 5         # Compare with 5
je equal          # Jump if equal
mov ax, 0xFFFF    # This gets skipped
equal:
mov ax, 0x9999    # This executes
```

### Assembly Examples by Architecture

#### x86_16 Assembly Example
```assembly
# DOS "Hello World" program
mov ax, 0x4C00    # DOS exit function
int 0x21          # Call DOS interrupt

# Arithmetic with expressions
mov ax, $(10 + 5)     # AX = 15
mov bx, $(20 * 2)     # BX = 40  
add ax, $(bx + 10)    # Complex immediate expressions

# Stack operations
push ax           # Save to stack
pop bx           # Restore to BX
```

#### ARM64 Assembly Example
```assembly
# ARM64 assembly with expressions
mov x0, #$(10 + 5)    # x0 = 15
add x1, x0, #$(5 * 2) # x1 = x0 + 10
ldr x2, =message      # Load address
str x1, [x2]          # Store value

# System call example
mov x8, #93           # sys_exit
mov x0, #0            # status
svc #0                # system call
```

### 🔄 Planned Future Enhancements
```bash
# RISC-V architecture (planned)
./bin/stas -a riscv -f elf64 -o program.o program.s

# Additional formats (when fully implemented)
./bin/stas -a arm64 -f hex -o program.hex program.s    # Intel HEX
./bin/stas -a x86_64 -f srec -o program.s19 program.s  # Motorola S-Record
```

## ✅ Testing & Validation

STAS includes comprehensive testing with CPU emulation, unit testing, and advanced parsing validation.

### Comprehensive Test Suite Coverage
```bash
# Run all tests
make test-all

# Results: Complete test coverage across all components
# - Unit Tests: 117 format unit tests (5 formats) - 100% pass rate
# - Execution Tests: Multi-architecture CPU emulation validation
# - Integration Tests: End-to-end assembly and execution workflows
# - Phase Tests: Advanced language feature validation
```

### Unit Testing Framework ✅
```bash
# Run format unit tests (Unity framework)
make test-unit-formats

# Results: 117 tests, 0 failures across 5 output formats
# - ELF Format: 29 tests (32/64-bit support)
# - Flat Binary: 20 tests (raw binary output)
# - Intel HEX: 21 tests (embedded systems format)
# - COM Format: 23 tests (DOS executable format)
# - Motorola S-Record: 24 tests (embedded bootloader format)
```

### CPU Execution Testing ✅
```bash
# Run architecture-specific execution tests
make test-execution-all

# x86_32 Real Mode to Protected Mode Boot Sequence
make test-execution-x86_32

# Results: Multi-architecture execution validation
# - x86_16: 8 basic instruction tests + real mode operations
# - x86_32: 10 basic tests + 4 boot sequence tests (real→protected mode)
# - x86_64: 10 comprehensive instruction tests
# - ARM64: Cross-platform execution validation
# - RISC-V: Alternative architecture verification
```

### Advanced x86_32 Boot Sequence Testing ✅
```bash
# Test complete i386 PC boot simulation
./testbin/execution_test_x86_32_real_to_protected

# Features demonstrated:
# 1. Real Mode Operations: 16-bit segment:offset addressing
# 2. GDT Setup: Global Descriptor Table configuration
# 3. Protected Mode Switch: CR0.PE bit manipulation
# 4. Mode Transition: Real mode → Protected mode simulation
# 5. Memory Management: Segmented vs flat memory models
# 6. Interrupt Vectors: IVT setup for real mode interrupt handling
```

### Phase 2 Advanced Parsing Test Suite ✅
```bash
# Run comprehensive Phase 2 parsing tests
make test-phase2

# Results: 6/6 tests PASSED (100% success rate)
# - Expression evaluation: Numbers, hex, parentheses
# - Arithmetic expressions: +, -, *, /, operator precedence  
# - Bitwise expressions: &, |, ^, complex operations
# - Symbol resolution: Label definitions and references
# - Forward references: Symbols defined after use
# - Immediate expressions: Complex $(expr) in operands
```

### Machine Code Validation
- **Real CPU Emulation**: Uses Unicorn Engine to execute generated code
- **Boot Sequence Simulation**: Complete i386 PC startup simulation
- **Register State Verification**: Validates CPU register values after execution  
- **Mode Transition Testing**: Real mode to protected mode switching
- **Memory Model Validation**: Segmented addressing and protected mode memory
- **Cross-Platform**: Tests run on any system with Unicorn Engine support

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

Currently supported architectures:
- **x86-16**: ✅ Intel 8086/80286 16-bit instruction set (COMPLETE)
- **x86-32**: ✅ Intel 80386+ 32-bit instruction set (IA-32) (COMPLETE)
- **x86-64**: ✅ Full Intel/AMD 64-bit instruction set (COMPLETE)
- **ARM64**: ✅ AArch64 instruction set (COMPLETE)
- **RISC-V**: ✅ RV64I base instruction set (COMPLETE)

### Related Documentation
- � **[Project Status](PROJECT_STATUS.md)** - Development priorities and roadmap
- 🏗️ **[Architecture Design](ARCHITECTURE.md)** - Detailed technical specifications
- 🧪 **[Unicorn Engine Setup](UNICORN_INSTALLATION.md)** - Testing framework installation

## Development

### Current Development Status
Based on the **[Project Status](PROJECT_STATUS.md)**, we have completed significant milestones:

#### ✅ **COMPLETED - Phase 1-5: Core Implementation**
- **Parser & Lexer**: Complete AST-based parsing with expression evaluation
- **Symbol Management**: Full symbol table with forward reference resolution
- **Code Generation**: Working machine code generation for all architectures
- **Testing Framework**: Comprehensive test suites with CPU emulation validation

#### ✅ **COMPLETED - Phase 6.1-6.2: Multi-Architecture & Format Enhancement**
- **x86_16 Architecture**: Complete 16-bit instruction set with DOS support
- **x86_32 Architecture**: Complete 32-bit instruction set with ELF support
- **x86_64 Architecture**: Complete 64-bit instruction set 
- **ARM64 Architecture**: Complete AArch64 instruction set implementation
- **Format Organization**: Modular format system with 6 supported formats

#### 🔄 **CURRENT FOCUS - Phase 6.3+: Advanced Features**
- **RISC-V Architecture**: Next major architecture to implement
- **Format Completion**: Finish Intel HEX and Motorola S-Record implementations
- **Optimization Features**: Code optimization and performance enhancements
- **Advanced Directives**: Macro support, conditional assembly, includes

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

## Recent Updates

**v0.6.0 Format Reorganization**: All output format implementations have been successfully reorganized into the dedicated `formats/` folder for improved modularity and maintainability. This includes:
- Modular format implementations (flat_binary, com_format, elf, intel_hex, motorola_srec)
- Clean separation of format logic from core assembler
- Consistent interface across all formats
- Easy addition of new output formats

## License

STAS is designed as a modular assembler framework. Add your own license as needed.
