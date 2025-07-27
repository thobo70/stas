# STAS - STIX Modular Assembler

A high-performance, multi-architecture assembler supporting AT&T syntax for x86-16, x86-32, x86-64, ARM64, and RISC-V architectures with comprehensive output format support.

## 🚀 Project Status

**Current Version**: v0.8.0 (Multi-Architecture Complete)

| Architecture | Recognition | Functional | Status |
|-------------|-------------|------------|---------|
| **x86_16**  | 90/90 (100%) | 90/90 (100%) | ✅ **COMPLETE** |
| **x86_32**  | 215/215 (100%) | 215/215 (100%) | ✅ **COMPLETE** |
| **x86_64**  | 37/410 (9.0%) | 37/410 (9.0%) | 🎯 **IN PROGRESS** |
| **ARM64**   | 223/223 (100%) | 10/223 (4.5%) | 🔧 **ENCODING WORK** |
| **RISC-V**  | 42/170 (24.7%) | 10/170 (5.9%) | 🔧 **EXPANDING** |

**Recent Achievements**:
- ✅ **x86_32 Architecture COMPLETED**: All 215 instructions fully functional
- ✅ **ARM64 Recognition COMPLETED**: All 223 instructions with comprehensive operand support  
- ✅ **Advanced Testing Framework**: Instruction completeness analysis with detailed reporting
- ✅ **Clean Modular Architecture**: Separated architecture plugins and output formats

## 🎯 Quick Start

```bash
# Clone and build
git clone <repository-url>
cd stas
make

# Test the assembler
make test

# Check instruction completeness across all architectures
./testbin/instruction_completeness_modular

# Create your first assembly program
echo 'movq $1, %rax' > hello.s
echo 'syscall' >> hello.s
./bin/stas -a x86_64 -f elf64 -o hello.o hello.s
```

## ✨ Key Features

- **🏗️ Multi-Architecture Support**: Five CPU architectures with modular plugin system
- **📄 Multiple Output Formats**: Binary, ELF32/64, DOS COM, Intel HEX, Motorola S-Record
- **🧮 Advanced Expression Parser**: Complex arithmetic, bitwise, and symbol expressions
- **🎯 AT&T Syntax**: Consistent assembly syntax across all architectures
- **🧪 Comprehensive Testing**: CPU emulation validation with Unicorn Engine
- **📊 Development Tools**: Instruction completeness analysis and progress tracking
- **⚡ Static Builds**: Self-contained, architecture-specific assembler variants
- **🔍 Detailed Diagnostics**: Helpful error messages with line/column information

## 🏛️ Architecture Support

### ✅ Completed Architectures

#### x86_16 (Intel 8086/80286) - **COMPLETE**
- **Instructions**: 90/90 (100% functional)
- **Features**: Real mode addressing, DOS COM format, interrupt support
- **Use Cases**: Legacy systems, embedded controllers, bootloaders

#### x86_32 (Intel IA-32) - **COMPLETE**  
- **Instructions**: 215/215 (100% functional)
- **Features**: Protected mode, ELF32 objects, full IA-32 instruction set
- **Use Cases**: 32-bit applications, embedded systems, legacy compatibility

### 🔧 In Development

#### x86_64 (Intel/AMD 64-bit) - **IN PROGRESS**
- **Instructions**: 37/410 (9% functional) - **Next Priority**
- **Focus**: Size variants (l/w/b), arithmetic extensions, shift operations
- **Target**: Foundation for modern 64-bit applications

#### ARM64 (AArch64) - **ENCODING PHASE**
- **Recognition**: 223/223 (100% complete)
- **Encoding**: 10/223 (4.5% functional)
- **Focus**: Instruction encoding implementation

#### RISC-V - **EXPANDING**
- **Instructions**: 42/170 (25% recognized, 6% functional) 
- **Focus**: Instruction recognition completion, basic encoding

## 🛠️ Usage Examples

### Basic Assembly

```bash
# x86_64 (64-bit)
./bin/stas -a x86_64 -f elf64 -o program.o program.s

# x86_32 (32-bit)  
./bin/stas -a x86_32 -f elf32 -o program.o program.s

# x86_16 (16-bit DOS)
./bin/stas -a x86_16 -f com -o program.com program.s

# ARM64
./bin/stas -a arm64 -f elf64 -o program.o program.s

# RISC-V
./bin/stas -a riscv -f elf64 -o program.o program.s
```

### Output Formats

```bash
# Raw binary (default)
./bin/stas -a x86_64 -f bin -o program.bin program.s

# ELF object files
./bin/stas -a x86_64 -f elf64 -o program.o program.s
./bin/stas -a x86_32 -f elf32 -o program.o program.s

# DOS COM executable (x86_16 only)
./bin/stas -a x86_16 -f com -o program.com program.s

# Embedded formats
./bin/stas -a arm64 -f hex -o program.hex program.s    # Intel HEX
./bin/stas -a x86_32 -f srec -o program.s19 program.s  # Motorola S-Record
```

### Assembly Code Examples

#### x86_64 Example
```assembly
.section .text
.global _start

_start:
    movq $1, %rax       # sys_write
    movq $1, %rdi       # stdout
    movq $message, %rsi # message address
    movq $13, %rdx      # message length
    syscall

    movq $60, %rax      # sys_exit
    movq $0, %rdi       # status
    syscall

.section .data
message: .ascii "Hello, World!"
```

#### ARM64 Example
```assembly
.section .text
.global _start

_start:
    mov x0, #1          # stdout
    ldr x1, =message    # message address
    mov x2, #13         # message length
    mov x8, #64         # sys_write
    svc #0

    mov x0, #0          # status
    mov x8, #93         # sys_exit
    svc #0

.section .data
message: .ascii "Hello, World!"
```

## 🧪 Testing & Validation

### Instruction Completeness Analysis
```bash
# Test all architectures
./testbin/instruction_completeness_modular

# Test specific architecture with details
./testbin/instruction_completeness_modular x86_64 -v

# Compact output for automation
./testbin/instruction_completeness_modular arm64 -c
```

**See [Instruction Completeness Guide](INSTRUCTION_COMPLETENESS_GUIDE.md) for detailed usage.**

### CPU Emulation Testing
```bash
# Run comprehensive test suite
make test-all

# Architecture-specific execution tests
make test-execution-x86_32
make test-execution-arm64

# Unit testing (Unity framework)
make test-unit-formats
```

### Development Quality Gates
```bash
# Before committing changes
make test                                    # Basic functionality
./testbin/instruction_completeness_modular  # Progress verification
make test-unicorn                           # CPU emulation validation
```

## 🏗️ Project Structure

```
stas/
├── src/                          # Source code
│   ├── core/                     # Core assembler engine
│   │   ├── parser.c              # AST-based parser
│   │   ├── lexer.c               # Tokenization
│   │   ├── expr.c                # Expression evaluation
│   │   ├── symbols.c             # Symbol table management
│   │   ├── codegen.c             # Code generation
│   │   ├── output.c              # Output coordination
│   │   └── output_format.c       # Format interface
│   ├── arch/                     # Architecture plugins
│   │   ├── x86_16/               # Complete 16-bit implementation
│   │   ├── x86_32/               # Complete 32-bit implementation  
│   │   ├── x86_64/               # 64-bit implementation (expanding)
│   │   ├── arm64/                # ARM64 implementation
│   │   └── riscv/                # RISC-V implementation
│   ├── formats/                  # Output format modules
│   │   ├── elf.c                 # ELF32/ELF64 object files
│   │   ├── flat_binary.c         # Raw binary output
│   │   ├── com_format.c          # DOS COM executables
│   │   ├── intel_hex.c           # Intel HEX format
│   │   └── motorola_srec.c       # Motorola S-Record format
│   ├── utils/                    # Utility functions
│   ├── main.c                    # Program entry point
│   ├── macro.c                   # Macro processing
│   └── include.c                 # Include file handling
├── include/                      # Header files
├── tests/                        # Comprehensive test suites
│   ├── instruction_completeness/ # Architecture analysis framework
│   ├── unit/                     # Unit tests (Unity framework)
│   ├── execution/                # CPU emulation tests  
│   ├── integration/              # End-to-end tests
│   └── framework/                # Test infrastructure
├── examples/                     # Assembly code examples
├── docs/                         # Additional documentation
├── bin/                          # Compiled executables (generated)
├── obj/                          # Build artifacts (generated)
└── testbin/                      # Test executables (generated)
```

## 🔧 Build System

### Standard Build
```bash
make              # Build main assembler
make debug        # Build with debug symbols
make static-all   # Build all static variants
make clean        # Clean build artifacts
```

### Architecture-Specific Static Builds
```bash
make static-x86_64   # 64-bit static assembler (~800KB)
make static-x86_32   # 32-bit static assembler  
make static-arm64    # ARM64 static assembler
```

### Testing Targets
```bash
make test                    # Basic functionality test
make test-all               # Complete test suite
make test-instruction-completeness  # Architecture analysis
make test-unicorn           # CPU emulation tests
make test-unit-formats      # Format unit tests
```

## 📚 Documentation

- **[Instruction Completeness Guide](INSTRUCTION_COMPLETENESS_GUIDE.md)** - Comprehensive testing tool documentation
- **[Development Status](PROJECT_STATUS_UPDATE.md)** - Current progress and roadmap
- **[Quick Reference](QUICK_REFERENCE.md)** - Command-line examples and syntax
- **[Development Guide](DEV_QUICK_REFERENCE.md)** - Developer principles and guidelines
- **[Architecture Design](ARCHITECTURE.md)** - Technical design documentation
- **[Static Builds](STATIC_BUILDS.md)** - Deployment documentation
- **[User Guide](USER_GUIDE.md)** - Complete usage manual

## 🎯 Development Roadmap

### Phase 1: x86_64 Completion (Current Priority)
- **Target**: Complete x86_64 instruction set (currently 37/410)
- **Focus**: Basic arithmetic, data movement, logical operations
- **Timeline**: Q1 2025

### Phase 2: ARM64 Encoding  
- **Target**: Convert 223 recognized instructions to functional
- **Focus**: ARM64 instruction encoding implementation
- **Timeline**: Q2 2025

### Phase 3: RISC-V Enhancement
- **Target**: Complete RISC-V instruction recognition and encoding
- **Focus**: Expand from 42/170 to full instruction set
- **Timeline**: Q3 2025

### Phase 4: Advanced Features
- **Target**: Optimization, advanced directives, performance
- **Focus**: Production readiness
- **Timeline**: Q4 2025

## 🏆 Quality Standards

### Development Principles
- **CPU Accuracy**: Hardware documentation is the ultimate authority
- **AT&T Syntax**: Consistent source/destination operand order
- **Test-Driven**: All changes validated with comprehensive test suite
- **Modular Design**: Clean separation between architectures and formats
- **No Regressions**: Existing functionality must be preserved

### Quality Gates
- ✅ All tests pass before commit
- ✅ Instruction completeness maintained or improved
- ✅ AT&T syntax compliance verified
- ✅ CPU documentation references validated
- ✅ No cross-architecture contamination

## 🤝 Contributing

1. **Check Current Status**: Review instruction completeness for target architecture
2. **Follow Standards**: Use AT&T syntax and validate with CPU documentation
3. **Test Thoroughly**: Run full test suite including emulation validation
4. **Document Changes**: Update relevant documentation and examples

### Development Setup
```bash
# Install dependencies (Ubuntu/Debian)
sudo apt-get install build-essential libunicorn-dev

# Clone and build
git clone <repository-url>
cd stas
make

# Verify setup
make test
./testbin/instruction_completeness_modular
```

## 📄 License

STAS is designed as a modular assembler framework. License to be determined.

---

**🎯 Current Focus**: x86_64 architecture completion - implementing size variants and arithmetic extensions to achieve foundational instruction set coverage.
## 📚 Documentation

- **[Instruction Completeness Guide](INSTRUCTION_COMPLETENESS_GUIDE.md)** - Comprehensive testing tool documentation
- **[Development Status](PROJECT_STATUS_UPDATE.md)** - Current progress and roadmap
- **[Quick Reference](QUICK_REFERENCE.md)** - Command-line examples and syntax
- **[Development Guide](DEV_QUICK_REFERENCE.md)** - Developer principles and guidelines
- **[Architecture Design](ARCHITECTURE.md)** - Technical design documentation
- **[Static Builds](STATIC_BUILDS.md)** - Deployment documentation
- **[User Guide](USER_GUIDE.md)** - Complete usage manual

## 🎯 Development Roadmap

### Phase 1: x86_64 Completion (Current Priority)
- **Target**: Complete x86_64 instruction set (currently 37/410)
- **Focus**: Basic arithmetic, data movement, logical operations
- **Timeline**: Q1 2025

### Phase 2: ARM64 Encoding  
- **Target**: Convert 223 recognized instructions to functional
- **Focus**: ARM64 instruction encoding implementation
- **Timeline**: Q2 2025

### Phase 3: RISC-V Enhancement
- **Target**: Complete RISC-V instruction recognition and encoding
- **Focus**: Expand from 42/170 to full instruction set
- **Timeline**: Q3 2025

### Phase 4: Advanced Features
- **Target**: Optimization, advanced directives, performance
- **Focus**: Production readiness
- **Timeline**: Q4 2025

## 🏆 Quality Standards

### Development Principles
- **CPU Accuracy**: Hardware documentation is the ultimate authority
- **AT&T Syntax**: Consistent source/destination operand order
- **Test-Driven**: All changes validated with comprehensive test suite
- **Modular Design**: Clean separation between architectures and formats
- **No Regressions**: Existing functionality must be preserved

### Quality Gates
- ✅ All tests pass before commit
- ✅ Instruction completeness maintained or improved
- ✅ AT&T syntax compliance verified
- ✅ CPU documentation references validated
- ✅ No cross-architecture contamination

## 🤝 Contributing

1. **Check Current Status**: Review instruction completeness for target architecture
2. **Follow Standards**: Use AT&T syntax and validate with CPU documentation
3. **Test Thoroughly**: Run full test suite including emulation validation
4. **Document Changes**: Update relevant documentation and examples

### Development Setup
```bash
# Install dependencies (Ubuntu/Debian)
sudo apt-get install build-essential libunicorn-dev

# Clone and build
git clone <repository-url>
cd stas
make

# Verify setup
make test
./testbin/instruction_completeness_modular
```

## 📄 License

STAS is designed as a modular assembler framework. License to be determined.

---

**🎯 Current Focus**: x86_64 architecture completion - implementing size variants and arithmetic extensions to achieve foundational instruction set coverage.
