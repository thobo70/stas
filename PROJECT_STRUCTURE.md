# STAS Project Directory Structure

This document describes the organized directory structure of the STAS assembler project.

## Core Project Structure

```
stas/
├── src/                    # Source code (tracked in git)
│   ├── core/              # Core assembler functionality
│   │   ├── lexer.c        # AT&T syntax tokenizer
│   │   ├── parser.c       # AST parsing engine
│   │   ├── expr.c         # Expression evaluation
│   │   ├── symbols.c      # Symbol table management
│   │   ├── expressions.c  # Complex expression handling
│   │   ├── output.c       # Output file generation
│   │   ├── output_format.c # Format-specific output
│   │   └── codegen.c      # Machine code generation
│   ├── arch/              # Architecture-specific modules
│   │   ├── x86_16/        # 16-bit x86 implementation
│   │   ├── x86_32/        # 32-bit x86 implementation
│   │   ├── x86_64/        # 64-bit x86 implementation
│   │   ├── arm64/         # ARM64 implementation
│   │   └── riscv/         # RISC-V implementation
│   ├── formats/           # Output format implementations
│   │   ├── elf.c          # ELF32/64 object files
│   │   ├── flat_binary.c  # Raw binary output
│   │   ├── com_format.c   # DOS COM executable
│   │   ├── intel_hex.c    # Intel HEX format
│   │   └── motorola_srec.c # Motorola S-Record format
│   ├── utils/             # Utility functions
│   ├── include.c          # Include directive processing
│   ├── macro.c            # Macro preprocessing
│   └── main.c             # Main program entry point
├── include/               # Header files (tracked in git)
│   ├── arch_interface.h   # Architecture abstraction
│   ├── codegen.h          # Code generation interface
│   ├── expr.h             # Expression evaluation
│   ├── lexer.h            # Lexer interface
│   ├── parser.h           # Parser interface
│   ├── symbols.h          # Symbol table interface
│   ├── utils.h            # Utility functions
│   ├── x86_16.h           # x86-16 definitions
│   ├── x86_32.h           # x86-32 definitions
│   ├── x86_64.h           # x86-64 definitions
│   ├── riscv.h            # RISC-V definitions
│   └── formats/           # Format-specific headers
├── tests/                 # Test source code (tracked in git)
│   ├── unit/              # Unity-based unit tests
│   │   ├── core/          # Core module tests
│   │   ├── arch/          # Architecture tests
│   │   ├── formats/       # Output format tests (117 tests)
│   │   └── utils/         # Utility tests
│   ├── execution/         # Unicorn-based execution tests
│   │   ├── x86_16/        # 16-bit execution validation
│   │   │   └── test_basic.c
│   │   ├── x86_32/        # 32-bit execution validation
│   │   │   ├── test_basic.c
│   │   │   └── test_real_to_protected_mode.c  # Boot sequence simulation
│   │   ├── x86_64/        # 64-bit execution validation
│   │   ├── arm64/         # ARM64 execution validation
│   │   └── riscv/         # RISC-V execution validation
│   ├── integration/       # Integration test scripts
│   ├── phase7/            # Advanced language feature tests
│   ├── framework/         # Testing framework utilities
│   │   ├── unicorn_test_framework.c  # CPU emulation testing
│   │   └── unity_extensions.c        # Custom Unity assertions
│   ├── unity.c            # Unity testing framework
│   └── unity.h            # Unity header
├── bin/                   # Built executables (ignored by git)
│   └── stas              # Main assembler executable
├── obj/                   # Object files during build (ignored by git)
├── tmp/                   # Temporary files (ignored by git)
├── testbin/               # Test binary outputs (ignored by git)
├── examples/              # Example assembly programs (tracked in git)
│   ├── hello_x86_16.s     # 16-bit DOS hello world
│   ├── hello_x86_32.s     # 32-bit Linux hello world
│   ├── hello_x86_64.s     # 64-bit Linux hello world
│   ├── hello_riscv.s      # RISC-V hello world
│   ├── arm64_simple.s     # ARM64 example
│   └── phase7_complete_demo.s  # Advanced features demo
├── logs/                  # Build and test logs (ignored by git)
└── reports/               # Test reports and analysis (ignored by git)
```

## Directory Guidelines

### 📁 Source Code Directories (Tracked)
- `src/` - All C source code
- `include/` - All header files
- `tests/` - Unit test source files (*.c)
- `examples/` - Example assembly programs for documentation

### 📁 Build Directories (Ignored)
- `bin/` - Final executables and built programs
- `obj/` - Intermediate object files during compilation

### 📁 Development Directories (Ignored)
- `tmp/` - Temporary source files, scratch work, debug files
- `testbin/` - Generated test binaries and assembled outputs

## File Organization Rules

### ✅ DO:
- Keep source code in `src/`, `include/`, `tests/`
- Put temporary assembly files in `tmp/`
- Output test binaries to `testbin/`
- Use descriptive filenames for test outputs

### ❌ DON'T:
- Mix source code with generated binaries
- Put temporary files in source directories
- Commit generated binaries to git
- Place test binaries in the same directory as test source

## Example Workflow

```bash
# 1. Create temporary test assembly
echo 'movq $60, %rax; syscall' > tmp/exit_test.s

# 2. Assemble to test binary directory  
./bin/stas --arch x86_64 -f bin -o testbin/exit_test.bin tmp/exit_test.s

# 3. Examine the output
xxd testbin/exit_test.bin

# 4. Clean up when done
rm tmp/exit_test.s        # Remove temporary source
rm testbin/exit_test.bin  # Remove test binary
```

This structure maintains clean separation between source code, build artifacts, and development/testing files.
