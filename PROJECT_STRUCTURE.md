# STAS Project Directory Structure

This document describes the organized directory structure of the STAS assembler project.

## Core Project Structure

```
stas/
├── src/                    # Source code (tracked in git)
│   ├── core/              # Core assembler functionality
│   ├── arch/              # Architecture-specific modules
│   └── utils/             # Utility functions
├── include/               # Header files (tracked in git)
├── tests/                 # Test source code (tracked in git)
│   └── test_*.c          # Unit test files
├── bin/                   # Built executables (ignored by git)
├── obj/                   # Object files during build (ignored by git)
├── tmp/                   # Temporary files (ignored by git)
├── testbin/               # Test binary outputs (ignored by git)
└── examples/              # Example assembly programs (tracked in git)
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
