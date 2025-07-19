# Test Binaries Directory

This directory contains binary files generated from test assembly programs.

## Directory Structure

- `testbin/` - Generated test binaries (*.bin, *.com, *.out, *.o)
- `tmp/` - Temporary files and scratch work
- `tests/` - Test source code (*.c files are tracked, binaries are ignored)

## Purpose

This directory is specifically for:
- Assembled test programs (from .s files)
- Generated object files for testing
- Binary outputs for manual inspection and debugging
- Test executables that need to be examined

## Rules

1. **No source code** should ever be placed in this directory
2. **Only generated binaries** from test assembly programs
3. All files here are **ignored by git** and can be deleted safely
4. Use descriptive filenames: `test_x86_64_hello.bin`, `test_mov_instruction.out`

## Usage Examples

```bash
# Generate test binary from assembly
./bin/stas --arch x86_64 -f bin -o testbin/hello_world.bin tmp/hello.s

# Examine binary with hexdump
xxd testbin/hello_world.bin

# Clean all test binaries
rm -rf testbin/*
```

## Integration with Build System

The Makefile should output test binaries to this directory to maintain clean separation between source and generated files.
