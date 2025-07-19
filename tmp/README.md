# Temporary Files Directory

This directory contains temporary files and scratch work during development.

## Purpose

- **Temporary assembly files** (*.s) for quick testing
- **Debug output files** and logs
- **Scratch files** for development experiments
- **Work-in-progress** files that don't need version control

## Directory Structure

- `tmp/` - Temporary source files and scratch work
- `testbin/` - Generated binary files (separate from source)
- `tests/` - Permanent test source code (tracked in git)

## Usage

```bash
# Create temporary test assembly
echo 'movq $60, %rax' > tmp/test.s

# Assemble to testbin (not tmp!)
./bin/stas --arch x86_64 -f bin -o testbin/test.bin tmp/test.s

# Clean temporary files
rm -rf tmp/*
```

**Note**: Files in this directory are ignored by git and may be deleted at any time.
