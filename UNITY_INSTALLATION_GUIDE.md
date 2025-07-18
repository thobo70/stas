# Unity Testing Framework Installation Guide for STAS

## Overview

This guide walks through installing and configuring the Unity testing framework for the STAS assembler project. Unity is a lightweight, embedded-focused C testing framework that requires zero external dependencies and integrates seamlessly with existing build systems.

---

## Quick Installation (Recommended)

### Step 1: Unity Framework Files

The Unity framework files are already included in the STAS project:

```bash
# Verify Unity core files are present
ls tests/unity*.{c,h}
```

**Expected output:**
```
tests/unity.c  tests/unity.h  tests/unity_internals.h
```

These files contain Unity v2.6.1 with zero external dependencies.

### Step 2: Test Installation

Unity is already configured and working. You can run the verification test:

```bash
# Run the Unity verification test
make tests/test_unity_install
./tests/test_unity_install
```

**Expected output:**
```
tests/test_unity_install.c:29:test_unity_is_working:PASS
tests/test_unity_install.c:30:test_basic_assertions:PASS

-----------------------
2 Tests 0 Failures 0 Ignored 
OK
```

---

## Integration with STAS Build System

### Makefile Integration

Unity testing is already integrated into the STAS build system. The Makefile includes:

- **test-unity**: Run all Unity unit tests
- **test-clean**: Clean test artifacts  
- **test-all**: Run Unity tests + Unicorn emulation tests

### Available Test Targets

```bash
# View all available targets
make help
```

**Current test targets:**
```
test-unity   - Run unit tests (Unity framework)
test-unicorn - Run Unicorn Engine emulation tests
test-all     - Run all tests (sample + unity + unicorn)
test-clean   - Clean test artifacts
```

### Verify Integration

```bash
# Run all Unity tests
make test-unity

# Clean test artifacts
make test-clean

# Run complete test suite (Unity + Unicorn)
make test-all
```

---

## Current STAS Test Suite

The following test files are already implemented and working:

### 1. Lexer Tests (`tests/test_lexer.c`)

Tests tokenization functionality:
- Lexer creation and initialization  
- Basic instruction tokenization
- Register tokenization (%rax, %rbx, etc.)
- Immediate value tokenization ($42, $0x1000)
- Complete instruction parsing

**Status**: ✅ 5 Tests, 0 Failures (100% pass rate)

### 2. Symbol Table Tests (`tests/test_symbols.c`)

Tests symbol management:
- Symbol table creation and cleanup
- Symbol creation with different types
- Symbol insertion and lookup operations
- Hash distribution verification

**Status**: ✅ 4 Tests, 0 Failures (100% pass rate)

### 3. Parser Tests (`tests/test_parser_simple.c`)

Tests basic parser functionality:
- Parser initialization with lexer input
- Basic instruction tokenization through parser
- Integration between lexer and parser components

**Status**: ✅ 2 Tests, 0 Failures (100% pass rate)

### 4. Unity Installation Test (`tests/test_unity_install.c`)

Verifies Unity framework is working:
- Basic Unity assertions
- Framework integration verification

**Status**: ✅ 2 Tests, 0 Failures (100% pass rate)

### Total Test Coverage

```
✅ Lexer Tests:     5 Tests, 0 Failures (100% pass rate)
✅ Symbols Tests:   4 Tests, 0 Failures (100% pass rate) 
✅ Parser Tests:    2 Tests, 0 Failures (100% pass rate)
✅ Unity Install:   2 Tests, 0 Failures (100% pass rate)
═══════════════════════════════════════════════════════
🎉 TOTAL: 13 Tests, 0 Failures, 0 Ignored - ALL PASSING
```

---

## Running Tests

### Individual Tests

```bash
# Run specific test suites
make tests/test_lexer
./tests/test_lexer

make tests/test_symbols  
./tests/test_symbols

make tests/test_parser_simple
./tests/test_parser_simple

make tests/test_unity_install
./tests/test_unity_install
```

### All Unit Tests

```bash
# Run all Unity tests
make test-unity
```

### Combined with Unicorn Tests

```bash
# Run complete test suite
make test-all
```

---

## Test Organization Best Practices

### Directory Structure

```
tests/
├── unity.c                 # Unity framework core
├── unity.h                 # Unity headers  
├── unity_internals.h       # Unity internal headers
├── test_lexer.c            # Lexer component tests ✅
├── test_parser_simple.c    # Parser component tests ✅
├── test_symbols.c          # Symbol table tests ✅
├── test_unity_install.c    # Installation verification ✅
├── run_unicorn_tests.sh    # Unicorn test runner
├── unicorn_*.c             # Unicorn emulation demos
└── verify_unicorn_integration.sh  # Unicorn verification
```

### Test Naming Conventions

- **Files**: `test_<component>.c`
- **Functions**: `test_<functionality>()`
- **Setup/Teardown**: `setUp()` and `tearDown()`
- **Test Runner**: `main()` with `UNITY_BEGIN()` and `UNITY_END()`

### Common Unity Assertions for STAS

```c
// Basic assertions
TEST_ASSERT_TRUE(condition)
TEST_ASSERT_FALSE(condition)
TEST_ASSERT(condition)

// Pointer assertions (very useful for AST nodes)
TEST_ASSERT_NULL(pointer)
TEST_ASSERT_NOT_NULL(pointer)
TEST_ASSERT_EQUAL_PTR(expected, actual)

// Integer assertions (addresses, counts, types)
TEST_ASSERT_EQUAL_INT(expected, actual)
TEST_ASSERT_EQUAL_UINT64(expected, actual)
TEST_ASSERT_GREATER_THAN_INT(threshold, actual)

// String assertions (tokens, names)
TEST_ASSERT_EQUAL_STRING(expected, actual)
TEST_ASSERT_EQUAL_STRING_LEN(expected, actual, len)

// Memory assertions (for safe memory management)
TEST_ASSERT_EQUAL_MEMORY(expected, actual, len)
```

---

## Continuous Integration

### GitHub Actions Integration (Future)

```yaml
# .github/workflows/tests.yml
name: STAS Tests
on: [push, pull_request]

jobs:
  test:
    runs-on: ubuntu-latest
    steps:
    - uses: actions/checkout@v2
    - name: Install dependencies
      run: sudo apt-get install -y gcc make libunicorn-dev
    - name: Build STAS
      run: make
    - name: Run unit tests
      run: make test
    - name: Run emulation tests
      run: make test-unicorn
```

---

## Troubleshooting

### Common Issues

**1. Compilation Errors**
```bash
# Ensure Unity headers are found
gcc -I tests/ -I include/ tests/test_lexer.c tests/unity.c src/lexer.c -o tests/test_lexer
```

**2. Missing Object Files** 
```bash
# Build project first
make clean && make
```

**3. Missing Headers**
```bash
# Verify Unity files are present
ls tests/unity*.{c,h}
# Should show: tests/unity.c tests/unity.h tests/unity_internals.h
```

**4. Test Failures**
```bash
# Run individual tests to isolate issues
make tests/test_lexer
./tests/test_lexer
```

### Debug Mode

```bash
# Compile tests with debug symbols
gcc -g -O0 -DDEBUG -I tests/ -I include/ \
    tests/test_parser.c tests/unity.c src/parser.c -o tests/test_parser

# Run with GDB
gdb tests/test_parser
```

---

## Verification

### Final Installation Check

```bash
# Verify Unity is properly installed and working
make test-clean
make test-unity

# Expected output:
# ===========================================
# Running STAS Unit Tests
# ===========================================
# Running tests/test_lexer...
# tests/test_lexer.c:117:test_lexer_creation:PASS
# tests/test_lexer.c:118:test_basic_tokenization:PASS
# tests/test_lexer.c:119:test_register_tokenization:PASS
# tests/test_lexer.c:120:test_immediate_value_tokenization:PASS
# tests/test_lexer.c:121:test_complete_instruction_tokenization:PASS
# 5 Tests 0 Failures 0 Ignored - OK
# ✅ tests/test_lexer PASSED
#
# Running tests/test_parser_simple...
# tests/test_parser_simple.c:53:test_parser_initialization:PASS
# tests/test_parser_simple.c:54:test_basic_instruction_parsing:PASS
# 2 Tests 0 Failures 0 Ignored - OK
# ✅ tests/test_parser_simple PASSED
#
# Running tests/test_symbols...
# tests/test_symbols.c:91:test_symbol_table_creation:PASS
# tests/test_symbols.c:92:test_symbol_creation:PASS
# tests/test_symbols.c:93:test_symbol_table_insert_and_lookup:PASS
# tests/test_symbols.c:94:test_symbol_table_hash_distribution:PASS
# 4 Tests 0 Failures 0 Ignored - OK
# ✅ tests/test_symbols PASSED
#
# Running tests/test_unity_install...
# tests/test_unity_install.c:29:test_unity_is_working:PASS
# tests/test_unity_install.c:30:test_basic_assertions:PASS
# 2 Tests 0 Failures 0 Ignored - OK
# ✅ tests/test_unity_install PASSED
#
# 🎉 All unit tests completed successfully!
```

### Integration Verification

```bash
# Test complete build and test cycle
make clean
make
make test-unity
make test-unicorn
```

---

## Next Steps

With Unity successfully installed and integrated:

1. **Add More Tests**: Expand test coverage for Phase 2 parser features
2. **Test-Driven Development**: Write tests before implementing new features  
3. **Continuous Testing**: Run `make test-unity` after each change
4. **Expand Coverage**: Add tests for new architecture modules as they're developed
5. **Integration Testing**: Create integration tests that combine multiple components

**Current Status**: Unity framework fully integrated with 13 passing tests across all core components (lexer, parser, symbols). Zero external dependencies, C99 compliant, and ready for production development.

Unity is now ready to support robust development of your STAS assembler! 🎯
