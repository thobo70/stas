# STAS Phase 7 Test Suite
## Comprehensive Regression Tests for Advanced Language Features

This directory contains comprehensive regression tests for STAS Phase 7 features:

### Test Structure

```
tests/phase7/
├── run_tests.sh                 # Main test runner script
├── test_includes.s             # Include directive tests
├── test_expressions.s          # Advanced expression tests  
├── test_combined.s             # Combined feature tests
├── common_test.inc            # Shared include file for testing
└── README.md                   # This file
```

### Features Tested

#### 1. Include Directives
- **Basic Inclusion**: Simple .include "file.inc" functionality
- **Nested Includes**: Include files that include other files
- **Constant Sharing**: Constants defined in included files
- **Function Sharing**: Labels and functions from included files
- **Data Sharing**: Data sections from included files

#### 2. Advanced Expressions
- **Arithmetic**: Addition, subtraction, multiplication
- **Bitwise**: OR, AND, XOR operations
- **Shift Operations**: Left shift (<<), right shift (>>)
- **Precedence**: Proper operator precedence handling
- **Parentheses**: Precedence override with parentheses

#### 3. Integration Tests
- **Combined Features**: Include directives with expressions
- **Cross-dependencies**: Constants using included values
- **Complex Assembly**: Real-world assembly patterns

### Running Tests

```bash
# Make the test script executable
chmod +x tests/phase7/run_tests.sh

# Run all Phase 7 tests
./tests/phase7/run_tests.sh

# Run individual test files
./bin/stas tests/phase7/test_includes.s -o test_output.bin
./bin/stas tests/phase7/test_expressions.s -o test_output.bin
```

### Expected Output

All tests should pass with the following results:
- ✅ Include directive processing
- ✅ Advanced expression evaluation
- ✅ Combined feature integration

### Test Architecture

Tests are designed to work with the x86_64 architecture (primary supported syntax) but the Phase 7 features are architecture-independent and should work across all supported architectures.

### Verification

Each test generates an output binary file. The test runner verifies:
1. **Assembly Success**: File assembles without errors
2. **Output Generation**: Binary file is created
3. **Content Verification**: Expected values appear in output (where applicable)

### Error Cases

The test suite also includes negative test cases to verify proper error handling:
- Undefined macro usage
- Malformed conditional blocks
- Missing include files
- Invalid expression syntax

### Maintenance

When adding new Phase 7 features:
1. Add corresponding test case to appropriate test file
2. Update run_tests.sh to include new verification
3. Update this README with feature documentation
4. Ensure all tests continue to pass
