# Unity Testing Framework Installation Guide for STAS

## Overview

This guide walks through installing and configuring the Unity testing framework for the STAS assembler project. Unity is a lightweight, embedded-focused C testing framework that requires zero external dependencies and integrates seamlessly with existing build systems.

---

## Quick Installation (Recommended)

### Step 1: Download Unity

```bash
# Navigate to your STAS project directory
cd /home/tom/project/stas

# Create Unity directory
mkdir -p tests/unity

# Download latest Unity release
wget -O tests/unity.tar.gz https://github.com/ThrowTheSwitch/Unity/archive/v2.6.1.tar.gz

# Extract Unity files
tar -xzf tests/unity.tar.gz -C tests/unity --strip-components=1

# Clean up download
rm tests/unity.tar.gz

# Verify installation
ls tests/unity/src/
```

**Expected output:**
```
unity.c  unity.h  unity_internals.h
```

### Step 2: Copy Core Files

```bash
# Copy Unity core files to tests directory
cp tests/unity/src/unity.c tests/
cp tests/unity/src/unity.h tests/
cp tests/unity/src/unity_internals.h tests/

# Verify core files
ls tests/unity*.{c,h}
```

### Step 3: Test Installation

Create a simple test to verify Unity is working:

```bash
cat > tests/test_unity_install.c << 'EOF'
#include "unity.h"
#include <stdio.h>

void setUp(void) {
    // Test setup - runs before each test
}

void tearDown(void) {
    // Test cleanup - runs after each test
}

void test_unity_is_working(void) {
    TEST_ASSERT_TRUE(1);
    TEST_ASSERT_FALSE(0);
    TEST_ASSERT_EQUAL_INT(42, 42);
}

void test_basic_assertions(void) {
    int value = 10;
    TEST_ASSERT_EQUAL_INT(10, value);
    TEST_ASSERT_NOT_EQUAL_INT(5, value);
    TEST_ASSERT_GREATER_THAN_INT(5, value);
    TEST_ASSERT_LESS_THAN_INT(15, value);
}

int main(void) {
    UNITY_BEGIN();
    
    RUN_TEST(test_unity_is_working);
    RUN_TEST(test_basic_assertions);
    
    return UNITY_END();
}
EOF
```

### Step 4: Compile and Test

```bash
# Compile the test
gcc -std=c99 -Wall -Wextra -Werror -Iinclude -Itests \
    tests/test_unity_install.c tests/unity.c -o tests/test_unity_install

# Run the test
./tests/test_unity_install
```

**Expected output:**
```
Unity test run 1 of 1
.....

-----------------------
2 Tests 0 Failures 0 Ignored 
OK
```

---

## Integration with STAS Build System

### Update Makefile

Add Unity testing support to your existing Makefile:

```bash
# Create backup of current Makefile
cp Makefile Makefile.backup

# Add Unity testing section to Makefile
cat >> Makefile << 'EOF'

# Unity Testing Framework
UNITY_DIR = tests
UNITY_SRC = $(UNITY_DIR)/unity.c
UNITY_HEADERS = $(UNITY_DIR)/unity.h $(UNITY_DIR)/unity_internals.h

# Test source files
TEST_SOURCES = $(wildcard tests/test_*.c)
TEST_OBJECTS = $(TEST_SOURCES:.c=.o)
TEST_TARGETS = $(TEST_SOURCES:.c=)

# Unity test compilation flags
TEST_CFLAGS = $(CFLAGS) -I$(UNITY_DIR) -Iinclude

# Test targets
.PHONY: test test-clean test-all

test: $(TEST_TARGETS)
	@echo "===========================================" 
	@echo "Running STAS Unit Tests"
	@echo "==========================================="
	@for test in $(TEST_TARGETS); do \
		echo "Running $$test..."; \
		if ./$$test; then \
			echo "✅ $$test PASSED"; \
		else \
			echo "❌ $$test FAILED"; \
			exit 1; \
		fi; \
		echo ""; \
	done
	@echo "🎉 All unit tests completed successfully!"

test-all: test test-unicorn
	@echo "🎯 Complete test suite finished!"

test-clean:
	@echo "Cleaning test artifacts..."
	rm -f $(TEST_TARGETS) $(TEST_OBJECTS)

# Individual test compilation
tests/test_%: tests/test_%.c $(UNITY_SRC) $(UNITY_HEADERS) $(OBJECTS)
	@echo "Compiling unit test: $@"
	gcc $(TEST_CFLAGS) $< $(UNITY_SRC) $(filter-out obj/main.o,$(OBJECTS)) -o $@

# Test object files
tests/%.o: tests/%.c $(UNITY_HEADERS)
	gcc $(TEST_CFLAGS) -c $< -o $@

# Help target update
help:
	@echo "STAS Assembler Build System"
	@echo "============================="
	@echo "Build targets:"
	@echo "  make / make all    - Build the assembler"
	@echo "  make debug         - Build with debug symbols"
	@echo "  make clean         - Clean build artifacts"
	@echo "  make test          - Run unit tests (Unity)"
	@echo "  make test-unicorn  - Run emulation tests" 
	@echo "  make test-all      - Run all tests"
	@echo "  make test-clean    - Clean test artifacts"
	@echo "  make install       - Install to system"
	@echo "  make help          - Show this help"

EOF
```

### Verify Makefile Integration

```bash
# Test the new makefile targets
make help

# Should show the new test targets
make test-clean
make test
```

---

## Creating Your First STAS Tests

### Test the Parser (Phase 1 functionality)

```bash
cat > tests/test_parser.c << 'EOF'
#include "unity.h"
#include "parser.h"
#include "lexer.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

void setUp(void) {
    // Setup before each test
}

void tearDown(void) {
    // Cleanup after each test
}

void test_ast_node_creation(void) {
    AST_Node *node = ast_node_create(AST_INSTRUCTION, "movq");
    
    TEST_ASSERT_NOT_NULL(node);
    TEST_ASSERT_EQUAL_INT(AST_INSTRUCTION, node->type);
    TEST_ASSERT_EQUAL_STRING("movq", node->token);
    TEST_ASSERT_NULL(node->children);
    TEST_ASSERT_EQUAL_INT(0, node->child_count);
    
    ast_node_destroy(node);
}

void test_ast_node_add_child(void) {
    AST_Node *parent = ast_node_create(AST_INSTRUCTION, "movq");
    AST_Node *child = ast_node_create(AST_OPERAND, "%rax");
    
    TEST_ASSERT_NOT_NULL(parent);
    TEST_ASSERT_NOT_NULL(child);
    
    int result = ast_node_add_child(parent, child);
    TEST_ASSERT_EQUAL_INT(0, result);
    TEST_ASSERT_EQUAL_INT(1, parent->child_count);
    TEST_ASSERT_EQUAL_PTR(child, parent->children[0]);
    
    ast_node_destroy(parent); // Should also destroy children
}

void test_parser_initialization(void) {
    Parser *parser = parser_create();
    
    TEST_ASSERT_NOT_NULL(parser);
    TEST_ASSERT_NULL(parser->current_token);
    TEST_ASSERT_EQUAL_INT(PARSER_STATE_INITIAL, parser->state);
    TEST_ASSERT_EQUAL_INT(0, parser->error_count);
    
    parser_destroy(parser);
}

void test_basic_instruction_parsing(void) {
    const char *assembly = "movq $42, %rax";
    
    Lexer *lexer = lexer_create(assembly);
    Parser *parser = parser_create();
    
    TEST_ASSERT_NOT_NULL(lexer);
    TEST_ASSERT_NOT_NULL(parser);
    
    AST_Node *ast = parse_statement(parser, lexer);
    
    TEST_ASSERT_NOT_NULL(ast);
    TEST_ASSERT_EQUAL_INT(AST_INSTRUCTION, ast->type);
    
    parser_destroy(parser);
    lexer_destroy(lexer);
    ast_node_destroy(ast);
}

int main(void) {
    UNITY_BEGIN();
    
    RUN_TEST(test_ast_node_creation);
    RUN_TEST(test_ast_node_add_child);
    RUN_TEST(test_parser_initialization);
    RUN_TEST(test_basic_instruction_parsing);
    
    return UNITY_END();
}
EOF
```

### Test the Symbol Table

```bash
cat > tests/test_symbols.c << 'EOF'
#include "unity.h"
#include "symbols.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

void setUp(void) {
    // Setup before each test
}

void tearDown(void) {
    // Cleanup after each test
}

void test_symbol_table_creation(void) {
    SymbolTable *table = symbol_table_create();
    
    TEST_ASSERT_NOT_NULL(table);
    TEST_ASSERT_NOT_NULL(table->buckets);
    TEST_ASSERT_EQUAL_INT(0, table->count);
    
    symbol_table_destroy(table);
}

void test_symbol_creation(void) {
    Symbol *symbol = symbol_create("test_label", 0x1000, SYMBOL_LABEL);
    
    TEST_ASSERT_NOT_NULL(symbol);
    TEST_ASSERT_EQUAL_STRING("test_label", symbol->name);
    TEST_ASSERT_EQUAL_UINT64(0x1000, symbol->address);
    TEST_ASSERT_EQUAL_INT(SYMBOL_LABEL, symbol->type);
    TEST_ASSERT_FALSE(symbol->is_defined);
    
    symbol_destroy(symbol);
}

void test_symbol_table_insert_and_lookup(void) {
    SymbolTable *table = symbol_table_create();
    
    // Insert a symbol
    int result = symbol_table_insert(table, "main", 0x2000, SYMBOL_LABEL);
    TEST_ASSERT_EQUAL_INT(0, result);
    TEST_ASSERT_EQUAL_INT(1, table->count);
    
    // Look up the symbol
    Symbol *found = symbol_table_lookup(table, "main");
    TEST_ASSERT_NOT_NULL(found);
    TEST_ASSERT_EQUAL_STRING("main", found->name);
    TEST_ASSERT_EQUAL_UINT64(0x2000, found->address);
    
    // Try to find non-existent symbol
    Symbol *not_found = symbol_table_lookup(table, "nonexistent");
    TEST_ASSERT_NULL(not_found);
    
    symbol_table_destroy(table);
}

void test_symbol_table_hash_distribution(void) {
    SymbolTable *table = symbol_table_create();
    
    // Insert multiple symbols
    const char *symbols[] = {"main", "start", "loop", "end", "data"};
    int symbol_count = sizeof(symbols) / sizeof(symbols[0]);
    
    for (int i = 0; i < symbol_count; i++) {
        int result = symbol_table_insert(table, symbols[i], i * 0x100, SYMBOL_LABEL);
        TEST_ASSERT_EQUAL_INT(0, result);
    }
    
    TEST_ASSERT_EQUAL_INT(symbol_count, table->count);
    
    // Verify all symbols can be found
    for (int i = 0; i < symbol_count; i++) {
        Symbol *found = symbol_table_lookup(table, symbols[i]);
        TEST_ASSERT_NOT_NULL(found);
        TEST_ASSERT_EQUAL_STRING(symbols[i], found->name);
    }
    
    symbol_table_destroy(table);
}

int main(void) {
    UNITY_BEGIN();
    
    RUN_TEST(test_symbol_table_creation);
    RUN_TEST(test_symbol_creation);
    RUN_TEST(test_symbol_table_insert_and_lookup);
    RUN_TEST(test_symbol_table_hash_distribution);
    
    return UNITY_END();
}
EOF
```

### Test the Lexer

```bash
cat > tests/test_lexer.c << 'EOF'
#include "unity.h"
#include "lexer.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

void setUp(void) {
    // Setup before each test
}

void tearDown(void) {
    // Cleanup after each test
}

void test_lexer_creation(void) {
    const char *input = "movq $42, %rax";
    Lexer *lexer = lexer_create(input);
    
    TEST_ASSERT_NOT_NULL(lexer);
    TEST_ASSERT_NOT_NULL(lexer->input);
    TEST_ASSERT_EQUAL_PTR(input, lexer->input);
    TEST_ASSERT_EQUAL_INT(0, lexer->position);
    TEST_ASSERT_EQUAL_INT(1, lexer->line);
    TEST_ASSERT_EQUAL_INT(1, lexer->column);
    
    lexer_destroy(lexer);
}

void test_basic_tokenization(void) {
    const char *input = "movq";
    Lexer *lexer = lexer_create(input);
    
    Token *token = lexer_next_token(lexer);
    
    TEST_ASSERT_NOT_NULL(token);
    TEST_ASSERT_EQUAL_INT(TOKEN_INSTRUCTION, token->type);
    TEST_ASSERT_EQUAL_STRING("movq", token->value);
    TEST_ASSERT_EQUAL_INT(1, token->line);
    TEST_ASSERT_EQUAL_INT(1, token->column);
    
    token_destroy(token);
    lexer_destroy(lexer);
}

void test_register_tokenization(void) {
    const char *input = "%rax %rbx %rcx";
    Lexer *lexer = lexer_create(input);
    
    const char *expected_registers[] = {"rax", "rbx", "rcx"};
    
    for (int i = 0; i < 3; i++) {
        Token *token = lexer_next_token(lexer);
        TEST_ASSERT_NOT_NULL(token);
        TEST_ASSERT_EQUAL_INT(TOKEN_REGISTER, token->type);
        TEST_ASSERT_EQUAL_STRING(expected_registers[i], token->value);
        token_destroy(token);
    }
    
    lexer_destroy(lexer);
}

void test_immediate_value_tokenization(void) {
    const char *input = "$42 $0x1000 $-5";
    Lexer *lexer = lexer_create(input);
    
    // Test decimal immediate
    Token *token1 = lexer_next_token(lexer);
    TEST_ASSERT_NOT_NULL(token1);
    TEST_ASSERT_EQUAL_INT(TOKEN_IMMEDIATE, token1->type);
    TEST_ASSERT_EQUAL_STRING("42", token1->value);
    
    // Test hex immediate
    Token *token2 = lexer_next_token(lexer);
    TEST_ASSERT_NOT_NULL(token2);
    TEST_ASSERT_EQUAL_INT(TOKEN_IMMEDIATE, token2->type);
    TEST_ASSERT_EQUAL_STRING("0x1000", token2->value);
    
    // Test negative immediate
    Token *token3 = lexer_next_token(lexer);
    TEST_ASSERT_NOT_NULL(token3);
    TEST_ASSERT_EQUAL_INT(TOKEN_IMMEDIATE, token3->type);
    TEST_ASSERT_EQUAL_STRING("-5", token3->value);
    
    token_destroy(token1);
    token_destroy(token2);
    token_destroy(token3);
    lexer_destroy(lexer);
}

void test_complete_instruction_tokenization(void) {
    const char *input = "movq $42, %rax";
    Lexer *lexer = lexer_create(input);
    
    // Instruction
    Token *instr = lexer_next_token(lexer);
    TEST_ASSERT_EQUAL_INT(TOKEN_INSTRUCTION, instr->type);
    TEST_ASSERT_EQUAL_STRING("movq", instr->value);
    
    // Immediate
    Token *imm = lexer_next_token(lexer);
    TEST_ASSERT_EQUAL_INT(TOKEN_IMMEDIATE, imm->type);
    TEST_ASSERT_EQUAL_STRING("42", imm->value);
    
    // Comma
    Token *comma = lexer_next_token(lexer);
    TEST_ASSERT_EQUAL_INT(TOKEN_COMMA, comma->type);
    
    // Register
    Token *reg = lexer_next_token(lexer);
    TEST_ASSERT_EQUAL_INT(TOKEN_REGISTER, reg->type);
    TEST_ASSERT_EQUAL_STRING("rax", reg->value);
    
    // EOF
    Token *eof = lexer_next_token(lexer);
    TEST_ASSERT_EQUAL_INT(TOKEN_EOF, eof->type);
    
    token_destroy(instr);
    token_destroy(imm);
    token_destroy(comma);
    token_destroy(reg);
    token_destroy(eof);
    lexer_destroy(lexer);
}

int main(void) {
    UNITY_BEGIN();
    
    RUN_TEST(test_lexer_creation);
    RUN_TEST(test_basic_tokenization);
    RUN_TEST(test_register_tokenization);
    RUN_TEST(test_immediate_value_tokenization);
    RUN_TEST(test_complete_instruction_tokenization);
    
    return UNITY_END();
}
EOF
```

---

## Running Tests

### Individual Tests

```bash
# Run specific test suites
make tests/test_parser
./tests/test_parser

make tests/test_symbols  
./tests/test_symbols

make tests/test_lexer
./tests/test_lexer
```

### All Unit Tests

```bash
# Run all Unity tests
make test
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
├── test_lexer.c            # Lexer component tests
├── test_parser.c           # Parser component tests
├── test_symbols.c          # Symbol table tests
├── test_arch_x86_64.c      # x86-64 architecture tests (future)
├── test_integration.c      # Integration tests (future)
└── test_unity_install.c    # Installation verification test
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
gcc -I tests/ -I include/ tests/test_parser.c tests/unity.c src/parser.c -o tests/test_parser
```

**2. Linking Issues**
```bash
# Exclude main.o from test compilation
gcc $(filter-out obj/main.o,$(OBJECTS)) tests/test_parser.c tests/unity.c -o tests/test_parser
```

**3. Missing Headers**
```bash
# Verify Unity files are present
ls tests/unity*.{c,h}
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
# Verify Unity is properly installed
make test-clean
make test

# Expected output:
# ==========================================
# Running STAS Unit Tests  
# ==========================================
# Running tests/test_parser...
# ✅ tests/test_parser PASSED
# 
# Running tests/test_symbols...
# ✅ tests/test_symbols PASSED
# 
# Running tests/test_lexer...
# ✅ tests/test_lexer PASSED
# 
# 🎉 All unit tests completed successfully!
```

### Integration Verification

```bash
# Test complete build and test cycle
make clean
make
make test
make test-unicorn
```

---

## Next Steps

With Unity successfully installed:

1. **Implement Tests**: Write comprehensive tests for Phase 2 parser features
2. **Test-Driven Development**: Write tests before implementing new features
3. **Continuous Testing**: Run `make test` after each change
4. **Expand Coverage**: Add tests for new architecture modules as they're developed

Unity is now ready to support robust development of your STAS assembler! 🎯
