# C Unit Testing Frameworks Comparison for STAS

## Overview

This analysis compares the most popular C unit testing frameworks to help determine the best fit for STAS assembler development. Each framework is evaluated based on setup complexity, feature set, maintainability, and integration capabilities.

---

## Framework Comparison Matrix

| Framework | Setup | Dependencies | Mocking | Output Formats | Memory Testing | License | Active Dev |
|-----------|-------|-------------|---------|----------------|----------------|---------|------------|
| **Unity** | ⭐⭐⭐⭐⭐ | None | No | Basic | No | MIT | ✅ Active |
| **CMocka** | ⭐⭐⭐⭐ | None | ✅ Yes | Multiple | ✅ Yes | Apache 2.0 | ✅ Active |
| **CUnit** | ⭐⭐⭐ | None | No | Multiple | No | LGPL | ⚠️ Maintenance |
| **Criterion** | ⭐⭐ | Many | ✅ Yes | Multiple | ✅ Yes | MIT | ✅ Active |
| **Minunit** | ⭐⭐⭐⭐⭐ | None | No | Basic | No | MIT | ⚠️ Minimal |

---

## Detailed Framework Analysis

### 1. Unity ⭐⭐⭐⭐⭐ **RECOMMENDED FOR STAS**

**Best fit for embedded-focused C projects like STAS**

#### ✅ **Strengths**
- **Minimal Setup**: Single `.c` file + headers, drop into any project
- **Zero Dependencies**: Only requires standard C library
- **Embedded Focus**: Designed specifically for microcontroller/embedded development
- **Simple API**: Easy to learn, minimal cognitive overhead
- **Build System Agnostic**: Works with Make, CMake, any build system
- **Excellent Documentation**: Comprehensive guides and examples
- **Active Community**: 4.6k GitHub stars, active development

#### ⚠️ **Limitations**
- **No Built-in Mocking**: Must use external tools (CMock) for mocking
- **Basic Output**: Simple text output (can be enhanced with external tools)
- **No Memory Leak Detection**: Requires external tools like Valgrind

#### 🔧 **Integration Example**
```c
#include "unity.h"
#include "../src/parser.h"

void setUp(void) {
    // Test setup
}

void tearDown(void) {
    // Test cleanup
}

void test_ast_node_creation(void) {
    AST_Node *node = ast_node_create(AST_INSTRUCTION, "movq");
    TEST_ASSERT_NOT_NULL(node);
    TEST_ASSERT_EQUAL_INT(AST_INSTRUCTION, node->type);
    TEST_ASSERT_EQUAL_STRING("movq", node->token);
    ast_node_destroy(node);
}

int main(void) {
    UNITY_BEGIN();
    RUN_TEST(test_ast_node_creation);
    return UNITY_END();
}
```

#### 📦 **Setup for STAS**
```bash
# Download Unity
wget https://github.com/ThrowTheSwitch/Unity/archive/v2.6.1.tar.gz
tar -xzf v2.6.1.tar.gz
cp Unity-2.6.1/src/* tests/unity/

# Add to Makefile
UNITY_SRC = tests/unity/unity.c
TEST_TARGETS = tests/test_parser tests/test_symbols tests/test_lexer
```

---

### 2. CMocka ⭐⭐⭐⭐ **SOLID ALTERNATIVE**

**Feature-rich framework with excellent mocking support**

#### ✅ **Strengths**
- **Built-in Mocking**: Excellent mock object support without external dependencies
- **Memory Testing**: Built-in memory leak detection and buffer overflow checking
- **Multiple Output Formats**: TAP, Subunit, xUnit XML, custom formats
- **Exception Handling**: Recovers from segfaults and signals
- **Professional Quality**: Used by major projects (Samba, OpenVPN, BIND DNS)
- **Cross-Platform**: Works on embedded systems, Linux, Windows, BSD

#### ⚠️ **Limitations**
- **More Complex Setup**: Requires CMake or manual configuration
- **Larger Footprint**: More overhead than Unity
- **Learning Curve**: More complex API than Unity

#### 🔧 **Integration Example**
```c
#include <stdarg.h>
#include <stddef.h>
#include <setjmp.h>
#include <cmocka.h>
#include "../src/parser.h"

// Mock symbol table for testing
Symbol* mock_symbol_lookup(const char* name) {
    check_expected_ptr(name);
    return (Symbol*)mock();
}

static void test_parser_with_mocked_symbols(void **state) {
    expect_string(mock_symbol_lookup, name, "test_label");
    will_return(mock_symbol_lookup, NULL);
    
    Parser *parser = parser_create();
    AST_Node *result = parse_instruction(parser, "jmp test_label");
    
    assert_non_null(result);
    assert_int_equal(AST_INSTRUCTION, result->type);
    
    parser_destroy(parser);
    ast_node_destroy(result);
}

int main(void) {
    const struct CMUnitTest tests[] = {
        cmocka_unit_test(test_parser_with_mocked_symbols),
    };
    return cmocka_run_group_tests(tests, NULL, NULL);
}
```

---

### 3. CUnit ⭐⭐⭐ **MATURE BUT AGING**

**Traditional C testing framework with comprehensive features**

#### ✅ **Strengths**
- **Multiple Interfaces**: Console, Curses, Automated XML output
- **Comprehensive API**: Rich set of assertion macros
- **Test Organization**: Good support for test suites and groups
- **Documentation**: Well-documented with examples

#### ⚠️ **Limitations**
- **Maintenance Mode**: Less active development
- **Setup Complexity**: Requires library compilation and linking
- **LGPL License**: May be restrictive for some projects
- **No Modern Features**: Lacks mocking, memory testing

#### 🔧 **Basic Example**
```c
#include <CUnit/Basic.h>
#include "../src/parser.h"

void test_ast_creation(void) {
    AST_Node *node = ast_node_create(AST_INSTRUCTION, "movq");
    CU_ASSERT_PTR_NOT_NULL(node);
    CU_ASSERT_EQUAL(node->type, AST_INSTRUCTION);
    ast_node_destroy(node);
}

int main() {
    CU_initialize_registry();
    
    CU_pSuite suite = CU_add_suite("Parser Tests", NULL, NULL);
    CU_add_test(suite, "AST Creation", test_ast_creation);
    
    CU_basic_run_tests();
    CU_cleanup_registry();
    return 0;
}
```

---

### 4. Criterion ⭐⭐ **FEATURE-RICH BUT HEAVY**

**Modern C/C++ testing framework with advanced features**

#### ✅ **Strengths**
- **Modern Design**: Contemporary C testing approach
- **Built-in Mocking**: Comprehensive mocking support
- **Parameterized Tests**: Support for data-driven testing
- **Memory Testing**: Built-in leak detection
- **Beautiful Output**: Colored, formatted test results

#### ⚠️ **Limitations**
- **Heavy Dependencies**: Requires many system libraries
- **Complex Setup**: CMake/Meson build system required
- **Large Footprint**: Not suitable for embedded development
- **Platform Limitations**: May not work on all embedded targets

---

### 5. Minunit ⭐⭐⭐⭐ **ULTRA-MINIMAL**

**Extremely lightweight testing framework**

#### ✅ **Strengths**
- **Ultra-Simple**: ~50 lines of code in a header file
- **Zero Dependencies**: Just a header file
- **Easy Integration**: Drop-in and use immediately

#### ⚠️ **Limitations**
- **Too Basic**: Lacks essential features for complex projects
- **No Test Organization**: No suite/group support
- **Minimal Assertions**: Very limited assertion macros
- **No Error Recovery**: Tests stop on first failure

---

## Recommendation for STAS

### **Primary Choice: Unity** ⭐⭐⭐⭐⭐

Unity is the **best fit for STAS** because:

1. **Perfect for Embedded/System Code**: Designed for projects like assemblers
2. **Minimal Integration Overhead**: Drops into existing build system easily
3. **Matches Project Philosophy**: Clean, simple, focused (like STAS design)
4. **Zero Dependencies**: Aligns with STAS's minimal dependency approach
5. **Active Development**: Ensures long-term support
6. **Industry Adoption**: Used by embedded systems companies worldwide

### **Secondary Choice: CMocka** ⭐⭐⭐⭐

Consider CMocka if you need:
- Built-in mocking capabilities
- Memory leak detection
- Advanced output formats
- Professional-grade testing features

---

## Implementation Plan for STAS

### Phase 1: Unity Integration
```bash
# 1. Add Unity to project
mkdir tests/unity
wget -O tests/unity.tar.gz https://github.com/ThrowTheSwitch/Unity/archive/v2.6.1.tar.gz
tar -xzf tests/unity.tar.gz -C tests/unity --strip-components=1
```

### Phase 2: Test Structure
```
tests/
├── unity/                  # Unity framework files
│   ├── unity.c
│   ├── unity.h
│   └── unity_internals.h
├── test_lexer.c           # Lexer tests
├── test_parser.c          # Parser tests  
├── test_symbols.c         # Symbol table tests
├── test_arch_x86_64.c     # Architecture tests
└── run_all_tests.c        # Test runner
```

### Phase 3: Makefile Integration
```makefile
# Unity testing
UNITY_DIR = tests/unity
UNITY_SRC = $(UNITY_DIR)/unity.c
TEST_SOURCES = tests/test_*.c
TEST_OBJECTS = $(TEST_SOURCES:.c=.o)
TEST_TARGETS = $(TEST_SOURCES:.c=)

test: $(TEST_TARGETS)
	@echo "Running all unit tests..."
	@for test in $(TEST_TARGETS); do \
		echo "Running $$test..."; \
		./$$test; \
	done

tests/%: tests/%.c $(UNITY_SRC) $(OBJECTS)
	gcc $(CFLAGS) -I$(UNITY_DIR) -Iinclude $< $(UNITY_SRC) $(filter-out obj/main.o,$(OBJECTS)) -o $@
```

---

## Conclusion

**Unity is the clear winner for STAS** due to its:
- Perfect match for embedded/systems programming
- Minimal setup and maintenance overhead  
- Strong community and documentation
- Clean integration with existing build systems
- Zero external dependencies

This choice aligns perfectly with STAS's design philosophy of clean, focused, and maintainable code while providing robust testing capabilities for your assembler development.

The framework can grow with the project - start with Unity for core functionality testing, and add CMock later if complex mocking becomes necessary for architecture modules.
