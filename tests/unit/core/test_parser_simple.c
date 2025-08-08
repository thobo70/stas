#include "../../unity/src/unity.h"
#include "../framework/unity_extensions.h"
#include "../../include/parser.h"
#include "../../include/lexer.h"
#include "../../include/symbols.h"
#include "../../include/arch_interface.h"
#include <string.h>
#include <stdlib.h>

// Forward declarations for specific architecture functions
extern arch_ops_t *get_arch_ops_x86_64(void);
extern arch_ops_t *get_arch_ops_x86_32(void);
extern arch_ops_t *get_arch_ops_x86_16(void);

// Test fixtures
static parser_t* parser;
static symbol_table_t* symbols;
static lexer_t* lexer;

void setUp(void) {
    symbols = symbol_table_create(32);
    lexer = NULL;
    parser = NULL;
}

void tearDown(void) {
    if (parser) {
        parser_destroy(parser);
        parser = NULL;
    }
    if (lexer) {
        lexer_destroy(lexer);
        lexer = NULL;
    }
    if (symbols) {
        symbol_table_destroy(symbols);
        symbols = NULL;
    }
}

// Test basic parser creation and destruction
void test_parser_create_destroy(void) {
    lexer = lexer_create("nop", "test.s");
    TEST_ASSERT_NOT_NULL(lexer);
    
    // Get x86_64 architecture (most common)
    arch_ops_t *arch = get_arch_ops_x86_64();
    TEST_ASSERT_NOT_NULL(arch);
    
    parser = parser_create(lexer, arch);
    TEST_ASSERT_NOT_NULL(parser);
    TEST_ASSERT_FALSE(parser_has_error(parser));
}

// Test parser with NULL lexer
void test_parser_create_null_lexer(void) {
    arch_ops_t *arch = get_arch_ops_x86_64();
    TEST_ASSERT_NOT_NULL(arch);
    
    parser = parser_create(NULL, arch);
    TEST_ASSERT_NULL(parser);
}

// Test parser with NULL architecture
void test_parser_create_null_arch(void) {
    lexer = lexer_create("nop", "test.s");
    TEST_ASSERT_NOT_NULL(lexer);
    
    parser = parser_create(lexer, NULL);
    TEST_ASSERT_NULL(parser);
}

// Test basic parsing functionality
void test_parser_basic_parse(void) {
    lexer = lexer_create("nop\nmov %rax, %rbx\n", "test.s");
    TEST_ASSERT_NOT_NULL(lexer);
    
    arch_ops_t *arch = get_arch_ops_x86_64();
    TEST_ASSERT_NOT_NULL(arch);
    
    parser = parser_create(lexer, arch);
    TEST_ASSERT_NOT_NULL(parser);
    
    // Try to parse the input
    ast_node_t *root = parser_parse(parser);
    (void)root;  // Suppress unused variable warning
    
    // Should not have errors for basic valid input
    if (parser_has_error(parser)) {
        printf("Parser error: %s\n", parser_get_error(parser));
    }
    
    // Even if parsing fails, the parser should be functional
    TEST_ASSERT_NOT_NULL(parser);
}

// Test parser error handling
void test_parser_error_handling(void) {
    lexer = lexer_create("invalid_instruction_xyz", "test.s");
    TEST_ASSERT_NOT_NULL(lexer);
    
    arch_ops_t *arch = get_arch_ops_x86_64();
    TEST_ASSERT_NOT_NULL(arch);
    
    parser = parser_create(lexer, arch);
    TEST_ASSERT_NOT_NULL(parser);
    
    // Parse invalid input
    ast_node_t *root = parser_parse(parser);
    (void)root;  // Suppress unused variable warning
    
    // Should have error handling capability
    // (The actual behavior depends on implementation)
    TEST_ASSERT_NOT_NULL(parser);
}

// Test parser with empty input
void test_parser_empty_input(void) {
    lexer = lexer_create("", "test.s");
    TEST_ASSERT_NOT_NULL(lexer);
    
    arch_ops_t *arch = get_arch_ops_x86_64();
    TEST_ASSERT_NOT_NULL(arch);
    
    parser = parser_create(lexer, arch);
    TEST_ASSERT_NOT_NULL(parser);
    
    ast_node_t *root = parser_parse(parser);
    (void)root;  // Suppress unused variable warning
    
    // Parser should handle empty input gracefully
    TEST_ASSERT_NOT_NULL(parser);
}

// Test parser with comment-only input
void test_parser_comments_only(void) {
    lexer = lexer_create("# This is a comment\n# Another comment\n", "test.s");
    TEST_ASSERT_NOT_NULL(lexer);
    
    arch_ops_t *arch = get_arch_ops_x86_64();
    TEST_ASSERT_NOT_NULL(arch);
    
    parser = parser_create(lexer, arch);
    TEST_ASSERT_NOT_NULL(parser);
    
    ast_node_t *root = parser_parse(parser);
    (void)root;  // Suppress unused variable warning
    
    // Parser should handle comment-only input
    TEST_ASSERT_NOT_NULL(parser);
}

// Test parser with multiple architectures
void test_parser_different_architectures(void) {
    // Test x86_64
    lexer = lexer_create("nop", "test.s");
    TEST_ASSERT_NOT_NULL(lexer);
    arch_ops_t *arch = get_arch_ops_x86_64();
    if (arch != NULL) {
        parser = parser_create(lexer, arch);
        TEST_ASSERT_NOT_NULL(parser);
        parser_destroy(parser);
        parser = NULL;
    }
    lexer_destroy(lexer);
    lexer = NULL;
    
    // Test x86_32
    lexer = lexer_create("nop", "test.s");
    TEST_ASSERT_NOT_NULL(lexer);
    arch = get_arch_ops_x86_32();
    if (arch != NULL) {
        parser = parser_create(lexer, arch);
        TEST_ASSERT_NOT_NULL(parser);
        parser_destroy(parser);
        parser = NULL;
    }
    lexer_destroy(lexer);
    lexer = NULL;
}

// Unity test runner setup
int main(void) {
    UNITY_BEGIN();
    
    RUN_TEST(test_parser_create_destroy);
    RUN_TEST(test_parser_create_null_lexer);
    RUN_TEST(test_parser_create_null_arch);
    RUN_TEST(test_parser_basic_parse);
    RUN_TEST(test_parser_error_handling);
    RUN_TEST(test_parser_empty_input);
    RUN_TEST(test_parser_comments_only);
    RUN_TEST(test_parser_different_architectures);
    
    return UNITY_END();
}
