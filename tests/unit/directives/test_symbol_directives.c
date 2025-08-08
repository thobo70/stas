#define _GNU_SOURCE
#include "../../unity/src/unity.h"
#include "codegen.h"
#include "parser.h"
#include "lexer.h"
#include "../../src/core/output_format.h"
#include "symbols.h"
#include "arch_interface.h"
#include <string.h>
#include <stdlib.h>

// Mock architecture operations
static arch_ops_t mock_arch_ops = {
    .name = "mock",
    .init = NULL,
    .cleanup = NULL,
    .parse_instruction = NULL,
    .encode_instruction = NULL,
    .parse_addressing = NULL,
    .validate_addressing = NULL,
    .handle_directive = NULL,
    .get_instruction_size = NULL,
    .get_alignment = NULL
};

// Helper function to create test context
static codegen_ctx_t *create_test_context(void) {
    output_context_t *output = calloc(1, sizeof(output_context_t));
    output->format = FORMAT_FLAT_BIN;
    output->base_address = 0x1000;
    output->verbose = false;
    
    symbol_table_t *symbols = symbol_table_create(256);
    
    codegen_ctx_t *ctx = codegen_create(&mock_arch_ops, output, symbols);
    return ctx;
}

// Helper function to cleanup test context
static void cleanup_test_context(codegen_ctx_t *ctx) {
    if (ctx) {
        if (ctx->symbols) {
            symbol_table_destroy(ctx->symbols);
        }
        if (ctx->output) {
            free(ctx->output);
        }
        codegen_destroy(ctx);
    }
}

// Helper function to create AST directive node
static ast_node_t *create_directive_node(const char *name, char **args, size_t arg_count) {
    ast_node_t *node = calloc(1, sizeof(ast_node_t));
    node->type = AST_DIRECTIVE;
    
    ast_directive_t *directive = calloc(1, sizeof(ast_directive_t));
    directive->name = strdup(name);
    directive->args = args;
    directive->arg_count = arg_count;
    
    node->data = directive;
    return node;
}

// Helper function to create AST label node
static ast_node_t *create_label_node(const char *name) {
    ast_node_t *node = calloc(1, sizeof(ast_node_t));
    node->type = AST_LABEL;
    
    ast_label_t *label = calloc(1, sizeof(ast_label_t));
    label->name = strdup(name);
    
    node->data = label;
    return node;
}

// Helper function to free directive/label node
static void free_ast_node(ast_node_t *node) {
    if (node && node->data) {
        if (node->type == AST_DIRECTIVE) {
            ast_directive_t *directive = (ast_directive_t *)node->data;
            if (directive->name) {
                free(directive->name);
            }
            free(directive);
        } else if (node->type == AST_LABEL) {
            ast_label_t *label = (ast_label_t *)node->data;
            if (label->name) {
                free(label->name);
            }
            free(label);
        }
        free(node);
    }
}

void setUp(void) {
    // Set up code before each test
}

void tearDown(void) {
    // Clean up code after each test
}

// Test .equ directive
void test_equ_directive(void) {
    codegen_ctx_t *ctx = create_test_context();
    TEST_ASSERT_NOT_NULL(ctx);
    
    char *args[] = {"MAX_VALUE", "100"};
    ast_node_t *node = create_directive_node(".equ", args, 2);
    
    int result = codegen_generate(ctx, node);
    TEST_ASSERT_EQUAL(0, result);
    
    // Check that symbol was created
    symbol_t *symbol = symbol_table_lookup(ctx->symbols, "MAX_VALUE");
    TEST_ASSERT_NOT_NULL(symbol);
    TEST_ASSERT_EQUAL(SYMBOL_CONSTANT, symbol->type);
    TEST_ASSERT_EQUAL(100, symbol->value);
    TEST_ASSERT_TRUE(symbol->defined);
    
    free_ast_node(node);
    cleanup_test_context(ctx);
}

// Test .equ directive with hex value
void test_equ_directive_hex(void) {
    codegen_ctx_t *ctx = create_test_context();
    TEST_ASSERT_NOT_NULL(ctx);
    
    char *args[] = {"BUFFER_SIZE", "0x400"};
    ast_node_t *node = create_directive_node(".equ", args, 2);
    
    int result = codegen_generate(ctx, node);
    TEST_ASSERT_EQUAL(0, result);
    
    symbol_t *symbol = symbol_table_lookup(ctx->symbols, "BUFFER_SIZE");
    TEST_ASSERT_NOT_NULL(symbol);
    TEST_ASSERT_EQUAL(0x400, symbol->value);
    
    free_ast_node(node);
    cleanup_test_context(ctx);
}

// Test .set directive (allows redefinition)
void test_set_directive_redefinition(void) {
    codegen_ctx_t *ctx = create_test_context();
    TEST_ASSERT_NOT_NULL(ctx);
    
    // First definition
    char *args1[] = {"FLAG", "1"};
    ast_node_t *node1 = create_directive_node(".set", args1, 2);
    
    int result1 = codegen_generate(ctx, node1);
    TEST_ASSERT_EQUAL(0, result1);
    
    symbol_t *symbol = symbol_table_lookup(ctx->symbols, "FLAG");
    TEST_ASSERT_NOT_NULL(symbol);
    TEST_ASSERT_EQUAL(1, symbol->value);
    
    // Redefinition with .set (should succeed)
    char *args2[] = {"FLAG", "2"};
    ast_node_t *node2 = create_directive_node(".set", args2, 2);
    
    int result2 = codegen_generate(ctx, node2);
    TEST_ASSERT_EQUAL(0, result2);
    
    symbol = symbol_table_lookup(ctx->symbols, "FLAG");
    TEST_ASSERT_NOT_NULL(symbol);
    TEST_ASSERT_EQUAL(2, symbol->value);
    
    free_ast_node(node1);
    free_ast_node(node2);
    cleanup_test_context(ctx);
}

// Test .equ directive redefinition fails
void test_equ_directive_redefinition_fails(void) {
    codegen_ctx_t *ctx = create_test_context();
    TEST_ASSERT_NOT_NULL(ctx);
    
    // First definition
    char *args1[] = {"CONSTANT", "10"};
    ast_node_t *node1 = create_directive_node(".equ", args1, 2);
    
    int result1 = codegen_generate(ctx, node1);
    TEST_ASSERT_EQUAL(0, result1);
    
    // Redefinition with .equ (should fail)
    char *args2[] = {"CONSTANT", "20"};
    ast_node_t *node2 = create_directive_node(".equ", args2, 2);
    
    int result2 = codegen_generate(ctx, node2);
    TEST_ASSERT_NOT_EQUAL(0, result2);  // Should fail
    
    // Original value should be preserved
    symbol_t *symbol = symbol_table_lookup(ctx->symbols, "CONSTANT");
    TEST_ASSERT_NOT_NULL(symbol);
    TEST_ASSERT_EQUAL(10, symbol->value);
    
    free_ast_node(node1);
    free_ast_node(node2);
    cleanup_test_context(ctx);
}

// Test .global directive
void test_global_directive(void) {
    codegen_ctx_t *ctx = create_test_context();
    TEST_ASSERT_NOT_NULL(ctx);
    
    char *args[] = {"_start"};
    ast_node_t *node = create_directive_node(".global", args, 1);
    
    int result = codegen_generate(ctx, node);
    TEST_ASSERT_EQUAL(0, result);
    
    // Check that symbol was created with global visibility
    symbol_t *symbol = symbol_table_lookup(ctx->symbols, "_start");
    TEST_ASSERT_NOT_NULL(symbol);
    TEST_ASSERT_EQUAL(VISIBILITY_GLOBAL, symbol->visibility);
    TEST_ASSERT_EQUAL(SYMBOL_UNDEFINED, symbol->type);  // Forward reference
    
    free_ast_node(node);
    cleanup_test_context(ctx);
}

// Test .global directive with multiple symbols
void test_global_directive_multiple(void) {
    codegen_ctx_t *ctx = create_test_context();
    TEST_ASSERT_NOT_NULL(ctx);
    
    char *args[] = {"_start", "main", "exit"};
    ast_node_t *node = create_directive_node(".global", args, 3);
    
    int result = codegen_generate(ctx, node);
    TEST_ASSERT_EQUAL(0, result);
    
    // Check all symbols
    symbol_t *symbol1 = symbol_table_lookup(ctx->symbols, "_start");
    symbol_t *symbol2 = symbol_table_lookup(ctx->symbols, "main");
    symbol_t *symbol3 = symbol_table_lookup(ctx->symbols, "exit");
    
    TEST_ASSERT_NOT_NULL(symbol1);
    TEST_ASSERT_NOT_NULL(symbol2);
    TEST_ASSERT_NOT_NULL(symbol3);
    
    TEST_ASSERT_EQUAL(VISIBILITY_GLOBAL, symbol1->visibility);
    TEST_ASSERT_EQUAL(VISIBILITY_GLOBAL, symbol2->visibility);
    TEST_ASSERT_EQUAL(VISIBILITY_GLOBAL, symbol3->visibility);
    
    free_ast_node(node);
    cleanup_test_context(ctx);
}

// Test .extern directive
void test_extern_directive(void) {
    codegen_ctx_t *ctx = create_test_context();
    TEST_ASSERT_NOT_NULL(ctx);
    
    char *args[] = {"printf"};
    ast_node_t *node = create_directive_node(".extern", args, 1);
    
    int result = codegen_generate(ctx, node);
    TEST_ASSERT_EQUAL(0, result);
    
    symbol_t *symbol = symbol_table_lookup(ctx->symbols, "printf");
    TEST_ASSERT_NOT_NULL(symbol);
    TEST_ASSERT_EQUAL(SYMBOL_EXTERNAL, symbol->type);
    TEST_ASSERT_EQUAL(VISIBILITY_GLOBAL, symbol->visibility);
    TEST_ASSERT_FALSE(symbol->defined);
    
    free_ast_node(node);
    cleanup_test_context(ctx);
}

// Test label creation and symbol table integration
void test_label_symbol_integration(void) {
    codegen_ctx_t *ctx = create_test_context();
    TEST_ASSERT_NOT_NULL(ctx);
    
    // Set current address
    ctx->current_address = 0x2000;
    ctx->current_section = ".text";
    
    ast_node_t *label_node = create_label_node("loop_start");
    
    int result = codegen_generate(ctx, label_node);
    TEST_ASSERT_EQUAL(0, result);
    
    symbol_t *symbol = symbol_table_lookup(ctx->symbols, "loop_start");
    TEST_ASSERT_NOT_NULL(symbol);
    TEST_ASSERT_EQUAL(SYMBOL_LABEL, symbol->type);
    TEST_ASSERT_EQUAL(0x2000, symbol->value);
    TEST_ASSERT_TRUE(symbol->defined);
    TEST_ASSERT_EQUAL(VISIBILITY_LOCAL, symbol->visibility);
    
    free_ast_node(label_node);
    cleanup_test_context(ctx);
}

// Test .global directive updating existing label
void test_global_directive_updates_existing_label(void) {
    codegen_ctx_t *ctx = create_test_context();
    TEST_ASSERT_NOT_NULL(ctx);
    
    // Create label first
    ctx->current_address = 0x3000;
    ctx->current_section = ".text";
    
    ast_node_t *label_node = create_label_node("my_function");
    int result1 = codegen_generate(ctx, label_node);
    TEST_ASSERT_EQUAL(0, result1);
    
    symbol_t *symbol = symbol_table_lookup(ctx->symbols, "my_function");
    TEST_ASSERT_NOT_NULL(symbol);
    TEST_ASSERT_EQUAL(VISIBILITY_LOCAL, symbol->visibility);
    
    // Now make it global
    char *args[] = {"my_function"};
    ast_node_t *global_node = create_directive_node(".global", args, 1);
    
    int result2 = codegen_generate(ctx, global_node);
    TEST_ASSERT_EQUAL(0, result2);
    
    // Check that visibility was updated
    symbol = symbol_table_lookup(ctx->symbols, "my_function");
    TEST_ASSERT_NOT_NULL(symbol);
    TEST_ASSERT_EQUAL(VISIBILITY_GLOBAL, symbol->visibility);
    TEST_ASSERT_EQUAL(0x3000, symbol->value);  // Address preserved
    TEST_ASSERT_TRUE(symbol->defined);
    
    free_ast_node(label_node);
    free_ast_node(global_node);
    cleanup_test_context(ctx);
}

// Test invalid symbol constant definition
void test_invalid_symbol_constant(void) {
    codegen_ctx_t *ctx = create_test_context();
    TEST_ASSERT_NOT_NULL(ctx);
    
    char *args[] = {"INVALID", "not_a_number"};
    ast_node_t *node = create_directive_node(".equ", args, 2);
    
    int result = codegen_generate(ctx, node);
    TEST_ASSERT_NOT_EQUAL(0, result);  // Should fail
    
    free_ast_node(node);
    cleanup_test_context(ctx);
}

// Test missing arguments
void test_missing_arguments(void) {
    codegen_ctx_t *ctx = create_test_context();
    TEST_ASSERT_NOT_NULL(ctx);
    
    char *args[] = {"SYMBOL_ONLY"};
    ast_node_t *node = create_directive_node(".equ", args, 1);  // Missing value
    
    int result = codegen_generate(ctx, node);
    TEST_ASSERT_NOT_EQUAL(0, result);  // Should fail
    
    free_ast_node(node);
    cleanup_test_context(ctx);
}

// Run all tests
int main(void) {
    UNITY_BEGIN();
    
    RUN_TEST(test_equ_directive);
    RUN_TEST(test_equ_directive_hex);
    RUN_TEST(test_set_directive_redefinition);
    RUN_TEST(test_equ_directive_redefinition_fails);
    RUN_TEST(test_global_directive);
    RUN_TEST(test_global_directive_multiple);
    RUN_TEST(test_extern_directive);
    RUN_TEST(test_label_symbol_integration);
    RUN_TEST(test_global_directive_updates_existing_label);
    RUN_TEST(test_invalid_symbol_constant);
    RUN_TEST(test_missing_arguments);
    
    return UNITY_END();
}
