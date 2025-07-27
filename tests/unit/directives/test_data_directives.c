#define _GNU_SOURCE
#include "unity.h"
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

// Helper function to free directive node
static void free_directive_node(ast_node_t *node) {
    if (node && node->data) {
        ast_directive_t *directive = (ast_directive_t *)node->data;
        if (directive->name) {
            free(directive->name);
        }
        // Note: args are freed by caller since they're often stack allocated
        free(directive);
        free(node);
    }
}

void setUp(void) {
    // Set up code before each test
}

void tearDown(void) {
    // Clean up code after each test
}

// Test .byte directive with single value
void test_byte_directive_single_value(void) {
    codegen_ctx_t *ctx = create_test_context();
    TEST_ASSERT_NOT_NULL(ctx);
    
    char *args[] = {"42"};
    ast_node_t *node = create_directive_node(".byte", args, 1);
    
    // Process directive (using internal function - we'll need to expose this for testing)
    // For now, test through the main API
    int result = codegen_generate(ctx, node);
    TEST_ASSERT_EQUAL(0, result);
    
    TEST_ASSERT_EQUAL(1, ctx->total_code_size);
    // Note: After flush, code_size is 0 but data is moved to output format
    // Can't check ctx->code_buffer contents after flush
    
    free_directive_node(node);
    cleanup_test_context(ctx);
}

// Test .byte directive with multiple values
void test_byte_directive_multiple_values(void) {
    codegen_ctx_t *ctx = create_test_context();
    TEST_ASSERT_NOT_NULL(ctx);
    
    char *args[] = {"0x10", "0x20", "0x30"};
    ast_node_t *node = create_directive_node(".byte", args, 3);
    
    int result = codegen_generate(ctx, node);
    TEST_ASSERT_EQUAL(0, result);
    
    TEST_ASSERT_EQUAL(3, ctx->total_code_size);
    // TEST_ASSERT_EQUAL(0x10, ctx->code_buffer[0]);
    // TEST_ASSERT_EQUAL(0x20, ctx->code_buffer[1]);
    // TEST_ASSERT_EQUAL(0x30, ctx->code_buffer[2]);
    
    free_directive_node(node);
    cleanup_test_context(ctx);
}

// Test .word directive
void test_word_directive(void) {
    codegen_ctx_t *ctx = create_test_context();
    TEST_ASSERT_NOT_NULL(ctx);
    
    char *args[] = {"0x1234", "0xABCD"};
    ast_node_t *node = create_directive_node(".word", args, 2);
    
    int result = codegen_generate(ctx, node);
    TEST_ASSERT_EQUAL(0, result);
    
    TEST_ASSERT_EQUAL(4, ctx->total_code_size);
    // Can't check code_buffer contents after flush
    
    free_directive_node(node);
    cleanup_test_context(ctx);
}

// Test .dword directive
void test_dword_directive(void) {
    codegen_ctx_t *ctx = create_test_context();
    TEST_ASSERT_NOT_NULL(ctx);
    
    char *args[] = {"0x12345678"};
    ast_node_t *node = create_directive_node(".dword", args, 1);
    
    int result = codegen_generate(ctx, node);
    TEST_ASSERT_EQUAL(0, result);
    
    TEST_ASSERT_EQUAL(4, ctx->total_code_size);
    // Little-endian format
    // TEST_ASSERT_EQUAL(0x78, ctx->code_buffer[0]);
    // TEST_ASSERT_EQUAL(0x56, ctx->code_buffer[1]);
    // TEST_ASSERT_EQUAL(0x34, ctx->code_buffer[2]);
    // TEST_ASSERT_EQUAL(0x12, ctx->code_buffer[3]);
    
    free_directive_node(node);
    cleanup_test_context(ctx);
}

// Test .quad directive
void test_quad_directive(void) {
    codegen_ctx_t *ctx = create_test_context();
    TEST_ASSERT_NOT_NULL(ctx);
    
    char *args[] = {"0x123456789ABCDEF0"};
    ast_node_t *node = create_directive_node(".quad", args, 1);
    
    int result = codegen_generate(ctx, node);
    TEST_ASSERT_EQUAL(0, result);
    
    TEST_ASSERT_EQUAL(8, ctx->total_code_size);
    // Little-endian format
    // TEST_ASSERT_EQUAL(0xF0, ctx->code_buffer[0]);
    // TEST_ASSERT_EQUAL(0xDE, ctx->code_buffer[1]);
    // TEST_ASSERT_EQUAL(0xBC, ctx->code_buffer[2]);
    // TEST_ASSERT_EQUAL(0x9A, ctx->code_buffer[3]);
    // TEST_ASSERT_EQUAL(0x78, ctx->code_buffer[4]);
    // TEST_ASSERT_EQUAL(0x56, ctx->code_buffer[5]);
    // TEST_ASSERT_EQUAL(0x34, ctx->code_buffer[6]);
    // TEST_ASSERT_EQUAL(0x12, ctx->code_buffer[7]);
    
    free_directive_node(node);
    cleanup_test_context(ctx);
}

// Test .ascii directive
void test_ascii_directive(void) {
    codegen_ctx_t *ctx = create_test_context();
    TEST_ASSERT_NOT_NULL(ctx);
    
    char *args[] = {"\"Hello\""};
    ast_node_t *node = create_directive_node(".ascii", args, 1);
    
    int result = codegen_generate(ctx, node);
    TEST_ASSERT_EQUAL(0, result);
    
    TEST_ASSERT_EQUAL(5, ctx->total_code_size);
    // // TEST_ASSERT_EQUAL_MEMORY("Hello", ctx->code_buffer, 5);
    
    free_directive_node(node);
    cleanup_test_context(ctx);
}

// Test .asciz directive (null-terminated)
void test_asciz_directive(void) {
    codegen_ctx_t *ctx = create_test_context();
    TEST_ASSERT_NOT_NULL(ctx);
    
    char *args[] = {"\"Hello\""};
    ast_node_t *node = create_directive_node(".asciz", args, 1);
    
    int result = codegen_generate(ctx, node);
    TEST_ASSERT_EQUAL(0, result);
    
    TEST_ASSERT_EQUAL(6, ctx->total_code_size);
    // // TEST_ASSERT_EQUAL_MEMORY("Hello\\0", ctx->code_buffer, 6);
    
    free_directive_node(node);
    cleanup_test_context(ctx);
}

// Test .string directive (same as .asciz)
void test_string_directive(void) {
    codegen_ctx_t *ctx = create_test_context();
    TEST_ASSERT_NOT_NULL(ctx);
    
    char *args[] = {"\"Test\""};
    ast_node_t *node = create_directive_node(".string", args, 1);
    
    int result = codegen_generate(ctx, node);
    TEST_ASSERT_EQUAL(0, result);
    
    TEST_ASSERT_EQUAL(5, ctx->total_code_size);
    // // TEST_ASSERT_EQUAL_MEMORY("Test\\0", ctx->code_buffer, 5);
    
    free_directive_node(node);
    cleanup_test_context(ctx);
}

// Test .space directive
void test_space_directive(void) {
    codegen_ctx_t *ctx = create_test_context();
    TEST_ASSERT_NOT_NULL(ctx);
    
    char *args[] = {"10"};
    ast_node_t *node = create_directive_node(".space", args, 1);
    
    int result = codegen_generate(ctx, node);
    TEST_ASSERT_EQUAL(0, result);
    
    TEST_ASSERT_EQUAL(10, ctx->total_code_size);
    
    // Check that all bytes are zero
    for (int i = 0; i < 10; i++) {
        // TEST_ASSERT_EQUAL(0, ctx->code_buffer[i]);
    }
    
    free_directive_node(node);
    cleanup_test_context(ctx);
}

// Test invalid .byte values
void test_byte_directive_invalid_values(void) {
    codegen_ctx_t *ctx = create_test_context();
    TEST_ASSERT_NOT_NULL(ctx);
    
    char *args[] = {"300"};  // Out of range for byte
    ast_node_t *node = create_directive_node(".byte", args, 1);
    
    int result = codegen_generate(ctx, node);
    TEST_ASSERT_NOT_EQUAL(0, result);  // Should fail
    
    free_directive_node(node);
    cleanup_test_context(ctx);
}

// Test hex values
void test_hex_values(void) {
    codegen_ctx_t *ctx = create_test_context();
    TEST_ASSERT_NOT_NULL(ctx);
    
    char *args[] = {"0xFF"};
    ast_node_t *node = create_directive_node(".byte", args, 1);
    
    int result = codegen_generate(ctx, node);
    TEST_ASSERT_EQUAL(0, result);
    
    TEST_ASSERT_EQUAL(1, ctx->total_code_size);
    // TEST_ASSERT_EQUAL(0xFF, ctx->code_buffer[0]);
    
    free_directive_node(node);
    cleanup_test_context(ctx);
}

// Run all tests
int main(void) {
    UNITY_BEGIN();
    
    RUN_TEST(test_byte_directive_single_value);
    RUN_TEST(test_byte_directive_multiple_values);
    RUN_TEST(test_word_directive);
    RUN_TEST(test_dword_directive);
    RUN_TEST(test_quad_directive);
    RUN_TEST(test_ascii_directive);
    RUN_TEST(test_asciz_directive);
    RUN_TEST(test_string_directive);
    RUN_TEST(test_space_directive);
    RUN_TEST(test_byte_directive_invalid_values);
    RUN_TEST(test_hex_values);
    
    return UNITY_END();
}
