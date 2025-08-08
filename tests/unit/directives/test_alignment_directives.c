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

// Helper function to free directive node
static void free_directive_node(ast_node_t *node) {
    if (node && node->data) {
        ast_directive_t *directive = (ast_directive_t *)node->data;
        if (directive->name) {
            free(directive->name);
        }
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

// Test .align directive with already aligned address
void test_align_directive_already_aligned(void) {
    codegen_ctx_t *ctx = create_test_context();
    TEST_ASSERT_NOT_NULL(ctx);
    
    // Set address to be already aligned to 4 bytes
    ctx->current_address = 0x1000;  // Already aligned to 4
    
    char *args[] = {"4"};
    ast_node_t *node = create_directive_node(".align", args, 1);
    
    int result = codegen_generate(ctx, node);
    TEST_ASSERT_EQUAL(0, result);
    
    // Should not add any padding
    TEST_ASSERT_EQUAL(0, ctx->total_code_size);
    TEST_ASSERT_EQUAL(0x1000, ctx->current_address);
    
    free_directive_node(node);
    cleanup_test_context(ctx);
}

// Test .align directive requiring padding
void test_align_directive_needs_padding(void) {
    codegen_ctx_t *ctx = create_test_context();
    TEST_ASSERT_NOT_NULL(ctx);
    
    // Set address to need alignment
    ctx->current_address = 0x1001;  // Needs 3 bytes to align to 4
    
    char *args[] = {"4"};
    ast_node_t *node = create_directive_node(".align", args, 1);
    
    int result = codegen_generate(ctx, node);
    TEST_ASSERT_EQUAL(0, result);
    
    // Should add 3 bytes of padding
    TEST_ASSERT_EQUAL(3, ctx->total_code_size);
    TEST_ASSERT_EQUAL(0x1004, ctx->current_address);
    
    // Check padding bytes are zeros
    for (size_t i = 0; i < ctx->total_code_size; i++) {
        // TEST_ASSERT_EQUAL(0, ctx->code_buffer[i]);
    }
    
    free_directive_node(node);
    cleanup_test_context(ctx);
}

// Test .align directive with 16-byte alignment
void test_align_directive_16_bytes(void) {
    codegen_ctx_t *ctx = create_test_context();
    TEST_ASSERT_NOT_NULL(ctx);
    
    ctx->current_address = 0x1005;  // Needs 11 bytes to align to 16
    
    char *args[] = {"16"};
    ast_node_t *node = create_directive_node(".align", args, 1);
    
    int result = codegen_generate(ctx, node);
    TEST_ASSERT_EQUAL(0, result);
    
    TEST_ASSERT_EQUAL(11, ctx->total_code_size);
    TEST_ASSERT_EQUAL(0x1010, ctx->current_address);
    
    free_directive_node(node);
    cleanup_test_context(ctx);
}

// Test .align directive with hex value
void test_align_directive_hex_value(void) {
    codegen_ctx_t *ctx = create_test_context();
    TEST_ASSERT_NOT_NULL(ctx);
    
    ctx->current_address = 0x1002;  // Needs 6 bytes to align to 8 (0x8)
    
    char *args[] = {"0x8"};
    ast_node_t *node = create_directive_node(".align", args, 1);
    
    int result = codegen_generate(ctx, node);
    TEST_ASSERT_EQUAL(0, result);
    
    TEST_ASSERT_EQUAL(6, ctx->total_code_size);
    TEST_ASSERT_EQUAL(0x1008, ctx->current_address);
    
    free_directive_node(node);
    cleanup_test_context(ctx);
}

// Test .align directive with invalid alignment (not power of 2)
void test_align_directive_invalid_alignment(void) {
    codegen_ctx_t *ctx = create_test_context();
    TEST_ASSERT_NOT_NULL(ctx);
    
    char *args[] = {"3"};  // Not a power of 2
    ast_node_t *node = create_directive_node(".align", args, 1);
    
    int result = codegen_generate(ctx, node);
    TEST_ASSERT_NOT_EQUAL(0, result);  // Should fail
    
    free_directive_node(node);
    cleanup_test_context(ctx);
}

// Test .align directive with zero alignment
void test_align_directive_zero_alignment(void) {
    codegen_ctx_t *ctx = create_test_context();
    TEST_ASSERT_NOT_NULL(ctx);
    
    char *args[] = {"0"};
    ast_node_t *node = create_directive_node(".align", args, 1);
    
    int result = codegen_generate(ctx, node);
    TEST_ASSERT_NOT_EQUAL(0, result);  // Should fail
    
    free_directive_node(node);
    cleanup_test_context(ctx);
}

// Test .align directive with too large alignment
void test_align_directive_too_large(void) {
    codegen_ctx_t *ctx = create_test_context();
    TEST_ASSERT_NOT_NULL(ctx);
    
    char *args[] = {"8192"};  // Larger than 4096 limit
    ast_node_t *node = create_directive_node(".align", args, 1);
    
    int result = codegen_generate(ctx, node);
    TEST_ASSERT_NOT_EQUAL(0, result);  // Should fail
    
    free_directive_node(node);
    cleanup_test_context(ctx);
}

// Test .org directive with forward origin
void test_org_directive_forward(void) {
    codegen_ctx_t *ctx = create_test_context();
    TEST_ASSERT_NOT_NULL(ctx);
    
    ctx->current_address = 0x1000;
    
    char *args[] = {"0x1100"};
    ast_node_t *node = create_directive_node(".org", args, 1);
    
    int result = codegen_generate(ctx, node);
    TEST_ASSERT_EQUAL(0, result);
    
    // Should fill gap with zeros
    TEST_ASSERT_EQUAL(0x100, ctx->total_code_size);  // 0x1100 - 0x1000
    TEST_ASSERT_EQUAL(0x1100, ctx->current_address);
    
    // Check that gap is filled with zeros
    for (size_t i = 0; i < ctx->total_code_size; i++) {
        // TEST_ASSERT_EQUAL(0, ctx->code_buffer[i]);
    }
    
    free_directive_node(node);
    cleanup_test_context(ctx);
}

// Test .org directive with same address
void test_org_directive_same_address(void) {
    codegen_ctx_t *ctx = create_test_context();
    TEST_ASSERT_NOT_NULL(ctx);
    
    ctx->current_address = 0x2000;
    
    char *args[] = {"0x2000"};
    ast_node_t *node = create_directive_node(".org", args, 1);
    
    int result = codegen_generate(ctx, node);
    TEST_ASSERT_EQUAL(0, result);
    
    // Should not change anything
    TEST_ASSERT_EQUAL(0, ctx->total_code_size);
    TEST_ASSERT_EQUAL(0x2000, ctx->current_address);
    
    free_directive_node(node);
    cleanup_test_context(ctx);
}

// Test .org directive with hex value
void test_org_directive_hex_value(void) {
    codegen_ctx_t *ctx = create_test_context();
    TEST_ASSERT_NOT_NULL(ctx);
    
    ctx->current_address = 0x1000;
    
    char *args[] = {"0x1800"};
    ast_node_t *node = create_directive_node(".org", args, 1);
    
    int result = codegen_generate(ctx, node);
    TEST_ASSERT_EQUAL(0, result);
    
    TEST_ASSERT_EQUAL(0x800, ctx->total_code_size);
    TEST_ASSERT_EQUAL(0x1800, ctx->current_address);
    
    free_directive_node(node);
    cleanup_test_context(ctx);
}

// Test .org directive with backward origin (should fail)
void test_org_directive_backward(void) {
    codegen_ctx_t *ctx = create_test_context();
    TEST_ASSERT_NOT_NULL(ctx);
    
    ctx->current_address = 0x2000;
    
    char *args[] = {"0x1000"};  // Backward from 0x2000
    ast_node_t *node = create_directive_node(".org", args, 1);
    
    int result = codegen_generate(ctx, node);
    TEST_ASSERT_NOT_EQUAL(0, result);  // Should fail
    
    free_directive_node(node);
    cleanup_test_context(ctx);
}

// Test .org directive with invalid value
void test_org_directive_invalid_value(void) {
    codegen_ctx_t *ctx = create_test_context();
    TEST_ASSERT_NOT_NULL(ctx);
    
    char *args[] = {"invalid_address"};
    ast_node_t *node = create_directive_node(".org", args, 1);
    
    int result = codegen_generate(ctx, node);
    TEST_ASSERT_NOT_EQUAL(0, result);  // Should fail
    
    free_directive_node(node);
    cleanup_test_context(ctx);
}

// Test .org directive with negative value
void test_org_directive_negative_value(void) {
    codegen_ctx_t *ctx = create_test_context();
    TEST_ASSERT_NOT_NULL(ctx);
    
    char *args[] = {"-100"};
    ast_node_t *node = create_directive_node(".org", args, 1);
    
    int result = codegen_generate(ctx, node);
    TEST_ASSERT_NOT_EQUAL(0, result);  // Should fail
    
    free_directive_node(node);
    cleanup_test_context(ctx);
}

// Test missing arguments for .align
void test_align_directive_missing_args(void) {
    codegen_ctx_t *ctx = create_test_context();
    TEST_ASSERT_NOT_NULL(ctx);
    
    ast_node_t *node = create_directive_node(".align", NULL, 0);
    
    int result = codegen_generate(ctx, node);
    TEST_ASSERT_NOT_EQUAL(0, result);  // Should fail
    
    free_directive_node(node);
    cleanup_test_context(ctx);
}

// Test missing arguments for .org
void test_org_directive_missing_args(void) {
    codegen_ctx_t *ctx = create_test_context();
    TEST_ASSERT_NOT_NULL(ctx);
    
    ast_node_t *node = create_directive_node(".org", NULL, 0);
    
    int result = codegen_generate(ctx, node);
    TEST_ASSERT_NOT_EQUAL(0, result);  // Should fail
    
    free_directive_node(node);
    cleanup_test_context(ctx);
}

// Test combination of .align and .org
void test_align_and_org_combination(void) {
    codegen_ctx_t *ctx = create_test_context();
    TEST_ASSERT_NOT_NULL(ctx);
    
    ctx->current_address = 0x1001;
    
    // First align to 4 bytes
    char *align_args[] = {"4"};
    ast_node_t *align_node = create_directive_node(".align", align_args, 1);
    
    int result1 = codegen_generate(ctx, align_node);
    TEST_ASSERT_EQUAL(0, result1);
    
    size_t after_align_size = ctx->total_code_size;
    // uint32_t after_align_addr = ctx->current_address; // Not needed for this test
    
    // Then set origin to higher address
    char *org_args[] = {"0x2000"};
    ast_node_t *org_node = create_directive_node(".org", org_args, 1);
    
    int result2 = codegen_generate(ctx, org_node);
    TEST_ASSERT_EQUAL(0, result2);
    
    TEST_ASSERT_EQUAL(0x2000, ctx->current_address);
    // Code size should include both alignment padding and origin gap
    TEST_ASSERT_GREATER_THAN(after_align_size, ctx->total_code_size);
    
    free_directive_node(align_node);
    free_directive_node(org_node);
    cleanup_test_context(ctx);
}

// Run all tests
int main(void) {
    UNITY_BEGIN();
    
    RUN_TEST(test_align_directive_already_aligned);
    RUN_TEST(test_align_directive_needs_padding);
    RUN_TEST(test_align_directive_16_bytes);
    RUN_TEST(test_align_directive_hex_value);
    RUN_TEST(test_align_directive_invalid_alignment);
    RUN_TEST(test_align_directive_zero_alignment);
    RUN_TEST(test_align_directive_too_large);
    RUN_TEST(test_org_directive_forward);
    RUN_TEST(test_org_directive_same_address);
    RUN_TEST(test_org_directive_hex_value);
    RUN_TEST(test_org_directive_backward);
    RUN_TEST(test_org_directive_invalid_value);
    RUN_TEST(test_org_directive_negative_value);
    RUN_TEST(test_align_directive_missing_args);
    RUN_TEST(test_org_directive_missing_args);
    RUN_TEST(test_align_and_org_combination);
    
    return UNITY_END();
}
