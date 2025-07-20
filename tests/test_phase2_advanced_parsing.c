/*
 * Phase 2: Advanced Parsing Test
 * Tests the enhanced expression evaluation and operand parsing capabilities
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <stdbool.h>
#include <assert.h>

// STAS includes
#include "parser.h"
#include "lexer.h"
#include "expr.h"
#include "../src/arch/x86_16/x86_16.h"
#include "arch_interface.h"

// Test configuration
#define MAX_INPUT_SIZE 1024

// Test results structure
typedef struct {
    const char *test_name;
    bool passed;
    const char *error_message;
    int64_t expected_result;
    int64_t actual_result;
} test_result_t;

// Function prototypes
static test_result_t test_expression_evaluation(void);
static test_result_t test_arithmetic_expressions(void);
static test_result_t test_bitwise_expressions(void);
static test_result_t test_symbol_resolution(void);
static test_result_t test_forward_references(void);
static test_result_t test_immediate_expressions(void);
static void print_test_result(const test_result_t *result);
static test_result_t create_test_result(const char *name, bool passed, const char *error);
static int64_t parse_and_evaluate_expression(const char *input);

// Unity framework required functions
void setUp(void) {
    // Setup before each test
}

void tearDown(void) {
    // Cleanup after each test
}

int main(void) {
    printf("=== STAS Phase 2: Advanced Parsing Test Suite ===\n\n");
    
    // Initialize x86_16 architecture for testing
    arch_ops_t *arch = get_arch_ops_x86_16();
    if (!arch || !arch->init || arch->init() != 0) {
        printf("ERROR: Failed to initialize x86_16 architecture\n");
        return 1;
    }
    
    printf("x86_16 architecture initialized successfully\n\n");
    
    // Run tests
    test_result_t tests[] = {
        test_expression_evaluation(),
        test_arithmetic_expressions(),
        test_bitwise_expressions(),
        test_symbol_resolution(),
        test_forward_references(),
        test_immediate_expressions()
    };
    
    size_t test_count = sizeof(tests) / sizeof(tests[0]);
    size_t passed_count = 0;
    
    // Print results
    printf("=== Test Results ===\n");
    for (size_t i = 0; i < test_count; i++) {
        print_test_result(&tests[i]);
        if (tests[i].passed) {
            passed_count++;
        }
    }
    
    printf("\n=== Summary ===\n");
    printf("Tests passed: %zu/%zu\n", passed_count, test_count);
    printf("Success rate: %.1f%%\n", (double)passed_count / test_count * 100.0);
    
    // Cleanup
    if (arch->cleanup) {
        arch->cleanup();
    }
    
    return (passed_count == test_count) ? 0 : 1;
}

// Test 1: Basic expression evaluation
static test_result_t test_expression_evaluation(void) {
    const char *test_name = "Expression evaluation";
    
    printf("Test: %s\n", test_name);
    
    // Test simple numbers
    int64_t result = parse_and_evaluate_expression("42");
    if (result != 42) {
        return create_test_result(test_name, false, "Simple number evaluation failed");
    }
    
    // Test hex numbers
    result = parse_and_evaluate_expression("0x10");
    if (result != 16) {
        return create_test_result(test_name, false, "Hex number evaluation failed");
    }
    
    // Test parentheses
    result = parse_and_evaluate_expression("(100)");
    if (result != 100) {
        return create_test_result(test_name, false, "Parentheses evaluation failed");
    }
    
    test_result_t success = create_test_result(test_name, true, NULL);
    success.expected_result = 42;
    success.actual_result = 42;
    return success;
}

// Test 2: Arithmetic expressions
static test_result_t test_arithmetic_expressions(void) {
    const char *test_name = "Arithmetic expressions";
    
    printf("Test: %s\n", test_name);
    
    // Test addition
    int64_t result = parse_and_evaluate_expression("10 + 5");
    if (result != 15) {
        return create_test_result(test_name, false, "Addition failed");
    }
    
    // Test subtraction
    result = parse_and_evaluate_expression("20 - 8");
    if (result != 12) {
        return create_test_result(test_name, false, "Subtraction failed");
    }
    
    // Test multiplication
    result = parse_and_evaluate_expression("6 * 7");
    if (result != 42) {
        return create_test_result(test_name, false, "Multiplication failed");
    }
    
    // Test division
    result = parse_and_evaluate_expression("84 / 2");
    if (result != 42) {
        return create_test_result(test_name, false, "Division failed");
    }
    
    // Test complex expression with precedence
    result = parse_and_evaluate_expression("2 + 3 * 4");
    if (result != 14) {
        return create_test_result(test_name, false, "Precedence failed");
    }
    
    test_result_t success = create_test_result(test_name, true, NULL);
    success.expected_result = 14;
    success.actual_result = 14;
    return success;
}

// Test 3: Bitwise expressions
static test_result_t test_bitwise_expressions(void) {
    const char *test_name = "Bitwise expressions";
    
    printf("Test: %s\n", test_name);
    
    // Test bitwise AND
    int64_t result = parse_and_evaluate_expression("0xFF & 0x0F");
    if (result != 0x0F) {
        return create_test_result(test_name, false, "Bitwise AND failed");
    }
    
    // Test bitwise OR
    result = parse_and_evaluate_expression("0xF0 | 0x0F");
    if (result != 0xFF) {
        return create_test_result(test_name, false, "Bitwise OR failed");
    }
    
    // Test bitwise XOR
    result = parse_and_evaluate_expression("0xFF ^ 0xF0");
    if (result != 0x0F) {
        return create_test_result(test_name, false, "Bitwise XOR failed");
    }
    
    test_result_t success = create_test_result(test_name, true, NULL);
    success.expected_result = 0x0F;
    success.actual_result = 0x0F;
    return success;
}

// Test 4: Symbol resolution
static test_result_t test_symbol_resolution(void) {
    const char *test_name = "Symbol resolution";
    
    printf("Test: %s\n", test_name);
    
    // Create a simple test with symbols
    const char *input = 
        "start:\n"
        "mov ax, start\n";
    
    lexer_t *lexer = lexer_create(input, "test_input");
    if (!lexer) {
        return create_test_result(test_name, false, "Failed to create lexer");
    }
    
    arch_ops_t *arch = get_arch_ops_x86_16();
    parser_t *parser = parser_create(lexer, arch);
    if (!parser) {
        lexer_destroy(lexer);
        return create_test_result(test_name, false, "Failed to create parser");
    }
    
    // Parse the input
    ast_node_t *ast = parser_parse(parser);
    if (!ast) {
        parser_destroy(parser);
        lexer_destroy(lexer);
        return create_test_result(test_name, false, "Failed to parse input");
    }
    
    // Check if symbols were added to the table
    symbol_t *start_symbol = symbol_table_lookup(parser->symbols, "start");
    bool symbol_found = (start_symbol != NULL);
    
    // Cleanup
    parser_destroy(parser);
    lexer_destroy(lexer);
    
    test_result_t result = create_test_result(test_name, symbol_found, 
                                            symbol_found ? NULL : "Symbol not found in table");
    result.expected_result = 1;
    result.actual_result = symbol_found ? 1 : 0;
    return result;
}

// Test 5: Forward references
static test_result_t test_forward_references(void) {
    const char *test_name = "Forward references";
    
    printf("Test: %s\n", test_name);
    
    // Create a test with forward reference
    const char *input = 
        "mov ax, end_label\n"
        "nop\n"
        "end_label:\n";
    
    lexer_t *lexer = lexer_create(input, "test_forward");
    if (!lexer) {
        return create_test_result(test_name, false, "Failed to create lexer");
    }
    
    arch_ops_t *arch = get_arch_ops_x86_16();
    parser_t *parser = parser_create(lexer, arch);
    if (!parser) {
        lexer_destroy(lexer);
        return create_test_result(test_name, false, "Failed to create parser");
    }
    
    // Parse the input
    ast_node_t *ast = parser_parse(parser);
    if (!ast) {
        parser_destroy(parser);
        lexer_destroy(lexer);
        return create_test_result(test_name, false, "Failed to parse input with forward reference");
    }
    
    // Check if forward reference was handled
    symbol_t *label_symbol = symbol_table_lookup(parser->symbols, "end_label");
    bool symbol_handled = (label_symbol != NULL);
    
    // Cleanup
    parser_destroy(parser);
    lexer_destroy(lexer);
    
    test_result_t result = create_test_result(test_name, symbol_handled, 
                                            symbol_handled ? NULL : "Forward reference not handled");
    result.expected_result = 1;
    result.actual_result = symbol_handled ? 1 : 0;
    return result;
}

// Test 6: Immediate expressions
static test_result_t test_immediate_expressions(void) {
    const char *test_name = "Immediate expressions";
    
    printf("Test: %s\n", test_name);
    
    // Create a test with complex immediate expression
    const char *input = "mov ax, $(10 + 5 * 2)\n";
    
    lexer_t *lexer = lexer_create(input, "test_immediate");
    if (!lexer) {
        return create_test_result(test_name, false, "Failed to create lexer");
    }
    
    arch_ops_t *arch = get_arch_ops_x86_16();
    parser_t *parser = parser_create(lexer, arch);
    if (!parser) {
        lexer_destroy(lexer);
        return create_test_result(test_name, false, "Failed to create parser");
    }
    
    // Parse the input
    ast_node_t *ast = parser_parse(parser);
    bool parse_success = (ast != NULL);
    
    // Cleanup
    parser_destroy(parser);
    lexer_destroy(lexer);
    
    test_result_t result = create_test_result(test_name, parse_success, 
                                            parse_success ? NULL : "Failed to parse immediate expression");
    result.expected_result = 1;
    result.actual_result = parse_success ? 1 : 0;
    return result;
}

// Helper function to parse and evaluate a simple expression
static int64_t parse_and_evaluate_expression(const char *input) {
    lexer_t *lexer = lexer_create(input, "test_expr");
    if (!lexer) return 0;
    
    arch_ops_t *arch = get_arch_ops_x86_16();
    parser_t *parser = parser_create(lexer, arch);
    if (!parser) {
        lexer_destroy(lexer);
        return 0;
    }
    
    token_t token = lexer_next_token(lexer); // Get first token
    parser->current_token = token;
    
    // Parse expression
    ast_node_t *expr = parse_expression(parser);
    int64_t result = 0;
    
    if (expr) {
        result = evaluate_expression_ast(parser, expr);
        ast_node_destroy(expr);
    }
    
    parser_destroy(parser);
    lexer_destroy(lexer);
    
    return result;
}

// Helper functions
static void print_test_result(const test_result_t *result) {
    printf("\n--- %s ---\n", result->test_name);
    printf("Status: %s\n", result->passed ? "PASSED" : "FAILED");
    
    if (result->passed) {
        printf("Expected: %ld, Actual: %ld\n", result->expected_result, result->actual_result);
    } else if (result->error_message) {
        printf("Error: %s\n", result->error_message);
    }
}

static test_result_t create_test_result(const char *name, bool passed, const char *error) {
    test_result_t result = {0};
    result.test_name = name;
    result.passed = passed;
    result.error_message = error;
    result.expected_result = 0;
    result.actual_result = 0;
    return result;
}
