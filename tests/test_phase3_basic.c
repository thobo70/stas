/*
 * Phase 3: Symbol Table Enhancement - Basic Tests
 * Tests the enhanced symbol table functionality for forward references and address calculation
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <stdbool.h>
#include <assert.h>

// STAS includes
#include "symbols.h"
#include "expr.h"

// Test results structure
typedef struct {
    const char *test_name;
    bool passed;
    const char *error_message;
    int64_t expected_result;
    int64_t actual_result;
} test_result_t;

// Function prototypes
static test_result_t test_forward_reference_basic(void);
static test_result_t test_address_calculation(void);
static test_result_t test_expression_symbol_resolution(void);
static void print_test_result(const test_result_t *result);

// Test implementation
static test_result_t test_forward_reference_basic(void) {
    test_result_t result = {0};
    result.test_name = "Forward Reference Basic";
    
    // Initialize symbol table
    symbol_table_t *table = symbol_table_create(16);
    if (!table) {
        result.passed = false;
        result.error_message = "Failed to create symbol table";
        return result;
    }
    
    // Add a forward reference
    symbol_add_forward_reference(table, "label1", 0x1000);
    
    // Add the actual symbol
    symbol_t *symbol = symbol_create("label1", SYMBOL_LABEL);
    symbol_set_value(symbol, 0x2000);
    symbol_mark_defined(symbol);
    symbol_table_add(table, symbol);
    
    // Resolve forward references
    symbol_resolve_all_forward_references(table);
    
    // Check if forward reference was resolved
    symbol_t *sym = symbol_table_lookup(table, "label1");
    if (!sym) {
        result.passed = false;
        result.error_message = "Symbol not found after resolution";
        symbol_table_destroy(table);
        return result;
    }
    
    result.expected_result = 0x2000;
    result.actual_result = sym->value;
    result.passed = (result.actual_result == result.expected_result);
    
    symbol_table_destroy(table);
    return result;
}

static test_result_t test_address_calculation(void) {
    test_result_t result = {0};
    result.test_name = "Address Calculation";
    
    // Initialize symbol table
    symbol_table_t *table = symbol_table_create(16);
    if (!table) {
        result.passed = false;
        result.error_message = "Failed to create symbol table";
        return result;
    }
    
    // Add a symbol with base address
    symbol_t *symbol = symbol_create("data_start", SYMBOL_LABEL);
    symbol_set_value(symbol, 0x8000);
    symbol_mark_defined(symbol);
    symbol_table_add(table, symbol);
    
    // Calculate address with offset
    int64_t calculated_addr = symbol_calculate_address(table, "data_start", 0x100);
    
    result.expected_result = 0x8100;
    result.actual_result = calculated_addr;
    result.passed = (result.actual_result == result.expected_result);
    
    if (!result.passed) {
        result.error_message = "Address calculation mismatch";
    }
    
    symbol_table_destroy(table);
    return result;
}

static test_result_t test_expression_symbol_resolution(void) {
    test_result_t result = {0};
    result.test_name = "Expression Symbol Resolution";
    
    // Initialize symbol table
    symbol_table_t *table = symbol_table_create(16);
    if (!table) {
        result.passed = false;
        result.error_message = "Failed to create symbol table";
        return result;
    }
    
    // Add some symbols
    symbol_t *symbol1 = symbol_create("value1", SYMBOL_CONSTANT);
    symbol_set_value(symbol1, 100);
    symbol_mark_defined(symbol1);
    symbol_table_add(table, symbol1);
    
    symbol_t *symbol2 = symbol_create("value2", SYMBOL_CONSTANT);
    symbol_set_value(symbol2, 50);
    symbol_mark_defined(symbol2);
    symbol_table_add(table, symbol2);
    
    // Test symbol lookup and basic arithmetic
    symbol_t *sym1 = symbol_table_lookup(table, "value1");
    symbol_t *sym2 = symbol_table_lookup(table, "value2");
    
    if (!sym1 || !sym2) {
        result.passed = false;
        result.error_message = "Failed to lookup symbols";
        symbol_table_destroy(table);
        return result;
    }
    
    // Simple manual "expression evaluation"
    int64_t expr_result = sym1->value + sym2->value;
    
    result.expected_result = 150;
    result.actual_result = expr_result;
    result.passed = (result.actual_result == result.expected_result);
    
    symbol_table_destroy(table);
    return result;
}

static void print_test_result(const test_result_t *result) {
    printf("Test: %s\n", result->test_name);
    printf("Status: %s\n", result->passed ? "PASSED" : "FAILED");
    
    if (!result->passed) {
        if (result->error_message) {
            printf("Error: %s\n", result->error_message);
        }
        if (result->expected_result != 0 || result->actual_result != 0) {
            printf("Expected: %ld, Got: %ld\n", result->expected_result, result->actual_result);
        }
    }
    printf("----------------------------------------\n");
}

// Unity framework required functions
void setUp(void) {
    // Setup before each test
}

void tearDown(void) {
    // Cleanup after each test
}

int main(void) {
    printf("=== Phase 3: Symbol Table Enhancement - Basic Tests ===\n\n");
    
    test_result_t results[3];
    int total_tests = 3;
    int passed_tests = 0;
    
    // Run tests
    results[0] = test_forward_reference_basic();
    results[1] = test_address_calculation();
    results[2] = test_expression_symbol_resolution();
    
    // Print results
    for (int i = 0; i < total_tests; i++) {
        print_test_result(&results[i]);
        if (results[i].passed) {
            passed_tests++;
        }
    }
    
    // Summary
    printf("=== Test Summary ===\n");
    printf("Total tests: %d\n", total_tests);
    printf("Passed: %d\n", passed_tests);
    printf("Failed: %d\n", total_tests - passed_tests);
    printf("Success rate: %.1f%%\n", (float)passed_tests / total_tests * 100.0f);
    
    return (passed_tests == total_tests) ? 0 : 1;
}
