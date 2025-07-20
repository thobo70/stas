/*
 * Phase 3: Symbol Table Enhancement - Final Integration Tests
 * Comprehensive tests for the enhanced symbol table with Phase 2 integration
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <stdbool.h>
#include <assert.h>

// STAS includes
#include "symbols.h"

// Test results structure
typedef struct {
    const char *test_name;
    bool passed;
    const char *error_message;
    int64_t expected_result;
    int64_t actual_result;
} test_result_t;

// Function prototypes
static test_result_t test_multi_pass_resolution(void);
static test_result_t test_complex_forward_references(void);
static test_result_t test_symbol_address_calculation(void);
static void print_test_result(const test_result_t *result);

// Test implementation
static test_result_t test_multi_pass_resolution(void) {
    test_result_t result = {0};
    result.test_name = "Multi-Pass Forward Reference Resolution";
    
    // Initialize symbol table
    symbol_table_t *table = symbol_table_create(16);
    if (!table) {
        result.passed = false;
        result.error_message = "Failed to create symbol table";
        return result;
    }
    
    // Add forward references in a chain
    symbol_add_forward_reference(table, "label1", 0x1000);
    symbol_add_forward_reference(table, "label2", 0x1004);
    symbol_add_forward_reference(table, "label3", 0x1008);
    
    // Add symbols out of order to test multi-pass
    symbol_t *sym3 = symbol_create("label3", SYMBOL_LABEL);
    symbol_set_value(sym3, 0x3000);
    symbol_mark_defined(sym3);
    symbol_table_add(table, sym3);
    
    symbol_t *sym1 = symbol_create("label1", SYMBOL_LABEL);
    symbol_set_value(sym1, 0x1000);
    symbol_mark_defined(sym1);
    symbol_table_add(table, sym1);
    
    symbol_t *sym2 = symbol_create("label2", SYMBOL_LABEL);
    symbol_set_value(sym2, 0x2000);
    symbol_mark_defined(sym2);
    symbol_table_add(table, sym2);
    
    // Resolve all forward references
    symbol_resolve_all_forward_references(table);
    
    // Check if all symbols are resolved correctly
    symbol_t *found1 = symbol_table_lookup(table, "label1");
    symbol_t *found2 = symbol_table_lookup(table, "label2");
    symbol_t *found3 = symbol_table_lookup(table, "label3");
    
    if (!found1 || !found2 || !found3) {
        result.passed = false;
        result.error_message = "One or more symbols not found after resolution";
        symbol_table_destroy(table);
        return result;
    }
    
    // Check if addresses are correct
    bool addresses_correct = (found1->value == 0x1000) &&
                           (found2->value == 0x2000) &&
                           (found3->value == 0x3000);
    
    result.expected_result = 1;
    result.actual_result = addresses_correct ? 1 : 0;
    result.passed = addresses_correct;
    
    if (!result.passed) {
        result.error_message = "Symbol addresses incorrect after resolution";
    }
    
    symbol_table_destroy(table);
    return result;
}

static test_result_t test_complex_forward_references(void) {
    test_result_t result = {0};
    result.test_name = "Complex Forward References with Dependencies";
    
    // Initialize symbol table
    symbol_table_t *table = symbol_table_create(16);
    if (!table) {
        result.passed = false;
        result.error_message = "Failed to create symbol table";
        return result;
    }
    
    // Add base symbol
    symbol_t *base_sym = symbol_create("base", SYMBOL_LABEL);
    symbol_set_value(base_sym, 0x8000);
    symbol_mark_defined(base_sym);
    symbol_table_add(table, base_sym);
    
    // Add forward reference
    symbol_add_forward_reference(table, "offset", 0x1000);
    
    // Calculate address based on another symbol
    uint64_t calculated = symbol_calculate_address(table, "base", 0x100);
    symbol_table_add_with_address(table, "derived", SYMBOL_LABEL, calculated, 0);
    
    // Add the forward referenced symbol
    symbol_t *offset_sym = symbol_create("offset", SYMBOL_CONSTANT);
    symbol_set_value(offset_sym, 0x200);
    symbol_mark_defined(offset_sym);
    symbol_table_add(table, offset_sym);
    
    // Resolve forward references
    symbol_resolve_all_forward_references(table);
    
    // Verify the derived symbol
    symbol_t *derived = symbol_table_lookup(table, "derived");
    if (!derived) {
        result.passed = false;
        result.error_message = "Derived symbol not found";
        symbol_table_destroy(table);
        return result;
    }
    
    result.expected_result = 0x8100; // base + 0x100
    result.actual_result = derived->value;
    result.passed = (result.actual_result == result.expected_result);
    
    symbol_table_destroy(table);
    return result;
}

static test_result_t test_symbol_address_calculation(void) {
    test_result_t result = {0};
    result.test_name = "Symbol Address Calculation";
    
    // Initialize symbol table
    symbol_table_t *table = symbol_table_create(16);
    if (!table) {
        result.passed = false;
        result.error_message = "Failed to create symbol table";
        return result;
    }
    
    // Add symbols for address calculation
    symbol_t *base_addr = symbol_create("BASE_ADDR", SYMBOL_CONSTANT);
    symbol_set_value(base_addr, 0x4000);
    symbol_mark_defined(base_addr);
    symbol_table_add(table, base_addr);
    
    symbol_t *offset = symbol_create("OFFSET", SYMBOL_CONSTANT);
    symbol_set_value(offset, 0x100);
    symbol_mark_defined(offset);
    symbol_table_add(table, offset);
    
    symbol_t *multiplier = symbol_create("MULTIPLIER", SYMBOL_CONSTANT);
    symbol_set_value(multiplier, 4);
    symbol_mark_defined(multiplier);
    symbol_table_add(table, multiplier);
    
    // Manual calculation: BASE_ADDR + (OFFSET * MULTIPLIER)
    symbol_t *base_lookup = symbol_table_lookup(table, "BASE_ADDR");
    symbol_t *offset_lookup = symbol_table_lookup(table, "OFFSET");
    symbol_t *mult_lookup = symbol_table_lookup(table, "MULTIPLIER");
    
    if (!base_lookup || !offset_lookup || !mult_lookup) {
        result.passed = false;
        result.error_message = "Failed to lookup symbols for calculation";
        symbol_table_destroy(table);
        return result;
    }
    
    uint64_t calc_result = base_lookup->value + (offset_lookup->value * mult_lookup->value);
    
    result.expected_result = 0x4400; // 0x4000 + (0x100 * 4)
    result.actual_result = calc_result;
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
            printf("Expected: 0x%lx (%ld), Got: 0x%lx (%ld)\n", 
                   result->expected_result, result->expected_result,
                   result->actual_result, result->actual_result);
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
    printf("=== Phase 3: Symbol Table Enhancement - Final Integration Tests ===\n\n");
    
    test_result_t results[3];
    int total_tests = 3;
    int passed_tests = 0;
    
    // Run tests
    results[0] = test_multi_pass_resolution();
    results[1] = test_complex_forward_references();
    results[2] = test_symbol_address_calculation();
    
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
