/*
 * Phase 3: Symbol Table Enhancement - Comprehensive Symbol Tests
 * Tests all advanced symbol table features including hash table optimization
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <stdbool.h>
#include <assert.h>
#include <time.h>

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
static test_result_t test_hash_table_optimization(void);
static test_result_t test_symbol_type_resolution(void);
static test_result_t test_large_symbol_table_performance(void);
static void print_test_result(const test_result_t *result);

// Test implementation
static test_result_t test_hash_table_optimization(void) {
    test_result_t result = {0};
    result.test_name = "Hash Table Optimization";
    
    // Initialize symbol table
    symbol_table_t *table = symbol_table_create(16);
    if (!table) {
        result.passed = false;
        result.error_message = "Failed to create symbol table";
        return result;
    }
    
    // Add symbols using hashed method
    char symbol_names[10][32];
    for (int i = 0; i < 10; i++) {
        snprintf(symbol_names[i], sizeof(symbol_names[i]), "hash_symbol_%d", i);
        symbol_t *sym = symbol_create(symbol_names[i], SYMBOL_LABEL);
        symbol_set_value(sym, 0x1000 + i * 0x10);
        symbol_mark_defined(sym);
        symbol_table_add_hashed(table, sym);
    }
    
    // Test lookup using hashed method
    int found_symbols = 0;
    for (int i = 0; i < 10; i++) {
        symbol_t *sym = symbol_table_lookup_hashed(table, symbol_names[i]);
        if (sym && sym->value == (uint64_t)(0x1000 + i * 0x10)) {
            found_symbols++;
        }
    }
    
    result.expected_result = 10;
    result.actual_result = found_symbols;
    result.passed = (result.actual_result == result.expected_result);
    
    if (!result.passed) {
        result.error_message = "Hash table lookup failed";
    }
    
    symbol_table_destroy(table);
    return result;
}

static test_result_t test_symbol_type_resolution(void) {
    test_result_t result = {0};
    result.test_name = "Symbol Type Resolution";
    
    // Initialize symbol table
    symbol_table_t *table = symbol_table_create(16);
    if (!table) {
        result.passed = false;
        result.error_message = "Failed to create symbol table";
        return result;
    }
    
    // Add symbols of different types
    symbol_t *label_sym = symbol_create("code_label", SYMBOL_LABEL);
    symbol_set_value(label_sym, 0x1000);
    symbol_mark_defined(label_sym);
    symbol_table_add(table, label_sym);
    
    symbol_t *const_sym = symbol_create("data_const", SYMBOL_CONSTANT);
    symbol_set_value(const_sym, 0x42);
    symbol_mark_defined(const_sym);
    symbol_table_add(table, const_sym);
    
    symbol_t *reg_sym = symbol_create("register_ref", SYMBOL_VARIABLE);
    symbol_set_value(reg_sym, 0x0);
    symbol_mark_defined(reg_sym);
    symbol_table_add(table, reg_sym);
    
    // Test symbol resolution by type
    symbol_t *label_lookup = symbol_table_lookup(table, "code_label");
    symbol_t *const_lookup = symbol_table_lookup(table, "data_const");
    symbol_t *reg_lookup = symbol_table_lookup(table, "register_ref");
    
    if (!label_lookup || !const_lookup || !reg_lookup) {
        result.passed = false;
        result.error_message = "Failed to find symbols by type";
        symbol_table_destroy(table);
        return result;
    }
    
    // Verify types and values
    bool types_correct = (label_lookup->type == SYMBOL_LABEL) &&
                        (const_lookup->type == SYMBOL_CONSTANT) &&
                        (reg_lookup->type == SYMBOL_VARIABLE);
    
    bool values_correct = (label_lookup->value == 0x1000) &&
                         (const_lookup->value == 0x42) &&
                         (reg_lookup->value == 0x0);
    
    result.expected_result = 1;
    result.actual_result = (types_correct && values_correct) ? 1 : 0;
    result.passed = (result.actual_result == result.expected_result);
    
    if (!result.passed) {
        result.error_message = "Symbol type or value verification failed";
    }
    
    symbol_table_destroy(table);
    return result;
}

static test_result_t test_large_symbol_table_performance(void) {
    test_result_t result = {0};
    result.test_name = "Large Symbol Table Performance";
    
    // Initialize symbol table
    symbol_table_t *table = symbol_table_create(1024); // Larger initial size for performance test
    if (!table) {
        result.passed = false;
        result.error_message = "Failed to create symbol table";
        return result;
    }
    
    const int num_symbols = 1000;
    char symbol_names[1000][32];
    
    // Add many symbols to test performance
    clock_t start = clock();
    for (int i = 0; i < num_symbols; i++) {
        snprintf(symbol_names[i], sizeof(symbol_names[i]), "perf_symbol_%d", i);
        symbol_t *sym = symbol_create(symbol_names[i], SYMBOL_LABEL);
        symbol_set_value(sym, 0x10000 + i);
        symbol_mark_defined(sym);
        symbol_table_add(table, sym);
    }
    clock_t add_time = clock() - start;
    
    // Test lookup performance
    start = clock();
    int successful_lookups = 0;
    for (int i = 0; i < num_symbols; i++) {
        symbol_t *sym = symbol_table_lookup(table, symbol_names[i]);
        if (sym && sym->value == (uint64_t)(0x10000 + i)) {
            successful_lookups++;
        }
    }
    clock_t lookup_time = clock() - start;
    
    // Test forward reference resolution with many symbols
    for (int i = 0; i < 100; i++) {
        char forward_name[32];
        snprintf(forward_name, sizeof(forward_name), "forward_%d", i);
        symbol_add_forward_reference(table, forward_name, 0x20000 + i);
        symbol_t *sym = symbol_create(forward_name, SYMBOL_LABEL);
        symbol_set_value(sym, 0x20000 + i);
        symbol_mark_defined(sym);
        symbol_table_add(table, sym);
    }
    
    start = clock();
    symbol_resolve_all_forward_references(table);
    clock_t resolve_time = clock() - start;
    
    // Check if all operations completed successfully
    result.expected_result = num_symbols;
    result.actual_result = successful_lookups;
    result.passed = (result.actual_result == result.expected_result);
    
    if (!result.passed) {
        result.error_message = "Performance test failed - not all symbols found";
    }
    
    // Print performance metrics
    printf("Performance metrics:\n");
    printf("  Add %d symbols: %ld ms\n", num_symbols, add_time * 1000 / CLOCKS_PER_SEC);
    printf("  Lookup %d symbols: %ld ms\n", num_symbols, lookup_time * 1000 / CLOCKS_PER_SEC);
    printf("  Resolve 100 forward refs: %ld ms\n", resolve_time * 1000 / CLOCKS_PER_SEC);
    
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

int main(void) {
    printf("=== Phase 3: Symbol Table Enhancement - Comprehensive Symbol Tests ===\n\n");
    
    test_result_t results[3];
    int total_tests = 3;
    int passed_tests = 0;
    
    // Run tests
    results[0] = test_hash_table_optimization();
    results[1] = test_symbol_type_resolution();
    results[2] = test_large_symbol_table_performance();
    
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
