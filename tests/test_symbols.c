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
    symbol_table_t *table = symbol_table_create(16);
    
    TEST_ASSERT_NOT_NULL(table);
    TEST_ASSERT_NOT_NULL(table->buckets);
    TEST_ASSERT_EQUAL_INT(0, table->symbol_count);
    TEST_ASSERT_EQUAL_INT(16, table->bucket_count);
    
    symbol_table_destroy(table);
}

void test_symbol_creation(void) {
    symbol_t *symbol = symbol_create("test_label", SYMBOL_LABEL);
    
    TEST_ASSERT_NOT_NULL(symbol);
    TEST_ASSERT_EQUAL_STRING("test_label", symbol->name);
    TEST_ASSERT_EQUAL_INT(SYMBOL_LABEL, symbol->type);
    TEST_ASSERT_FALSE(symbol->defined);
    TEST_ASSERT_EQUAL_UINT64(0, symbol->value);  // Should default to 0
    
    symbol_destroy(symbol);
}

void test_symbol_table_insert_and_lookup(void) {
    symbol_table_t *table = symbol_table_create(16);
    
    // Create and add a symbol
    symbol_t *symbol = symbol_create("main", SYMBOL_LABEL);
    symbol_set_value(symbol, 0x2000);
    
    int result = symbol_table_add(table, symbol);
    TEST_ASSERT_EQUAL_INT(0, result);
    TEST_ASSERT_EQUAL_INT(1, table->symbol_count);
    
    // Look up the symbol
    symbol_t *found = symbol_table_lookup(table, "main");
    TEST_ASSERT_NOT_NULL(found);
    TEST_ASSERT_EQUAL_STRING("main", found->name);
    TEST_ASSERT_EQUAL_UINT64(0x2000, found->value);
    
    // Try to find non-existent symbol
    symbol_t *not_found = symbol_table_lookup(table, "nonexistent");
    TEST_ASSERT_NULL(not_found);
    
    symbol_table_destroy(table);
}

void test_symbol_table_hash_distribution(void) {
    symbol_table_t *table = symbol_table_create(16);
    
    // Insert multiple symbols
    const char *symbol_names[] = {"main", "start", "loop", "end", "data"};
    int symbol_count = sizeof(symbol_names) / sizeof(symbol_names[0]);
    
    for (int i = 0; i < symbol_count; i++) {
        symbol_t *symbol = symbol_create(symbol_names[i], SYMBOL_LABEL);
        symbol_set_value(symbol, i * 0x100);
        int result = symbol_table_add(table, symbol);
        TEST_ASSERT_EQUAL_INT(0, result);
    }
    
    TEST_ASSERT_EQUAL_INT(symbol_count, table->symbol_count);
    
    // Verify all symbols can be found
    for (int i = 0; i < symbol_count; i++) {
        symbol_t *found = symbol_table_lookup(table, symbol_names[i]);
        TEST_ASSERT_NOT_NULL(found);
        TEST_ASSERT_EQUAL_STRING(symbol_names[i], found->name);
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
