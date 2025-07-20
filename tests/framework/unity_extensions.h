#ifndef UNITY_EXTENSIONS_H
#define UNITY_EXTENSIONS_H

#include "unity.h"
#include <stdint.h>
#include <stdbool.h>
#include <string.h>

// Function declarations (forward declare only what we need to avoid circular dependencies)
void cleanup_test_resources(void* symbol_table, void* temp_file, void* other_resource);
char* create_temp_test_file(const char* content, const char* suffix);
bool verify_test_file_content(const char* filename, const char* expected_content);
bool compare_binary_data(const uint8_t* data1, const uint8_t* data2, size_t size);
void print_hex_dump(const uint8_t* data, size_t size, const char* label);

// Custom Unity assertions for assembly testing

// Assert that two machine code bytes are equal with detailed output
#define TEST_ASSERT_EQUAL_MACHINE_CODE(expected, actual, size) \
    do { \
        if (!compare_binary_data((const uint8_t*)(expected), (const uint8_t*)(actual), (size))) { \
            print_hex_dump((const uint8_t*)(expected), (size), "Expected"); \
            print_hex_dump((const uint8_t*)(actual), (size), "Actual"); \
            TEST_FAIL_MESSAGE("Machine code mismatch"); \
        } \
    } while(0)

// Assert that a register encoding is correct
#define TEST_ASSERT_REGISTER_ENCODING(expected_id, actual_reg) \
    TEST_ASSERT_EQUAL_UINT32((expected_id), (actual_reg).id)

// Assert that an error message contains expected text
#define TEST_ASSERT_ERROR_CONTAINS(error_msg, expected_text) \
    TEST_ASSERT_NOT_NULL(error_msg); \
    TEST_ASSERT_NOT_NULL(strstr(error_msg, expected_text))

#endif // UNITY_EXTENSIONS_H
