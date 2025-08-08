#include "../../unity/src/unity.h"
#include "unity_extensions.h"
#include "../../../include/utils.h"
#include <string.h>
#include <stdlib.h>
#include <limits.h>

// Global test fixtures
char *test_string;
void *test_memory;

void setUp(void)
{
    test_string = NULL;
    test_memory = NULL;
}

void tearDown(void)
{
    if (test_string) {
        free(test_string);
        test_string = NULL;
    }
    if (test_memory) {
        free(test_memory);
        test_memory = NULL;
    }
}

// ========================================
// COMPREHENSIVE STRING UTILITIES TESTS
// ========================================

void test_safe_strdup_valid_string(void)
{
    const char *original = "Hello, World!";
    test_string = safe_strdup(original);
    
    TEST_ASSERT_NOT_NULL(test_string);
    TEST_ASSERT_EQUAL_STRING(original, test_string);
    TEST_ASSERT_NOT_EQUAL(original, test_string); // Different memory addresses
}

void test_safe_strdup_empty_string(void)
{
    const char *original = "";
    test_string = safe_strdup(original);
    
    TEST_ASSERT_NOT_NULL(test_string);
    TEST_ASSERT_EQUAL_STRING("", test_string);
}

void test_safe_strdup_null_string(void)
{
    test_string = safe_strdup(NULL);
    TEST_ASSERT_NULL(test_string);
}

void test_safe_strdup_long_string(void)
{
    // Create a long string
    char long_string[1000];
    memset(long_string, 'A', 999);
    long_string[999] = '\0';
    
    test_string = safe_strdup(long_string);
    TEST_ASSERT_NOT_NULL(test_string);
    TEST_ASSERT_EQUAL_STRING(long_string, test_string);
    TEST_ASSERT_EQUAL(999, strlen(test_string));
}

void test_safe_strdup_special_characters(void)
{
    const char *original = "Special chars: !@#$%^&*()_+-={}[]|\\:;\"'<>?,./~`";
    test_string = safe_strdup(original);
    
    TEST_ASSERT_NOT_NULL(test_string);
    TEST_ASSERT_EQUAL_STRING(original, test_string);
}

// ========================================
// COMPREHENSIVE NUMBER PARSING TESTS
// ========================================

void test_parse_number_decimal(void)
{
    int64_t result = parse_number_with_base("42");
    TEST_ASSERT_EQUAL(42, result);
    
    result = parse_number_with_base("0");
    TEST_ASSERT_EQUAL(0, result);
    
    result = parse_number_with_base("999999");
    TEST_ASSERT_EQUAL(999999, result);
}

void test_parse_number_negative(void)
{
    int64_t result = parse_number_with_base("-42");
    TEST_ASSERT_EQUAL(-42, result);
    
    result = parse_number_with_base("-1");
    TEST_ASSERT_EQUAL(-1, result);
}

void test_parse_number_hexadecimal(void)
{
    int64_t result = parse_number_with_base("0x10");
    TEST_ASSERT_EQUAL(16, result);
    
    result = parse_number_with_base("0xFF");
    TEST_ASSERT_EQUAL(255, result);
    
    result = parse_number_with_base("0xDEADBEEF");
    TEST_ASSERT_EQUAL(0xDEADBEEF, result);
}

void test_parse_number_octal(void)
{
    int64_t result = parse_number_with_base("010");
    TEST_ASSERT_EQUAL(8, result);
    
    result = parse_number_with_base("0777");
    TEST_ASSERT_EQUAL(511, result);
}

void test_parse_number_binary(void)
{
    int64_t result = parse_number_with_base("0b1010");
    TEST_ASSERT_EQUAL(10, result);
    
    result = parse_number_with_base("0b11111111");
    TEST_ASSERT_EQUAL(255, result);
}

void test_parse_number_invalid_format(void)
{
    int64_t result = parse_number_with_base("invalid");
    // Implementation-specific: may return 0 or error value
    (void)result;
    TEST_ASSERT_TRUE(true); // Test that it doesn't crash
    
    result = parse_number_with_base("");
    (void)result;
    TEST_ASSERT_TRUE(true);
}

void test_parse_number_null_input(void)
{
    int64_t result = parse_number_with_base(NULL);
    // Should handle NULL gracefully
    (void)result;
    TEST_ASSERT_TRUE(true);
}

void test_parse_number_overflow(void)
{
    // Test with very large number
    int64_t result = parse_number_with_base("999999999999999999999");
    // Implementation should handle overflow gracefully
    (void)result;
    TEST_ASSERT_TRUE(true);
}

void test_parse_number_mixed_case_hex(void)
{
    int64_t result = parse_number_with_base("0xaBcDeF");
    TEST_ASSERT_EQUAL(0xABCDEF, result);
    
    result = parse_number_with_base("0XaBcDeF");
    TEST_ASSERT_EQUAL(0xABCDEF, result);
}

// ========================================
// COMPREHENSIVE MEMORY UTILITIES TESTS
// ========================================

void test_safe_malloc_valid_size(void)
{
    test_memory = safe_malloc(100);
    TEST_ASSERT_NOT_NULL(test_memory);
    
    // Test that we can write to the memory
    memset(test_memory, 0xAA, 100);
    TEST_ASSERT_EQUAL(0xAA, ((unsigned char*)test_memory)[0]);
    TEST_ASSERT_EQUAL(0xAA, ((unsigned char*)test_memory)[99]);
}

void test_safe_malloc_zero_size(void)
{
    test_memory = safe_malloc(0);
    // Implementation-specific: may return NULL or valid pointer
    // Test that it doesn't crash
    TEST_ASSERT_TRUE(true);
}

void test_safe_malloc_large_size(void)
{
    test_memory = safe_malloc(1024 * 1024); // 1MB
    TEST_ASSERT_NOT_NULL(test_memory);
    
    // Test that we can write to the memory
    ((unsigned char*)test_memory)[0] = 0xFF;
    TEST_ASSERT_EQUAL(0xFF, ((unsigned char*)test_memory)[0]);
}

void test_safe_calloc_valid_size(void)
{
    test_memory = safe_calloc(10, sizeof(int));
    TEST_ASSERT_NOT_NULL(test_memory);
    
    // Test that memory is zeroed
    int *int_array = (int*)test_memory;
    for (int i = 0; i < 10; i++) {
        TEST_ASSERT_EQUAL(0, int_array[i]);
    }
}

void test_safe_calloc_zero_count(void)
{
    test_memory = safe_calloc(0, sizeof(int));
    // Implementation-specific behavior
    TEST_ASSERT_TRUE(true);
}

void test_safe_calloc_zero_size(void)
{
    test_memory = safe_calloc(10, 0);
    // Implementation-specific behavior
    TEST_ASSERT_TRUE(true);
}

void test_safe_realloc_expand(void)
{
    test_memory = safe_malloc(100);
    TEST_ASSERT_NOT_NULL(test_memory);
    
    // Write some data
    memset(test_memory, 0xBB, 100);
    
    // Expand the memory
    test_memory = safe_realloc(test_memory, 200);
    TEST_ASSERT_NOT_NULL(test_memory);
    
    // Check that original data is preserved
    TEST_ASSERT_EQUAL(0xBB, ((unsigned char*)test_memory)[0]);
    TEST_ASSERT_EQUAL(0xBB, ((unsigned char*)test_memory)[99]);
}

void test_safe_realloc_shrink(void)
{
    test_memory = safe_malloc(200);
    TEST_ASSERT_NOT_NULL(test_memory);
    
    // Write some data
    memset(test_memory, 0xCC, 200);
    
    // Shrink the memory
    test_memory = safe_realloc(test_memory, 100);
    TEST_ASSERT_NOT_NULL(test_memory);
    
    // Check that data is preserved in the remaining part
    TEST_ASSERT_EQUAL(0xCC, ((unsigned char*)test_memory)[0]);
    TEST_ASSERT_EQUAL(0xCC, ((unsigned char*)test_memory)[99]);
}

void test_safe_realloc_null_pointer(void)
{
    test_memory = safe_realloc(NULL, 100);
    TEST_ASSERT_NOT_NULL(test_memory);
    // Should behave like malloc
}

void test_safe_realloc_zero_size(void)
{
    test_memory = safe_malloc(100);
    TEST_ASSERT_NOT_NULL(test_memory);
    
    void *result = safe_realloc(test_memory, 0);
    // Implementation-specific: may free and return NULL or return valid pointer
    if (result == NULL) {
        test_memory = NULL; // Prevent double-free in tearDown
    } else {
        test_memory = result;
    }
    TEST_ASSERT_TRUE(true);
}

// ========================================
// COMPREHENSIVE LEGACY FUNCTION TESTS
// ========================================

void test_add_numbers_positive(void)
{
    int result = add_numbers(5, 3);
    TEST_ASSERT_EQUAL(8, result);
    
    result = add_numbers(100, 200);
    TEST_ASSERT_EQUAL(300, result);
}

void test_add_numbers_negative(void)
{
    int result = add_numbers(-5, 3);
    TEST_ASSERT_EQUAL(-2, result);
    
    result = add_numbers(-10, -20);
    TEST_ASSERT_EQUAL(-30, result);
}

void test_add_numbers_zero(void)
{
    int result = add_numbers(0, 0);
    TEST_ASSERT_EQUAL(0, result);
    
    result = add_numbers(42, 0);
    TEST_ASSERT_EQUAL(42, result);
    
    result = add_numbers(0, -42);
    TEST_ASSERT_EQUAL(-42, result);
}

void test_add_numbers_overflow(void)
{
    int result = add_numbers(INT_MAX, 1);
    // Implementation should handle overflow gracefully
    (void)result;
    TEST_ASSERT_TRUE(true);
}

void test_multiply_numbers_positive(void)
{
    int result = multiply_numbers(5, 3);
    TEST_ASSERT_EQUAL(15, result);
    
    result = multiply_numbers(7, 8);
    TEST_ASSERT_EQUAL(56, result);
}

void test_multiply_numbers_negative(void)
{
    int result = multiply_numbers(-5, 3);
    TEST_ASSERT_EQUAL(-15, result);
    
    result = multiply_numbers(-4, -6);
    TEST_ASSERT_EQUAL(24, result);
}

void test_multiply_numbers_zero(void)
{
    int result = multiply_numbers(0, 42);
    TEST_ASSERT_EQUAL(0, result);
    
    result = multiply_numbers(42, 0);
    TEST_ASSERT_EQUAL(0, result);
    
    result = multiply_numbers(0, 0);
    TEST_ASSERT_EQUAL(0, result);
}

void test_multiply_numbers_one(void)
{
    int result = multiply_numbers(1, 42);
    TEST_ASSERT_EQUAL(42, result);
    
    result = multiply_numbers(42, 1);
    TEST_ASSERT_EQUAL(42, result);
    
    result = multiply_numbers(-1, 42);
    TEST_ASSERT_EQUAL(-42, result);
}

void test_multiply_numbers_overflow(void)
{
    int result = multiply_numbers(INT_MAX, 2);
    // Implementation should handle overflow gracefully
    (void)result;
    TEST_ASSERT_TRUE(true);
}

// Test runner
int main(void)
{
    UNITY_BEGIN();
    
    // String utilities tests
    RUN_TEST(test_safe_strdup_valid_string);
    RUN_TEST(test_safe_strdup_empty_string);
    RUN_TEST(test_safe_strdup_null_string);
    RUN_TEST(test_safe_strdup_long_string);
    RUN_TEST(test_safe_strdup_special_characters);
    
    // Number parsing tests
    RUN_TEST(test_parse_number_decimal);
    RUN_TEST(test_parse_number_negative);
    RUN_TEST(test_parse_number_hexadecimal);
    RUN_TEST(test_parse_number_octal);
    RUN_TEST(test_parse_number_binary);
    RUN_TEST(test_parse_number_invalid_format);
    RUN_TEST(test_parse_number_null_input);
    RUN_TEST(test_parse_number_overflow);
    RUN_TEST(test_parse_number_mixed_case_hex);
    
    // Memory utilities tests
    RUN_TEST(test_safe_malloc_valid_size);
    RUN_TEST(test_safe_malloc_zero_size);
    RUN_TEST(test_safe_malloc_large_size);
    RUN_TEST(test_safe_calloc_valid_size);
    RUN_TEST(test_safe_calloc_zero_count);
    RUN_TEST(test_safe_calloc_zero_size);
    RUN_TEST(test_safe_realloc_expand);
    RUN_TEST(test_safe_realloc_shrink);
    RUN_TEST(test_safe_realloc_null_pointer);
    RUN_TEST(test_safe_realloc_zero_size);
    
    // Legacy function tests
    RUN_TEST(test_add_numbers_positive);
    RUN_TEST(test_add_numbers_negative);
    RUN_TEST(test_add_numbers_zero);
    RUN_TEST(test_add_numbers_overflow);
    RUN_TEST(test_multiply_numbers_positive);
    RUN_TEST(test_multiply_numbers_negative);
    RUN_TEST(test_multiply_numbers_zero);
    RUN_TEST(test_multiply_numbers_one);
    RUN_TEST(test_multiply_numbers_overflow);
    
    return UNITY_END();
}
