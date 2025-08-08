#include "../../unity/src/unity.h"
#include "../framework/unity_extensions.h"
#include <stdbool.h>
#include <stdint.h>

// Simple Unity test to verify the framework is working
void test_unity_framework_basic(void)
{
    TEST_ASSERT_EQUAL(1, 1);
    TEST_ASSERT_NOT_EQUAL(1, 2);
    TEST_ASSERT_TRUE(true);
    TEST_ASSERT_FALSE(false);
}

// Test custom assertions from unity_extensions
void test_unity_extensions_basic(void)
{
    uint8_t data1[] = {0x01, 0x02, 0x03};
    uint8_t data2[] = {0x01, 0x02, 0x03};
    uint8_t data3[] = {0x01, 0x02, 0x04};
    
    TEST_ASSERT_TRUE(compare_binary_data(data1, data2, 3));
    TEST_ASSERT_FALSE(compare_binary_data(data1, data3, 3));
}

// Test file operations
void test_file_operations(void)
{
    const char* test_content = "test content";
    char* temp_file = create_temp_test_file(test_content, ".txt");
    TEST_ASSERT_NOT_NULL(temp_file);
    
    bool content_match = verify_test_file_content(temp_file, test_content);
    TEST_ASSERT_TRUE(content_match);
    
    // Cleanup
    cleanup_test_resources(NULL, temp_file, NULL);
}

void setUp(void) {}
void tearDown(void) {}

// Main test runner
int main(void)
{
    UNITY_BEGIN();
    
    RUN_TEST(test_unity_framework_basic);
    RUN_TEST(test_unity_extensions_basic);
    RUN_TEST(test_file_operations);
    
    return UNITY_END();
}
