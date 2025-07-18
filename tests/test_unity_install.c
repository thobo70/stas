#include "unity.h"
#include <stdio.h>

void setUp(void) {
    // Test setup - runs before each test
}

void tearDown(void) {
    // Test cleanup - runs after each test
}

void test_unity_is_working(void) {
    TEST_ASSERT_TRUE(1);
    TEST_ASSERT_FALSE(0);
    TEST_ASSERT_EQUAL_INT(42, 42);
}

void test_basic_assertions(void) {
    int value = 10;
    TEST_ASSERT_EQUAL_INT(10, value);
    TEST_ASSERT_NOT_EQUAL_INT(5, value);
    TEST_ASSERT_GREATER_THAN_INT(5, value);
    TEST_ASSERT_LESS_THAN_INT(15, value);
}

int main(void) {
    UNITY_BEGIN();
    
    RUN_TEST(test_unity_is_working);
    RUN_TEST(test_basic_assertions);
    
    return UNITY_END();
}
