#include "unity.h"
#include "../../framework/unicorn_test_framework.h"
#include <stdint.h>
#include <string.h>

void setUp(void) {
    // Setup before each test
}

void tearDown(void) {
    // Cleanup after each test
}

// Test basic MOV instruction with immediate value
void test_mov_immediate_to_register(void) {
    // mov $0x1234, %ax
    // Machine code: B8 34 12
    uint8_t code[] = {0xB8, 0x34, 0x12};
    
    test_case_t* test = create_test_case(code, sizeof(code));
    set_expected_register(test, X86_16_AX, 0x1234);
    
    TEST_ASSERT_EXECUTION_SUCCESS(&arch_x86_16, test);
    
    destroy_test_case(test);
}

// Test MOV between registers
void test_mov_register_to_register(void) {
    // mov $0x5678, %ax; mov %ax, %bx
    uint8_t code[] = {
        0xB8, 0x78, 0x56, // mov $0x5678, %ax
        0x89, 0xC3        // mov %ax, %bx (actually movw %ax, %bx)
    };
    
    test_case_t* test = create_test_case(code, sizeof(code));
    set_expected_register(test, X86_16_AX, 0x5678);
    set_expected_register(test, X86_16_BX, 0x5678);
    
    TEST_ASSERT_EXECUTION_SUCCESS(&arch_x86_16, test);
    
    destroy_test_case(test);
}

// Test arithmetic: addition
void test_add_registers(void) {
    // mov $10, %ax; mov $5, %bx; add %bx, %ax
    uint8_t code[] = {
        0xB8, 0x0A, 0x00, // mov $10, %ax
        0xBB, 0x05, 0x00, // mov $5, %bx
        0x01, 0xD8        // add %bx, %ax
    };
    
    test_case_t* test = create_test_case(code, sizeof(code));
    set_expected_register(test, X86_16_AX, 15);
    set_expected_register(test, X86_16_BX, 5);
    
    TEST_ASSERT_EXECUTION_SUCCESS(&arch_x86_16, test);
    
    destroy_test_case(test);
}

// Test arithmetic: subtraction
void test_sub_registers(void) {
    // mov $20, %ax; mov $8, %bx; sub %bx, %ax
    uint8_t code[] = {
        0xB8, 0x14, 0x00, // mov $20, %ax
        0xBB, 0x08, 0x00, // mov $8, %bx
        0x29, 0xD8        // sub %bx, %ax
    };
    
    test_case_t* test = create_test_case(code, sizeof(code));
    set_expected_register(test, X86_16_AX, 12);
    set_expected_register(test, X86_16_BX, 8);
    
    TEST_ASSERT_EXECUTION_SUCCESS(&arch_x86_16, test);
    
    destroy_test_case(test);
}

// Test stack operations: push and pop
void test_push_pop_operations(void) {
    // mov $0x5678, %ax; push %ax; pop %bx
    uint8_t code[] = {
        0xB8, 0x78, 0x56, // mov $0x5678, %ax
        0x50,             // push %ax
        0x5B              // pop %bx
    };
    
    test_case_t* test = create_test_case(code, sizeof(code));
    set_expected_register(test, X86_16_AX, 0x5678);
    set_expected_register(test, X86_16_BX, 0x5678);
    // Stack pointer should be back to original position
    set_expected_register(test, X86_16_SP, arch_x86_16.stack_addr + arch_x86_16.stack_size - 2);
    
    TEST_ASSERT_EXECUTION_SUCCESS(&arch_x86_16, test);
    
    destroy_test_case(test);
}

// Test increment and decrement
void test_inc_dec_operations(void) {
    // mov $10, %ax; inc %ax; dec %ax
    uint8_t code[] = {
        0xB8, 0x0A, 0x00, // mov $10, %ax
        0x40,             // inc %ax
        0x48              // dec %ax
    };
    
    test_case_t* test = create_test_case(code, sizeof(code));
    set_expected_register(test, X86_16_AX, 10); // Should be back to 10
    
    TEST_ASSERT_EXECUTION_SUCCESS(&arch_x86_16, test);
    
    destroy_test_case(test);
}

// Test bitwise operations
void test_bitwise_operations(void) {
    // mov $0xFF00, %ax; mov $0x00FF, %bx; and %bx, %ax
    uint8_t code[] = {
        0xB8, 0x00, 0xFF, // mov $0xFF00, %ax
        0xBB, 0xFF, 0x00, // mov $0x00FF, %bx
        0x21, 0xD8        // and %bx, %ax
    };
    
    test_case_t* test = create_test_case(code, sizeof(code));
    set_expected_register(test, X86_16_AX, 0x0000); // 0xFF00 & 0x00FF = 0x0000
    set_expected_register(test, X86_16_BX, 0x00FF);
    
    TEST_ASSERT_EXECUTION_SUCCESS(&arch_x86_16, test);
    
    destroy_test_case(test);
}

// Test compare instruction
void test_cmp_instruction(void) {
    // mov $10, %ax; mov $10, %bx; cmp %bx, %ax
    uint8_t code[] = {
        0xB8, 0x0A, 0x00, // mov $10, %ax
        0xBB, 0x0A, 0x00, // mov $10, %bx
        0x39, 0xD8        // cmp %bx, %ax
    };
    
    test_case_t* test = create_test_case(code, sizeof(code));
    set_expected_register(test, X86_16_AX, 10);
    set_expected_register(test, X86_16_BX, 10);
    
    TEST_ASSERT_EXECUTION_SUCCESS(&arch_x86_16, test);
    
    destroy_test_case(test);
}

int main(void) {
    UNITY_BEGIN();
    
    // Basic move operations
    RUN_TEST(test_mov_immediate_to_register);
    RUN_TEST(test_mov_register_to_register);
    
    // Arithmetic operations
    RUN_TEST(test_add_registers);
    RUN_TEST(test_sub_registers);
    RUN_TEST(test_inc_dec_operations);
    
    // Stack operations
    RUN_TEST(test_push_pop_operations);
    
    // Bitwise operations
    RUN_TEST(test_bitwise_operations);
    
    // Other operations
    RUN_TEST(test_cmp_instruction);
    
    return UNITY_END();
}
