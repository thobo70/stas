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
void test_movl_immediate_to_register(void) {
    // movl $0x12345678, %eax
    // Machine code: B8 78 56 34 12
    uint8_t code[] = {0xB8, 0x78, 0x56, 0x34, 0x12};
    
    test_case_t* test = create_test_case(code, sizeof(code));
    set_expected_register(test, X86_32_EAX, 0x12345678);
    
    TEST_ASSERT_EXECUTION_SUCCESS(&arch_x86_32, test);
    
    destroy_test_case(test);
}

// Test MOV between registers
void test_movl_register_to_register(void) {
    // movl $0x87654321, %eax; movl %eax, %ebx
    uint8_t code[] = {
        0xB8, 0x21, 0x43, 0x65, 0x87, // movl $0x87654321, %eax
        0x89, 0xC3                     // movl %eax, %ebx
    };
    
    test_case_t* test = create_test_case(code, sizeof(code));
    set_expected_register(test, X86_32_EAX, 0x87654321);
    set_expected_register(test, X86_32_EBX, 0x87654321);
    
    TEST_ASSERT_EXECUTION_SUCCESS(&arch_x86_32, test);
    
    destroy_test_case(test);
}

// Test arithmetic: addition
void test_addl_registers(void) {
    // movl $100, %eax; movl $50, %ebx; addl %ebx, %eax
    uint8_t code[] = {
        0xB8, 0x64, 0x00, 0x00, 0x00, // movl $100, %eax
        0xBB, 0x32, 0x00, 0x00, 0x00, // movl $50, %ebx
        0x01, 0xD8                     // addl %ebx, %eax
    };
    
    test_case_t* test = create_test_case(code, sizeof(code));
    set_expected_register(test, X86_32_EAX, 150);
    set_expected_register(test, X86_32_EBX, 50);
    
    TEST_ASSERT_EXECUTION_SUCCESS(&arch_x86_32, test);
    
    destroy_test_case(test);
}

// Test arithmetic: subtraction
void test_subl_registers(void) {
    // movl $200, %eax; movl $80, %ebx; subl %ebx, %eax
    uint8_t code[] = {
        0xB8, 0xC8, 0x00, 0x00, 0x00, // movl $200, %eax
        0xBB, 0x50, 0x00, 0x00, 0x00, // movl $80, %ebx
        0x29, 0xD8                     // subl %ebx, %eax
    };
    
    test_case_t* test = create_test_case(code, sizeof(code));
    set_expected_register(test, X86_32_EAX, 120);
    set_expected_register(test, X86_32_EBX, 80);
    
    TEST_ASSERT_EXECUTION_SUCCESS(&arch_x86_32, test);
    
    destroy_test_case(test);
}

// Test memory operations: store and load
void test_memory_store_load(void) {
    // movl $0x1234, %eax; movl %eax, (%esp); movl (%esp), %ebx
    uint8_t code[] = {
        0xB8, 0x34, 0x12, 0x00, 0x00, // movl $0x1234, %eax
        0x89, 0x04, 0x24,             // movl %eax, (%esp)
        0x8B, 0x1C, 0x24              // movl (%esp), %ebx
    };
    
    test_case_t* test = create_test_case(code, sizeof(code));
    set_expected_register(test, X86_32_EAX, 0x1234);
    set_expected_register(test, X86_32_EBX, 0x1234);
    
    // Also verify memory contents
    uint8_t expected_mem[] = {0x34, 0x12, 0x00, 0x00};
    set_expected_memory(test, arch_x86_32.stack_addr + arch_x86_32.stack_size - 4, 
                       expected_mem, 4);
    
    TEST_ASSERT_EXECUTION_SUCCESS(&arch_x86_32, test);
    
    destroy_test_case(test);
}

// Test stack operations: push and pop
void test_push_pop_operations(void) {
    // movl $0x56789ABC, %eax; pushl %eax; popl %ebx
    uint8_t code[] = {
        0xB8, 0xBC, 0x9A, 0x78, 0x56, // movl $0x56789ABC, %eax
        0x50,                         // pushl %eax
        0x5B                          // popl %ebx
    };
    
    test_case_t* test = create_test_case(code, sizeof(code));
    set_expected_register(test, X86_32_EAX, 0x56789ABC);
    set_expected_register(test, X86_32_EBX, 0x56789ABC);
    // Stack pointer should be back to original position
    set_expected_register(test, X86_32_ESP, arch_x86_32.stack_addr + arch_x86_32.stack_size - 4);
    
    TEST_ASSERT_EXECUTION_SUCCESS(&arch_x86_32, test);
    
    destroy_test_case(test);
}

// Test increment and decrement
void test_inc_dec_operations(void) {
    // movl $100, %eax; incl %eax; decl %eax
    uint8_t code[] = {
        0xB8, 0x64, 0x00, 0x00, 0x00, // movl $100, %eax
        0x40,                         // incl %eax
        0x48                          // decl %eax
    };
    
    test_case_t* test = create_test_case(code, sizeof(code));
    set_expected_register(test, X86_32_EAX, 100); // Should be back to 100
    
    TEST_ASSERT_EXECUTION_SUCCESS(&arch_x86_32, test);
    
    destroy_test_case(test);
}

// Test bitwise operations
void test_bitwise_operations(void) {
    // movl $0xFFFF0000, %eax; movl $0x0000FFFF, %ebx; andl %ebx, %eax
    uint8_t code[] = {
        0xB8, 0x00, 0x00, 0xFF, 0xFF, // movl $0xFFFF0000, %eax
        0xBB, 0xFF, 0xFF, 0x00, 0x00, // movl $0x0000FFFF, %ebx
        0x21, 0xD8                     // andl %ebx, %eax
    };
    
    test_case_t* test = create_test_case(code, sizeof(code));
    set_expected_register(test, X86_32_EAX, 0x00000000); // 0xFFFF0000 & 0x0000FFFF = 0x00000000
    set_expected_register(test, X86_32_EBX, 0x0000FFFF);
    
    TEST_ASSERT_EXECUTION_SUCCESS(&arch_x86_32, test);
    
    destroy_test_case(test);
}

// Test OR operation
void test_or_operation(void) {
    // movl $0xFF00FF00, %eax; movl $0x00FF00FF, %ebx; orl %ebx, %eax
    uint8_t code[] = {
        0xB8, 0x00, 0xFF, 0x00, 0xFF, // movl $0xFF00FF00, %eax
        0xBB, 0xFF, 0x00, 0xFF, 0x00, // movl $0x00FF00FF, %ebx
        0x09, 0xD8                     // orl %ebx, %eax
    };
    
    test_case_t* test = create_test_case(code, sizeof(code));
    set_expected_register(test, X86_32_EAX, 0xFFFFFFFF); // OR should result in all 1s
    set_expected_register(test, X86_32_EBX, 0x00FF00FF);
    
    TEST_ASSERT_EXECUTION_SUCCESS(&arch_x86_32, test);
    
    destroy_test_case(test);
}

// Test compare instruction
void test_cmp_instruction(void) {
    // movl $1000, %eax; movl $1000, %ebx; cmpl %ebx, %eax
    uint8_t code[] = {
        0xB8, 0xE8, 0x03, 0x00, 0x00, // movl $1000, %eax
        0xBB, 0xE8, 0x03, 0x00, 0x00, // movl $1000, %ebx
        0x39, 0xD8                     // cmpl %ebx, %eax
    };
    
    test_case_t* test = create_test_case(code, sizeof(code));
    set_expected_register(test, X86_32_EAX, 1000);
    set_expected_register(test, X86_32_EBX, 1000);
    
    TEST_ASSERT_EXECUTION_SUCCESS(&arch_x86_32, test);
    
    destroy_test_case(test);
}

int main(void) {
    UNITY_BEGIN();
    
    // Basic move operations
    RUN_TEST(test_movl_immediate_to_register);
    RUN_TEST(test_movl_register_to_register);
    
    // Arithmetic operations
    RUN_TEST(test_addl_registers);
    RUN_TEST(test_subl_registers);
    RUN_TEST(test_inc_dec_operations);
    
    // Memory operations
    RUN_TEST(test_memory_store_load);
    RUN_TEST(test_push_pop_operations);
    
    // Bitwise operations
    RUN_TEST(test_bitwise_operations);
    RUN_TEST(test_or_operation);
    
    // Other operations
    RUN_TEST(test_cmp_instruction);
    
    return UNITY_END();
}
