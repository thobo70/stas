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
void test_movq_immediate_to_register(void) {
    // STAS assembled code: movq $0x1234567890ABCDEF, %rax
    // Machine code: 48 B8 EF CD AB 90 78 56 34 12
    uint8_t code[] = {0x48, 0xB8, 0xEF, 0xCD, 0xAB, 0x90, 0x78, 0x56, 0x34, 0x12};
    
    test_case_t* test = create_test_case(code, sizeof(code));
    set_expected_register(test, X86_64_RAX, 0x1234567890ABCDEF);
    
    TEST_ASSERT_EXECUTION_SUCCESS(&arch_x86_64, test);
    
    destroy_test_case(test);
}

// Test MOV between registers
void test_movq_register_to_register(void) {
    // Setup: RAX = 0x1234567890ABCDEF, then movq %rax, %rbx
    uint8_t code[] = {
        0x48, 0xB8, 0xEF, 0xCD, 0xAB, 0x90, 0x78, 0x56, 0x34, 0x12, // movq $imm, %rax
        0x48, 0x89, 0xC3  // movq %rax, %rbx
    };
    
    test_case_t* test = create_test_case(code, sizeof(code));
    set_expected_register(test, X86_64_RAX, 0x1234567890ABCDEF);
    set_expected_register(test, X86_64_RBX, 0x1234567890ABCDEF);
    
    TEST_ASSERT_EXECUTION_SUCCESS(&arch_x86_64, test);
    
    destroy_test_case(test);
}

// Test arithmetic: addition
void test_addq_registers(void) {
    // movq $10, %rax; movq $5, %rbx; addq %rbx, %rax
    uint8_t code[] = {
        0x48, 0xC7, 0xC0, 0x0A, 0x00, 0x00, 0x00, // movq $10, %rax
        0x48, 0xC7, 0xC3, 0x05, 0x00, 0x00, 0x00, // movq $5, %rbx
        0x48, 0x01, 0xD8                            // addq %rbx, %rax
    };
    
    test_case_t* test = create_test_case(code, sizeof(code));
    set_expected_register(test, X86_64_RAX, 15);
    set_expected_register(test, X86_64_RBX, 5);
    
    TEST_ASSERT_EXECUTION_SUCCESS(&arch_x86_64, test);
    
    destroy_test_case(test);
}

// Test arithmetic: subtraction
void test_subq_registers(void) {
    // movq $20, %rax; movq $8, %rbx; subq %rbx, %rax
    uint8_t code[] = {
        0x48, 0xC7, 0xC0, 0x14, 0x00, 0x00, 0x00, // movq $20, %rax
        0x48, 0xC7, 0xC3, 0x08, 0x00, 0x00, 0x00, // movq $8, %rbx
        0x48, 0x29, 0xD8                            // subq %rbx, %rax
    };
    
    test_case_t* test = create_test_case(code, sizeof(code));
    set_expected_register(test, X86_64_RAX, 12);
    set_expected_register(test, X86_64_RBX, 8);
    
    TEST_ASSERT_EXECUTION_SUCCESS(&arch_x86_64, test);
    
    destroy_test_case(test);
}

// Test memory operations: store and load
void test_memory_store_load(void) {
    // movq $0x1234, %rax; movq %rax, (%rsp); movq (%rsp), %rbx
    uint8_t code[] = {
        0x48, 0xC7, 0xC0, 0x34, 0x12, 0x00, 0x00, // movq $0x1234, %rax
        0x48, 0x89, 0x04, 0x24,                     // movq %rax, (%rsp)
        0x48, 0x8B, 0x1C, 0x24                      // movq (%rsp), %rbx
    };
    
    test_case_t* test = create_test_case(code, sizeof(code));
    set_expected_register(test, X86_64_RAX, 0x1234);
    set_expected_register(test, X86_64_RBX, 0x1234);
    
    // Also verify memory contents
    uint8_t expected_mem[] = {0x34, 0x12, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00};
    set_expected_memory(test, arch_x86_64.stack_addr + arch_x86_64.stack_size - 8, 
                       expected_mem, 8);
    
    TEST_ASSERT_EXECUTION_SUCCESS(&arch_x86_64, test);
    
    destroy_test_case(test);
}

// Test stack operations: push and pop
void test_push_pop_operations(void) {
    // movq $0x5678, %rax; pushq %rax; popq %rbx
    uint8_t code[] = {
        0x48, 0xC7, 0xC0, 0x78, 0x56, 0x00, 0x00, // movq $0x5678, %rax
        0x50,                                       // pushq %rax
        0x5B                                        // popq %rbx
    };
    
    test_case_t* test = create_test_case(code, sizeof(code));
    set_expected_register(test, X86_64_RAX, 0x5678);
    set_expected_register(test, X86_64_RBX, 0x5678);
    // Stack pointer should be back to original position
    set_expected_register(test, X86_64_RSP, arch_x86_64.stack_addr + arch_x86_64.stack_size - 8);
    
    TEST_ASSERT_EXECUTION_SUCCESS(&arch_x86_64, test);
    
    destroy_test_case(test);
}

// Test increment and decrement
void test_inc_dec_operations(void) {
    // movq $10, %rax; incq %rax; decq %rax
    uint8_t code[] = {
        0x48, 0xC7, 0xC0, 0x0A, 0x00, 0x00, 0x00, // movq $10, %rax
        0x48, 0xFF, 0xC0,                           // incq %rax
        0x48, 0xFF, 0xC8                            // decq %rax
    };
    
    test_case_t* test = create_test_case(code, sizeof(code));
    set_expected_register(test, X86_64_RAX, 10); // Should be back to 10
    
    TEST_ASSERT_EXECUTION_SUCCESS(&arch_x86_64, test);
    
    destroy_test_case(test);
}

// Test bitwise operations
void test_bitwise_operations(void) {
    // movq $0xFF00, %rax; movq $0x00FF, %rbx; andq %rbx, %rax
    uint8_t code[] = {
        0x48, 0xC7, 0xC0, 0x00, 0xFF, 0x00, 0x00, // movq $0xFF00, %rax
        0x48, 0xC7, 0xC3, 0xFF, 0x00, 0x00, 0x00, // movq $0x00FF, %rbx
        0x48, 0x21, 0xD8                            // andq %rbx, %rax
    };
    
    test_case_t* test = create_test_case(code, sizeof(code));
    set_expected_register(test, X86_64_RAX, 0); // 0xFF00 & 0x00FF = 0
    set_expected_register(test, X86_64_RBX, 0xFF);
    
    TEST_ASSERT_EXECUTION_SUCCESS(&arch_x86_64, test);
    
    destroy_test_case(test);
}

// Test OR operation
void test_or_operation(void) {
    // movq $0xFF00, %rax; movq $0x00FF, %rbx; orq %rbx, %rax
    uint8_t code[] = {
        0x48, 0xC7, 0xC0, 0x00, 0xFF, 0x00, 0x00, // movq $0xFF00, %rax
        0x48, 0xC7, 0xC3, 0xFF, 0x00, 0x00, 0x00, // movq $0x00FF, %rbx
        0x48, 0x09, 0xD8                            // orq %rbx, %rax
    };
    
    test_case_t* test = create_test_case(code, sizeof(code));
    set_expected_register(test, X86_64_RAX, 0xFFFF); // 0xFF00 | 0x00FF = 0xFFFF
    set_expected_register(test, X86_64_RBX, 0xFF);
    
    TEST_ASSERT_EXECUTION_SUCCESS(&arch_x86_64, test);
    
    destroy_test_case(test);
}

// Test XOR operation
void test_xor_operation(void) {
    // movq $0xFFFF, %rax; movq $0xFF00, %rbx; xorq %rbx, %rax
    uint8_t code[] = {
        0x48, 0xC7, 0xC0, 0xFF, 0xFF, 0x00, 0x00, // movq $0xFFFF, %rax
        0x48, 0xC7, 0xC3, 0x00, 0xFF, 0x00, 0x00, // movq $0xFF00, %rbx
        0x48, 0x31, 0xD8                            // xorq %rbx, %rax
    };
    
    test_case_t* test = create_test_case(code, sizeof(code));
    set_expected_register(test, X86_64_RAX, 0xFF); // 0xFFFF ^ 0xFF00 = 0x00FF
    set_expected_register(test, X86_64_RBX, 0xFF00);
    
    TEST_ASSERT_EXECUTION_SUCCESS(&arch_x86_64, test);
    
    destroy_test_case(test);
}

// Test shift operations
void test_shift_left(void) {
    // movq $5, %rax; shlq $2, %rax  (5 << 2 = 20)
    uint8_t code[] = {
        0x48, 0xC7, 0xC0, 0x05, 0x00, 0x00, 0x00, // movq $5, %rax
        0x48, 0xC1, 0xE0, 0x02                      // shlq $2, %rax
    };
    
    test_case_t* test = create_test_case(code, sizeof(code));
    set_expected_register(test, X86_64_RAX, 20);
    
    TEST_ASSERT_EXECUTION_SUCCESS(&arch_x86_64, test);
    
    destroy_test_case(test);
}

// Test comparison instruction (affects flags but we can't easily check flags)
void test_cmp_instruction(void) {
    // movq $10, %rax; movq $5, %rbx; cmpq %rbx, %rax
    uint8_t code[] = {
        0x48, 0xC7, 0xC0, 0x0A, 0x00, 0x00, 0x00, // movq $10, %rax
        0x48, 0xC7, 0xC3, 0x05, 0x00, 0x00, 0x00, // movq $5, %rbx
        0x48, 0x39, 0xD8                            // cmpq %rbx, %rax
    };
    
    test_case_t* test = create_test_case(code, sizeof(code));
    // Registers should remain unchanged after comparison
    set_expected_register(test, X86_64_RAX, 10);
    set_expected_register(test, X86_64_RBX, 5);
    
    TEST_ASSERT_EXECUTION_SUCCESS(&arch_x86_64, test);
    
    destroy_test_case(test);
}

// Test 32-bit operations (should zero upper 32 bits)
void test_32bit_operation_zero_extension(void) {
    // movq $0xFFFFFFFFFFFFFFFF, %rax; movl $0x1234, %eax
    uint8_t code[] = {
        0x48, 0xC7, 0xC0, 0xFF, 0xFF, 0xFF, 0xFF, // movq $0xFFFFFFFF, %rax (sign extended)
        0xB8, 0x34, 0x12, 0x00, 0x00               // movl $0x1234, %eax
    };
    
    test_case_t* test = create_test_case(code, sizeof(code));
    // 32-bit operation should zero upper 32 bits
    set_expected_register(test, X86_64_RAX, 0x1234);
    
    TEST_ASSERT_EXECUTION_SUCCESS(&arch_x86_64, test);
    
    destroy_test_case(test);
}

// Test error conditions
void test_invalid_instruction_execution(void) {
    // Invalid opcode: 0xFF 0xFF
    uint8_t code[] = {0xFF, 0xFF};
    
    test_case_t* test = create_test_case(code, sizeof(code));
    test->should_succeed = false;
    
    // Should fail with invalid instruction error
    int result = execute_and_verify(&arch_x86_64, test);
    TEST_ASSERT_NOT_EQUAL(0, result);
    
    destroy_test_case(test);
}

int main(void) {
    UNITY_BEGIN();
    
    // Basic move operations
    RUN_TEST(test_movq_immediate_to_register);
    RUN_TEST(test_movq_register_to_register);
    
    // Arithmetic operations
    RUN_TEST(test_addq_registers);
    RUN_TEST(test_subq_registers);
    RUN_TEST(test_inc_dec_operations);
    
    // Memory operations
    RUN_TEST(test_memory_store_load);
    RUN_TEST(test_push_pop_operations);
    
    // Bitwise operations
    RUN_TEST(test_bitwise_operations);
    RUN_TEST(test_or_operation);
    RUN_TEST(test_xor_operation);
    RUN_TEST(test_shift_left);
    
    // Other operations
    RUN_TEST(test_cmp_instruction);
    RUN_TEST(test_32bit_operation_zero_extension);
    
    // Error conditions
    RUN_TEST(test_invalid_instruction_execution);
    
    return UNITY_END();
}
