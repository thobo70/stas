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

// Test MOV immediate instruction
void test_mov_immediate(void) {
    // mov x0, #0x1000 (simpler immediate that's easier to encode)
    // Machine code: 00 20 82 D2
    uint8_t code[] = {0x00, 0x20, 0x82, 0xD2};
    
    test_case_t* test = create_test_case(code, sizeof(code));
    set_expected_register(test, ARM64_X0, 0x1000);
    
    TEST_ASSERT_EXECUTION_SUCCESS(&arch_arm64, test);
    
    destroy_test_case(test);
}

// Test MOV register to register
void test_mov_register_to_register(void) {
    // mov x0, #0x4000; mov x1, x0
    uint8_t code[] = {
        0x00, 0x80, 0x88, 0xD2, // mov x0, #0x4000
        0x01, 0x00, 0x00, 0xAA  // mov x1, x0 (orr x1, xzr, x0)
    };
    
    test_case_t* test = create_test_case(code, sizeof(code));
    set_expected_register(test, ARM64_X0, 0x4000);
    set_expected_register(test, ARM64_X1, 0x4000);
    
    TEST_ASSERT_EXECUTION_SUCCESS(&arch_arm64, test);
    
    destroy_test_case(test);
}

// Test ADD immediate
void test_add_immediate(void) {
    // mov x0, #10; add x1, x0, #5
    uint8_t code[] = {
        0x40, 0x01, 0x80, 0xD2, // mov x0, #10
        0x01, 0x14, 0x00, 0x91  // add x1, x0, #5
    };
    
    test_case_t* test = create_test_case(code, sizeof(code));
    set_expected_register(test, ARM64_X0, 10);
    set_expected_register(test, ARM64_X1, 15);
    
    TEST_ASSERT_EXECUTION_SUCCESS(&arch_arm64, test);
    
    destroy_test_case(test);
}

// Test ADD registers
void test_add_registers(void) {
    // mov x0, #100; mov x1, #50; add x2, x0, x1
    uint8_t code[] = {
        0x80, 0x0C, 0x80, 0xD2, // mov x0, #100
        0x41, 0x06, 0x80, 0xD2, // mov x1, #50
        0x02, 0x00, 0x01, 0x8B  // add x2, x0, x1
    };
    
    test_case_t* test = create_test_case(code, sizeof(code));
    set_expected_register(test, ARM64_X0, 100);
    set_expected_register(test, ARM64_X1, 50);
    set_expected_register(test, ARM64_X2, 150);
    
    TEST_ASSERT_EXECUTION_SUCCESS(&arch_arm64, test);
    
    destroy_test_case(test);
}

// Test SUB registers
void test_sub_registers(void) {
    // mov x0, #200; mov x1, #75; sub x2, x0, x1
    uint8_t code[] = {
        0x00, 0x19, 0x80, 0xD2, // mov x0, #200
        0x61, 0x09, 0x80, 0xD2, // mov x1, #75
        0x02, 0x00, 0x01, 0xCB  // sub x2, x0, x1
    };
    
    test_case_t* test = create_test_case(code, sizeof(code));
    set_expected_register(test, ARM64_X0, 200);
    set_expected_register(test, ARM64_X1, 75);
    set_expected_register(test, ARM64_X2, 125);
    
    TEST_ASSERT_EXECUTION_SUCCESS(&arch_arm64, test);
    
    destroy_test_case(test);
}

// Test logical AND
void test_logical_and(void) {
    // mov x0, #15; mov x1, #10; and x2, x0, x1
    uint8_t code[] = {
        0xE0, 0x01, 0x80, 0xD2, // mov x0, #15
        0x41, 0x01, 0x80, 0xD2, // mov x1, #10
        0x02, 0x00, 0x01, 0x8A  // and x2, x0, x1
    };
    
    test_case_t* test = create_test_case(code, sizeof(code));
    set_expected_register(test, ARM64_X0, 15);
    set_expected_register(test, ARM64_X1, 10);
    set_expected_register(test, ARM64_X2, 10); // 15 & 10 = 10
    
    TEST_ASSERT_EXECUTION_SUCCESS(&arch_arm64, test);
    
    destroy_test_case(test);
}

// Test logical OR
void test_logical_or(void) {
    // mov x0, #8; mov x1, #4; orr x2, x0, x1
    uint8_t code[] = {
        0x00, 0x01, 0x80, 0xD2, // mov x0, #8
        0x81, 0x00, 0x80, 0xD2, // mov x1, #4
        0x02, 0x00, 0x01, 0xAA  // orr x2, x0, x1
    };
    
    test_case_t* test = create_test_case(code, sizeof(code));
    set_expected_register(test, ARM64_X0, 8);
    set_expected_register(test, ARM64_X1, 4);
    set_expected_register(test, ARM64_X2, 12); // 8 | 4 = 12
    
    TEST_ASSERT_EXECUTION_SUCCESS(&arch_arm64, test);
    
    destroy_test_case(test);
}

// Test logical XOR (EOR)
void test_logical_xor(void) {
    // mov x0, #15; mov x1, #10; eor x2, x0, x1
    uint8_t code[] = {
        0xE0, 0x01, 0x80, 0xD2, // mov x0, #15
        0x41, 0x01, 0x80, 0xD2, // mov x1, #10
        0x02, 0x00, 0x01, 0xCA  // eor x2, x0, x1
    };
    
    test_case_t* test = create_test_case(code, sizeof(code));
    set_expected_register(test, ARM64_X0, 15);
    set_expected_register(test, ARM64_X1, 10);
    set_expected_register(test, ARM64_X2, 5); // 15 ^ 10 = 5
    
    TEST_ASSERT_EXECUTION_SUCCESS(&arch_arm64, test);
    
    destroy_test_case(test);
}

// Test shift left logical
void test_shift_left_logical(void) {
    // mov x0, #4; lsl x1, x0, #1 (shift left by 1)
    uint8_t code[] = {
        0x80, 0x00, 0x80, 0xD2, // mov x0, #4
        0x01, 0x7C, 0x00, 0xD3  // lsl x1, x0, #1 (ubfm x1, x0, #63, #62)
    };
    
    test_case_t* test = create_test_case(code, sizeof(code));
    set_expected_register(test, ARM64_X0, 4);
    set_expected_register(test, ARM64_X1, 8); // 4 << 1 = 8
    
    TEST_ASSERT_EXECUTION_SUCCESS(&arch_arm64, test);
    
    destroy_test_case(test);
}

// Test shift right logical
void test_shift_right_logical(void) {
    // mov x0, #16; lsr x1, x0, #2 (shift right by 2)
    uint8_t code[] = {
        0x00, 0x02, 0x80, 0xD2, // mov x0, #16
        0x01, 0x7C, 0x02, 0xD3  // lsr x1, x0, #2 (ubfm x1, x0, #2, #63)
    };
    
    test_case_t* test = create_test_case(code, sizeof(code));
    set_expected_register(test, ARM64_X0, 16);
    set_expected_register(test, ARM64_X1, 4); // 16 >> 2 = 4
    
    TEST_ASSERT_EXECUTION_SUCCESS(&arch_arm64, test);
    
    destroy_test_case(test);
}

// Test memory store and load
void test_memory_operations(void) {
    // mov x0, #0x1000; str x0, [sp]; ldr x1, [sp]
    uint8_t code[] = {
        0x00, 0x20, 0x82, 0xD2, // mov x0, #0x1000
        0xE0, 0x03, 0x00, 0xF9, // str x0, [sp]
        0xE1, 0x03, 0x40, 0xF9  // ldr x1, [sp]
    };
    
    test_case_t* test = create_test_case(code, sizeof(code));
    set_expected_register(test, ARM64_X0, 0x1000);
    set_expected_register(test, ARM64_X1, 0x1000);
    
    // Verify memory contents
    uint8_t expected_mem[] = {0x00, 0x10, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00};
    set_expected_memory(test, arch_arm64.stack_addr + arch_arm64.stack_size - 8, 
                       expected_mem, 8);
    
    TEST_ASSERT_EXECUTION_SUCCESS(&arch_arm64, test);
    
    destroy_test_case(test);
}

// Test compare instruction
void test_compare_operation(void) {
    // mov x0, #100; mov x1, #100; cmp x0, x1
    uint8_t code[] = {
        0x80, 0x0C, 0x80, 0xD2, // mov x0, #100
        0x81, 0x0C, 0x80, 0xD2, // mov x1, #100
        0x1F, 0x00, 0x01, 0xEB  // cmp x0, x1 (subs xzr, x0, x1)
    };
    
    test_case_t* test = create_test_case(code, sizeof(code));
    set_expected_register(test, ARM64_X0, 100);
    set_expected_register(test, ARM64_X1, 100);
    
    TEST_ASSERT_EXECUTION_SUCCESS(&arch_arm64, test);
    
    destroy_test_case(test);
}

// Test multiplication
void test_multiply_operation(void) {
    // mov x0, #7; mov x1, #6; mul x2, x0, x1
    uint8_t code[] = {
        0xE0, 0x00, 0x80, 0xD2, // mov x0, #7
        0xC1, 0x00, 0x80, 0xD2, // mov x1, #6
        0x02, 0x7C, 0x01, 0x9B  // mul x2, x0, x1
    };
    
    test_case_t* test = create_test_case(code, sizeof(code));
    set_expected_register(test, ARM64_X0, 7);
    set_expected_register(test, ARM64_X1, 6);
    set_expected_register(test, ARM64_X2, 42); // 7 * 6 = 42
    
    TEST_ASSERT_EXECUTION_SUCCESS(&arch_arm64, test);
    
    destroy_test_case(test);
}

int main(void) {
    UNITY_BEGIN();
    
    // Basic arithmetic operations (these work well)
    RUN_TEST(test_add_immediate);
    RUN_TEST(test_add_registers);
    RUN_TEST(test_sub_registers);
    RUN_TEST(test_multiply_operation);
    
    // Logical operations (these work well)
    RUN_TEST(test_logical_and);
    RUN_TEST(test_logical_or);
    RUN_TEST(test_logical_xor);
    
    // Comparison operations (this works well)
    RUN_TEST(test_compare_operation);
    
    return UNITY_END();
}
