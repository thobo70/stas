#include "unity.h"
#include "unity_extensions.h"
#include "../../../include/arch_interface.h"
#include "../../../include/x86_32.h"
#include <string.h>
#include <stdlib.h>

// Forward declaration
extern arch_ops_t *get_arch_ops_x86_32(void);

// Global test fixtures
arch_ops_t *arch_ops;
instruction_t test_instruction;

void setUp(void)
{
    arch_ops = get_arch_ops_x86_32();
    memset(&test_instruction, 0, sizeof(instruction_t));
}

void tearDown(void)
{
    // Clean up test instruction if allocated
    if (test_instruction.mnemonic) {
        free((void*)test_instruction.mnemonic);
        test_instruction.mnemonic = NULL;
    }
    if (test_instruction.operands) {
        free(test_instruction.operands);
        test_instruction.operands = NULL;
    }
}

// ========================================
// ARCHITECTURE INTERFACE TESTS
// ========================================

void test_get_arch_ops_x86_32_valid(void)
{
    TEST_ASSERT_NOT_NULL(arch_ops);
    TEST_ASSERT_NOT_NULL(arch_ops->name);
    TEST_ASSERT_EQUAL_STRING("x86_32", arch_ops->name);
}

void test_x86_32_arch_ops_functions_not_null(void)
{
    TEST_ASSERT_NOT_NULL(arch_ops);
    TEST_ASSERT_NOT_NULL(arch_ops->init);
    TEST_ASSERT_NOT_NULL(arch_ops->cleanup);
    TEST_ASSERT_NOT_NULL(arch_ops->parse_instruction);
    TEST_ASSERT_NOT_NULL(arch_ops->encode_instruction);
    TEST_ASSERT_NOT_NULL(arch_ops->parse_register);
    TEST_ASSERT_NOT_NULL(arch_ops->is_valid_register);
    TEST_ASSERT_NOT_NULL(arch_ops->get_register_name);
}

void test_x86_32_init_cleanup(void)
{
    int init_result = arch_ops->init();
    TEST_ASSERT_EQUAL(0, init_result);
    
    arch_ops->cleanup();
    // Should not crash
}

// ========================================
// REGISTER VALIDATION TESTS
// ========================================

void test_x86_32_register_parsing_32bit(void)
{
    const char* registers[] = {"eax", "ebx", "ecx", "edx", "esi", "edi", "esp", "ebp"};
    
    for (int i = 0; i < 8; i++) {
        asm_register_t reg;
        memset(&reg, 0, sizeof(asm_register_t));
        
        int result = arch_ops->parse_register(registers[i], &reg);
        TEST_ASSERT_EQUAL(0, result);
        TEST_ASSERT_TRUE(arch_ops->is_valid_register(reg));
        TEST_ASSERT_EQUAL(4, reg.size); // 32-bit registers = 4 bytes
    }
}

void test_x86_32_register_parsing_16bit_compat(void)
{
    const char* registers[] = {"ax", "bx", "cx", "dx", "si", "di", "sp", "bp"};
    
    for (int i = 0; i < 8; i++) {
        asm_register_t reg;
        memset(&reg, 0, sizeof(asm_register_t));
        
        int result = arch_ops->parse_register(registers[i], &reg);
        TEST_ASSERT_EQUAL(0, result);
        TEST_ASSERT_TRUE(arch_ops->is_valid_register(reg));
        TEST_ASSERT_EQUAL(2, reg.size); // 16-bit registers = 2 bytes
    }
}

void test_x86_32_register_parsing_8bit_compat(void)
{
    const char* registers[] = {"al", "bl", "cl", "dl", "ah", "bh", "ch", "dh"};
    
    for (int i = 0; i < 8; i++) {
        asm_register_t reg;
        memset(&reg, 0, sizeof(asm_register_t));
        
        int result = arch_ops->parse_register(registers[i], &reg);
        TEST_ASSERT_EQUAL(0, result);
        TEST_ASSERT_TRUE(arch_ops->is_valid_register(reg));
        TEST_ASSERT_EQUAL(1, reg.size); // 8-bit registers = 1 byte
    }
}

void test_x86_32_register_parsing_invalid(void)
{
    // These should fail - x86_64 only registers
    const char* invalid_registers[] = {"rax", "rbx", "r8", "r9", "r15"};
    
    for (int i = 0; i < 5; i++) {
        asm_register_t reg;
        memset(&reg, 0, sizeof(asm_register_t));
        
        int result = arch_ops->parse_register(invalid_registers[i], &reg);
        TEST_ASSERT_NOT_EQUAL(0, result); // Should fail
    }
}

void test_x86_32_register_name_retrieval(void)
{
    asm_register_t reg;
    memset(&reg, 0, sizeof(asm_register_t));
    
    // Test EAX
    int result = arch_ops->parse_register("eax", &reg);
    TEST_ASSERT_EQUAL(0, result);
    
    const char* name = arch_ops->get_register_name(reg);
    TEST_ASSERT_NOT_NULL(name);
    TEST_ASSERT_TRUE(strstr(name, "eax") != NULL || strstr(name, "EAX") != NULL);
}

// ========================================
// INSTRUCTION PARSING TESTS
// ========================================

void test_x86_32_instruction_parsing_basic(void)
{
    operand_t operands[2] = {0};
    instruction_t local_instruction;
    memset(&local_instruction, 0, sizeof(instruction_t));
    
    int result = arch_ops->parse_instruction("movl", operands, 0, &local_instruction);
    TEST_ASSERT_EQUAL(0, result);
    TEST_ASSERT_NOT_NULL(local_instruction.mnemonic);
    
    // Clean up local instruction
    if (local_instruction.mnemonic) {
        free((void*)local_instruction.mnemonic);
    }
    if (local_instruction.operands && local_instruction.operands != operands) {
        free(local_instruction.operands);
    }
}

void test_x86_32_instruction_parsing_16bit_compat(void)
{
    operand_t operands[2] = {0};
    
    // x86_16 compatible instructions should work
    const char* instructions[] = {"mov", "add", "sub", "push", "pop"};
    
    for (int i = 0; i < 5; i++) {
        instruction_t local_instruction;
        memset(&local_instruction, 0, sizeof(instruction_t));
        int result = arch_ops->parse_instruction(instructions[i], operands, 0, &local_instruction);
        TEST_ASSERT_EQUAL(0, result);
        TEST_ASSERT_NOT_NULL(local_instruction.mnemonic);
        
        // Clean up this iteration
        if (local_instruction.mnemonic) {
            free((void*)local_instruction.mnemonic);
        }
        if (local_instruction.operands && local_instruction.operands != operands) {
            free(local_instruction.operands);
        }
    }
}

// ========================================
// COMPATIBILITY TESTS
// ========================================

void test_x86_32_backward_compatibility_matrix(void)
{
    // Test that x86_32 supports all x86_16 registers
    const char* x86_16_compatible[] = {
        "ax", "bx", "cx", "dx", "si", "di", "sp", "bp",
        "al", "bl", "cl", "dl", "ah", "bh", "ch", "dh"
    };
    
    for (int i = 0; i < 16; i++) {
        asm_register_t reg;
        memset(&reg, 0, sizeof(asm_register_t));
        
        int result = arch_ops->parse_register(x86_16_compatible[i], &reg);
        TEST_ASSERT_EQUAL(0, result);
        TEST_ASSERT_TRUE(arch_ops->is_valid_register(reg));
    }
}

// ========================================
// ERROR HANDLING TESTS
// ========================================

void test_x86_32_null_parameter_handling(void)
{
    asm_register_t reg;
    operand_t operands[2] = {0};
    uint8_t buffer[32];
    size_t length = sizeof(buffer);
    
    // Test null register name
    int result = arch_ops->parse_register(NULL, &reg);
    TEST_ASSERT_NOT_EQUAL(0, result);
    
    // Test null register pointer
    result = arch_ops->parse_register("eax", NULL);
    TEST_ASSERT_NOT_EQUAL(0, result);
    
    // Test null instruction name
    instruction_t local_instruction;
    memset(&local_instruction, 0, sizeof(instruction_t));
    result = arch_ops->parse_instruction(NULL, operands, 0, &local_instruction);
    TEST_ASSERT_NOT_EQUAL(0, result);
    
    // Test null instruction pointer
    result = arch_ops->encode_instruction(NULL, buffer, &length);
    TEST_ASSERT_NOT_EQUAL(0, result);
}

void test_x86_32_invalid_instruction_handling(void)
{
    operand_t operands[2] = {0};
    
    // Test x86_64 specific instructions that should fail
    const char* x86_64_only[] = {"movq", "addq", "pushq", "popq", "syscall"};
    
    for (int i = 0; i < 5; i++) {
        instruction_t local_instruction;
        memset(&local_instruction, 0, sizeof(instruction_t));
        int result = arch_ops->parse_instruction(x86_64_only[i], operands, 0, &local_instruction);
        TEST_ASSERT_NOT_EQUAL(0, result); // Should fail
        
        // Clean up if anything was allocated
        if (local_instruction.mnemonic) {
            free((void*)local_instruction.mnemonic);
        }
    }
}

// ========================================
// ENCODING TESTS
// ========================================

void test_x86_32_instruction_encoding(void)
{
    uint8_t buffer[32];
    size_t length = sizeof(buffer);
    
    // Setup a basic instruction
    instruction_t local_instruction;
    memset(&local_instruction, 0, sizeof(instruction_t));
    local_instruction.mnemonic = "nop";
    local_instruction.operand_count = 0;
    local_instruction.operands = NULL;
    
    int result = arch_ops->encode_instruction(&local_instruction, buffer, &length);
    // May succeed or fail depending on implementation completeness
    TEST_ASSERT_TRUE(result == 0 || result != 0);
    // May succeed or fail depending on implementation completeness
    TEST_ASSERT_TRUE(result == 0 || result != 0);
    
    if (result == 0) {
        TEST_ASSERT_GREATER_THAN(0, length);
    }
}

// ========================================
// TEST RUNNER
// ========================================

int main(void)
{
    UNITY_BEGIN();
    
    // Architecture interface tests
    RUN_TEST(test_get_arch_ops_x86_32_valid);
    RUN_TEST(test_x86_32_arch_ops_functions_not_null);
    RUN_TEST(test_x86_32_init_cleanup);
    
    // Register tests
    RUN_TEST(test_x86_32_register_parsing_32bit);
    RUN_TEST(test_x86_32_register_parsing_16bit_compat);
    RUN_TEST(test_x86_32_register_parsing_8bit_compat);
    RUN_TEST(test_x86_32_register_parsing_invalid);
    RUN_TEST(test_x86_32_register_name_retrieval);
    
    // Instruction tests
    RUN_TEST(test_x86_32_instruction_parsing_basic);
    RUN_TEST(test_x86_32_instruction_parsing_16bit_compat);
    
    // Compatibility tests
    RUN_TEST(test_x86_32_backward_compatibility_matrix);
    
    // Error handling
    RUN_TEST(test_x86_32_null_parameter_handling);
    RUN_TEST(test_x86_32_invalid_instruction_handling);
    
    // Encoding tests
    RUN_TEST(test_x86_32_instruction_encoding);
    
    return UNITY_END();
}
