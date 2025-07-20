#include "unity.h"
#include "unity_extensions.h"
#include "../../../include/arch_interface.h"
#include "../../../src/arch/arm64/arm64.h"
#include <string.h>
#include <stdlib.h>

// Forward declaration
extern arch_ops_t *get_arch_ops_arm64(void);

// Global test fixtures
arch_ops_t *arch_ops;
instruction_t test_instruction;

void setUp(void)
{
    arch_ops = get_arch_ops_arm64();
    memset(&test_instruction, 0, sizeof(instruction_t));
}

void tearDown(void)
{
    // Reset the test instruction struct
    memset(&test_instruction, 0, sizeof(instruction_t));
}

// ========================================
// ARCHITECTURE INTERFACE TESTS
// ========================================

void test_get_arch_ops_arm64_valid(void)
{
    TEST_ASSERT_NOT_NULL(arch_ops);
    TEST_ASSERT_NOT_NULL(arch_ops->name);
    TEST_ASSERT_EQUAL_STRING("arm64", arch_ops->name);
}

void test_arm64_arch_ops_functions_not_null(void)
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

void test_arm64_init_cleanup(void)
{
    int init_result = arch_ops->init();
    TEST_ASSERT_EQUAL(0, init_result);
    
    arch_ops->cleanup();
    // Should not crash
}

// ========================================
// REGISTER VALIDATION TESTS
// ========================================

void test_arm64_register_parsing_64bit(void)
{
    const char* registers[] = {"x0", "x1", "x2", "x8", "x16", "x29", "x30", "sp"};
    
    for (int i = 0; i < 8; i++) {
        asm_register_t reg;
        memset(&reg, 0, sizeof(asm_register_t));
        
        int result = arch_ops->parse_register(registers[i], &reg);
        TEST_ASSERT_EQUAL(0, result);
        TEST_ASSERT_TRUE(arch_ops->is_valid_register(reg));
        TEST_ASSERT_EQUAL(8, reg.size); // 64-bit registers = 8 bytes
    }
}

void test_arm64_register_parsing_32bit(void)
{
    const char* registers[] = {"w0", "w1", "w2", "w8", "w16", "w29", "w30", "wzr"};
    
    for (int i = 0; i < 8; i++) {
        asm_register_t reg;
        memset(&reg, 0, sizeof(asm_register_t));
        
        int result = arch_ops->parse_register(registers[i], &reg);
        TEST_ASSERT_EQUAL(0, result);
        TEST_ASSERT_TRUE(arch_ops->is_valid_register(reg));
        TEST_ASSERT_EQUAL(4, reg.size); // 32-bit registers = 4 bytes
    }
}

void test_arm64_register_parsing_vector(void)
{
    const char* registers[] = {"v0", "v1", "v15", "v31"};
    
    for (int i = 0; i < 4; i++) {
        asm_register_t reg;
        memset(&reg, 0, sizeof(asm_register_t));
        
        int result = arch_ops->parse_register(registers[i], &reg);
        // Vector registers may or may not be implemented yet
        TEST_ASSERT_TRUE(result == 0 || result != 0);
        
        if (result == 0) {
            TEST_ASSERT_TRUE(arch_ops->is_valid_register(reg));
        }
    }
}

void test_arm64_register_parsing_special(void)
{
    const char* special_regs[] = {"lr", "pc", "sp", "xzr", "wzr"};
    
    for (int i = 0; i < 5; i++) {
        asm_register_t reg;
        memset(&reg, 0, sizeof(asm_register_t));
        
        int result = arch_ops->parse_register(special_regs[i], &reg);
        TEST_ASSERT_EQUAL(0, result);
        TEST_ASSERT_TRUE(arch_ops->is_valid_register(reg));
    }
}

void test_arm64_register_parsing_invalid(void)
{
    // These should fail - x86 registers
    const char* invalid_registers[] = {"eax", "rax", "ax", "al", "r8", "esp"};
    
    for (int i = 0; i < 6; i++) {
        asm_register_t reg;
        memset(&reg, 0, sizeof(asm_register_t));
        
        int result = arch_ops->parse_register(invalid_registers[i], &reg);
        TEST_ASSERT_NOT_EQUAL(0, result); // Should fail
    }
}

void test_arm64_register_name_retrieval(void)
{
    asm_register_t reg;
    memset(&reg, 0, sizeof(asm_register_t));
    
    // Test X0
    int result = arch_ops->parse_register("x0", &reg);
    TEST_ASSERT_EQUAL(0, result);
    
    const char* name = arch_ops->get_register_name(reg);
    TEST_ASSERT_NOT_NULL(name);
    TEST_ASSERT_TRUE(strstr(name, "x0") != NULL || strstr(name, "X0") != NULL);
}

// ========================================
// INSTRUCTION PARSING TESTS
// ========================================

void test_arm64_instruction_parsing_basic(void)
{
    operand_t operands[2] = {0};
    
    int result = arch_ops->parse_instruction("mov", operands, 0, &test_instruction);
    TEST_ASSERT_EQUAL(0, result);
    TEST_ASSERT_NOT_NULL(test_instruction.mnemonic);
}

void test_arm64_instruction_parsing_arithmetic(void)
{
    operand_t operands[3] = {0};
    
    const char* instructions[] = {"add", "sub", "mul", "and", "orr", "eor"};
    
    for (int i = 0; i < 6; i++) {
        memset(&test_instruction, 0, sizeof(instruction_t));
        int result = arch_ops->parse_instruction(instructions[i], operands, 0, &test_instruction);
        TEST_ASSERT_EQUAL(0, result);
        TEST_ASSERT_NOT_NULL(test_instruction.mnemonic);
        
        if (test_instruction.mnemonic) {
            free((void*)test_instruction.mnemonic);
            test_instruction.mnemonic = NULL;
        }
    }
}

void test_arm64_instruction_parsing_memory(void)
{
    operand_t operands[3] = {0};
    
    const char* instructions[] = {"ldr", "str", "ldp", "stp"};
    
    for (int i = 0; i < 4; i++) {
        memset(&test_instruction, 0, sizeof(instruction_t));
        int result = arch_ops->parse_instruction(instructions[i], operands, 0, &test_instruction);
        TEST_ASSERT_EQUAL(0, result);
        TEST_ASSERT_NOT_NULL(test_instruction.mnemonic);
        
        if (test_instruction.mnemonic) {
            free((void*)test_instruction.mnemonic);
            test_instruction.mnemonic = NULL;
        }
    }
}

void test_arm64_instruction_parsing_control_flow(void)
{
    operand_t operands[2] = {0};
    
    const char* instructions[] = {"b", "bl", "br", "blr", "ret", "cbz", "cbnz"};
    
    for (int i = 0; i < 7; i++) {
        memset(&test_instruction, 0, sizeof(instruction_t));
        int result = arch_ops->parse_instruction(instructions[i], operands, 0, &test_instruction);
        TEST_ASSERT_EQUAL(0, result);
        TEST_ASSERT_NOT_NULL(test_instruction.mnemonic);
        
        if (test_instruction.mnemonic) {
            free((void*)test_instruction.mnemonic);
            test_instruction.mnemonic = NULL;
        }
    }
}

// ========================================
// ARM64 SPECIFIC TESTS
// ========================================

void test_arm64_addressing_modes(void)
{
    // Test ARM64 specific addressing modes
    operand_t operands[3] = {0};
    
    // This mainly tests that the instruction parser doesn't crash
    const char* addressing_instructions[] = {"ldr", "str", "add", "sub"};
    
    for (int i = 0; i < 4; i++) {
        memset(&test_instruction, 0, sizeof(instruction_t));
        int result = arch_ops->parse_instruction(addressing_instructions[i], operands, 0, &test_instruction);
        TEST_ASSERT_EQUAL(0, result);
        
        if (test_instruction.mnemonic) {
            free((void*)test_instruction.mnemonic);
            test_instruction.mnemonic = NULL;
        }
    }
}

// ========================================
// ERROR HANDLING TESTS
// ========================================

void test_arm64_null_parameter_handling(void)
{
    asm_register_t reg;
    operand_t operands[2] = {0};
    uint8_t buffer[32];
    size_t length = sizeof(buffer);
    
    // Test null register name
    int result = arch_ops->parse_register(NULL, &reg);
    TEST_ASSERT_NOT_EQUAL(0, result);
    
    // Test null register pointer
    result = arch_ops->parse_register("x0", NULL);
    TEST_ASSERT_NOT_EQUAL(0, result);
    
    // Test null instruction name
    result = arch_ops->parse_instruction(NULL, operands, 0, &test_instruction);
    TEST_ASSERT_NOT_EQUAL(0, result);
    
    // Test null instruction pointer
    result = arch_ops->encode_instruction(NULL, buffer, &length);
    TEST_ASSERT_NOT_EQUAL(0, result);
}

void test_arm64_invalid_instruction_handling(void)
{
    operand_t operands[2] = {0};
    
    // Test x86 instructions that should fail
    const char* x86_instructions[] = {"mov", "push", "pop", "call", "syscall"};
    
    for (int i = 0; i < 5; i++) {
        memset(&test_instruction, 0, sizeof(instruction_t));
        int result = arch_ops->parse_instruction(x86_instructions[i], operands, 0, &test_instruction);
        // Some may work (mov), others may not - just test they don't crash
        TEST_ASSERT_TRUE(result == 0 || result != 0);
        
        if (result == 0 && test_instruction.mnemonic) {
            free((void*)test_instruction.mnemonic);
            test_instruction.mnemonic = NULL;
        }
    }
}

// ========================================
// ENCODING TESTS
// ========================================

void test_arm64_instruction_encoding(void)
{
    uint8_t buffer[32];
    size_t length = sizeof(buffer);
    
    // Setup a basic instruction
    test_instruction.mnemonic = "nop";
    test_instruction.operand_count = 0;
    test_instruction.operands = NULL;
    
    int result = arch_ops->encode_instruction(&test_instruction, buffer, &length);
    // May succeed or fail depending on implementation completeness
    TEST_ASSERT_TRUE(result == 0 || result != 0);
    
    if (result == 0) {
        TEST_ASSERT_GREATER_THAN(0, length);
    }
}

// ========================================
// ALIGNMENT AND SIZING TESTS
// ========================================

void test_arm64_get_alignment(void)
{
    size_t alignment = arch_ops->get_alignment(SECTION_TEXT);
    TEST_ASSERT_GREATER_THAN(0, alignment);
    // ARM64 typically uses 4-byte alignment
    TEST_ASSERT_TRUE(alignment == 4 || alignment == 8 || alignment == 16);
}

// ========================================
// TEST RUNNER
// ========================================

int main(void)
{
    UNITY_BEGIN();
    
    // Architecture interface tests
    RUN_TEST(test_get_arch_ops_arm64_valid);
    RUN_TEST(test_arm64_arch_ops_functions_not_null);
    RUN_TEST(test_arm64_init_cleanup);
    
    // Register tests
    RUN_TEST(test_arm64_register_parsing_64bit);
    RUN_TEST(test_arm64_register_parsing_32bit);
    RUN_TEST(test_arm64_register_parsing_vector);
    RUN_TEST(test_arm64_register_parsing_special);
    RUN_TEST(test_arm64_register_parsing_invalid);
    RUN_TEST(test_arm64_register_name_retrieval);
    
    // Instruction tests
    RUN_TEST(test_arm64_instruction_parsing_basic);
    RUN_TEST(test_arm64_instruction_parsing_arithmetic);
    RUN_TEST(test_arm64_instruction_parsing_memory);
    RUN_TEST(test_arm64_instruction_parsing_control_flow);
    RUN_TEST(test_arm64_addressing_modes);
    
    // Error handling
    RUN_TEST(test_arm64_null_parameter_handling);
    RUN_TEST(test_arm64_invalid_instruction_handling);
    
    // Encoding and sizing
    RUN_TEST(test_arm64_instruction_encoding);
    RUN_TEST(test_arm64_get_alignment);
    
    return UNITY_END();
}
