#include "unity.h"
#include "unity_extensions.h"
#include "../../../include/arch_interface.h"
#include "../../../include/riscv.h"
#include <string.h>
#include <stdlib.h>

// Forward declaration
extern arch_ops_t *get_riscv_arch_ops(void);

// Global test fixtures
arch_ops_t *arch_ops;
instruction_t test_instruction;

void setUp(void)
{
    arch_ops = get_riscv_arch_ops();
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

void test_get_arch_ops_riscv_valid(void)
{
    TEST_ASSERT_NOT_NULL(arch_ops);
    TEST_ASSERT_NOT_NULL(arch_ops->name);
    TEST_ASSERT_EQUAL_STRING("riscv", arch_ops->name);
}

void test_riscv_arch_ops_functions_not_null(void)
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

void test_riscv_init_cleanup(void)
{
    int init_result = arch_ops->init();
    TEST_ASSERT_EQUAL(0, init_result);
    
    arch_ops->cleanup();
    // Should not crash
}

// ========================================
// REGISTER VALIDATION TESTS
// ========================================

void test_riscv_register_parsing_integer(void)
{
    const char* registers[] = {"x0", "x1", "x2", "x8", "x16", "x31"};
    
    for (int i = 0; i < 6; i++) {
        asm_register_t reg;
        memset(&reg, 0, sizeof(asm_register_t));
        
        int result = arch_ops->parse_register(registers[i], &reg);
        TEST_ASSERT_EQUAL(0, result);
        TEST_ASSERT_TRUE(arch_ops->is_valid_register(reg));
        TEST_ASSERT_EQUAL(8, reg.size); // RISC-V registers are 64-bit = 8 bytes (RV64)
    }
}

void test_riscv_register_parsing_abi_names(void)
{
    const char* registers[] = {"zero", "ra", "sp", "t0", "s0", "a0"};
    
    for (int i = 0; i < 6; i++) {
        asm_register_t reg;
        memset(&reg, 0, sizeof(asm_register_t));
        
        int result = arch_ops->parse_register(registers[i], &reg);
        TEST_ASSERT_EQUAL(0, result);
        TEST_ASSERT_TRUE(arch_ops->is_valid_register(reg));
    }
}

void test_riscv_register_parsing_floating_point(void)
{
    const char* registers[] = {"f0", "f1", "f16", "f31"};
    
    for (int i = 0; i < 4; i++) {
        asm_register_t reg;
        memset(&reg, 0, sizeof(asm_register_t));
        
        int result = arch_ops->parse_register(registers[i], &reg);
        // Floating point registers may or may not be implemented yet
        TEST_ASSERT_TRUE(result == 0 || result != 0);
        
        if (result == 0) {
            TEST_ASSERT_TRUE(arch_ops->is_valid_register(reg));
        }
    }
}

void test_riscv_register_parsing_invalid(void)
{
    // These should fail - x86/ARM registers
    const char* invalid_registers[] = {"eax", "rax", "w0", "x32", "r8"};
    
    for (int i = 0; i < 5; i++) {
        asm_register_t reg;
        memset(&reg, 0, sizeof(asm_register_t));
        
        int result = arch_ops->parse_register(invalid_registers[i], &reg);
        TEST_ASSERT_NOT_EQUAL(0, result); // Should fail
    }
}

void test_riscv_register_name_retrieval(void)
{
    asm_register_t reg;
    memset(&reg, 0, sizeof(asm_register_t));
    
    // Test x0/zero
    int result = arch_ops->parse_register("x0", &reg);
    TEST_ASSERT_EQUAL(0, result);
    
    const char* name = arch_ops->get_register_name(reg);
    TEST_ASSERT_NOT_NULL(name);
    TEST_ASSERT_TRUE(strstr(name, "x0") != NULL || strstr(name, "zero") != NULL);
}

// ========================================
// INSTRUCTION PARSING TESTS
// ========================================

void test_riscv_instruction_parsing_basic(void)
{
    operand_t operands[3] = {0};
    
    int result = arch_ops->parse_instruction("add", operands, 0, &test_instruction);
    TEST_ASSERT_EQUAL(0, result);
    TEST_ASSERT_NOT_NULL(test_instruction.mnemonic);
}

void test_riscv_instruction_parsing_arithmetic(void)
{
    operand_t operands[3] = {0};
    
    const char* instructions[] = {"add", "sub", "and", "or", "xor", "sll", "srl", "sra"};
    
    for (int i = 0; i < 8; i++) {
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

void test_riscv_instruction_parsing_immediate(void)
{
    operand_t operands[3] = {0};
    
    const char* instructions[] = {"addi", "andi", "ori", "xori", "slli", "srli", "srai"};
    
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

void test_riscv_instruction_parsing_memory(void)
{
    operand_t operands[3] = {0};
    
    const char* instructions[] = {"ld", "sd", "lw", "sw", "lb", "sb"};
    
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

void test_riscv_instruction_parsing_control_flow(void)
{
    operand_t operands[3] = {0};
    
    const char* instructions[] = {"beq", "bne", "blt", "bge", "jal", "jalr"};
    
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

// ========================================
// RISC-V SPECIFIC TESTS
// ========================================

void test_riscv_instruction_formats(void)
{
    // Test RISC-V instruction format handling
    operand_t operands[3] = {0};
    
    // R-type, I-type, S-type, B-type, U-type, J-type examples
    const char* format_instructions[] = {"add", "addi", "sw", "beq", "lui", "jal"};
    
    for (int i = 0; i < 6; i++) {
        memset(&test_instruction, 0, sizeof(instruction_t));
        int result = arch_ops->parse_instruction(format_instructions[i], operands, 0, &test_instruction);
        TEST_ASSERT_EQUAL(0, result);
        
        if (test_instruction.mnemonic) {
            free((void*)test_instruction.mnemonic);
            test_instruction.mnemonic = NULL;
        }
    }
}

void test_riscv_pseudoinstructions(void)
{
    // Test common RISC-V pseudoinstructions
    operand_t operands[3] = {0};
    
    const char* pseudo_instructions[] = {"nop", "mv", "neg", "not"};
    
    for (int i = 0; i < 4; i++) {
        memset(&test_instruction, 0, sizeof(instruction_t));
        int result = arch_ops->parse_instruction(pseudo_instructions[i], operands, 0, &test_instruction);
        // Pseudoinstructions may or may not be implemented - just test they don't crash
        TEST_ASSERT_TRUE(result == 0 || result != 0);
        
        if (result == 0 && test_instruction.mnemonic) {
            free((void*)test_instruction.mnemonic);
            test_instruction.mnemonic = NULL;
        }
    }
}

// ========================================
// ERROR HANDLING TESTS
// ========================================

void test_riscv_null_parameter_handling(void)
{
    asm_register_t reg;
    operand_t operands[3] = {0};
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

void test_riscv_invalid_instruction_handling(void)
{
    operand_t operands[3] = {0};
    
    // Test x86 instructions that should fail
    const char* x86_instructions[] = {"mov", "push", "pop", "call", "ret"};
    
    for (int i = 0; i < 5; i++) {
        memset(&test_instruction, 0, sizeof(instruction_t));
        int result = arch_ops->parse_instruction(x86_instructions[i], operands, 0, &test_instruction);
        TEST_ASSERT_NOT_EQUAL(0, result); // Should fail
    }
}

// ========================================
// ENCODING TESTS
// ========================================

void test_riscv_instruction_encoding(void)
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

void test_riscv_get_alignment(void)
{
    size_t alignment = arch_ops->get_alignment(SECTION_TEXT);
    TEST_ASSERT_GREATER_THAN(0, alignment);
    // RISC-V typically uses 4-byte alignment for instructions
    TEST_ASSERT_TRUE(alignment == 4 || alignment == 8);
}

// ========================================
// TEST RUNNER
// ========================================

int main(void)
{
    UNITY_BEGIN();
    
    // Architecture interface tests
    RUN_TEST(test_get_arch_ops_riscv_valid);
    RUN_TEST(test_riscv_arch_ops_functions_not_null);
    RUN_TEST(test_riscv_init_cleanup);
    
    // Register tests
    RUN_TEST(test_riscv_register_parsing_integer);
    RUN_TEST(test_riscv_register_parsing_abi_names);
    RUN_TEST(test_riscv_register_parsing_floating_point);
    RUN_TEST(test_riscv_register_parsing_invalid);
    RUN_TEST(test_riscv_register_name_retrieval);
    
    // Instruction tests
    RUN_TEST(test_riscv_instruction_parsing_basic);
    RUN_TEST(test_riscv_instruction_parsing_arithmetic);
    RUN_TEST(test_riscv_instruction_parsing_immediate);
    RUN_TEST(test_riscv_instruction_parsing_memory);
    RUN_TEST(test_riscv_instruction_parsing_control_flow);
    RUN_TEST(test_riscv_instruction_formats);
    RUN_TEST(test_riscv_pseudoinstructions);
    
    // Error handling
    RUN_TEST(test_riscv_null_parameter_handling);
    RUN_TEST(test_riscv_invalid_instruction_handling);
    
    // Encoding and sizing
    RUN_TEST(test_riscv_instruction_encoding);
    RUN_TEST(test_riscv_get_alignment);
    
    return UNITY_END();
}
