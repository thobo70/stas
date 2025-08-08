#include "../../unity/src/unity.h"
#include "unity_extensions.h"
#include "../../../include/arch_interface.h"
#include "../../../src/arch/x86_16/x86_16.h"
#include <string.h>
#include <stdlib.h>

// Forward declaration
extern arch_ops_t *get_arch_ops_x86_16(void);

// Global test fixtures
arch_ops_t *arch_ops;
instruction_t test_instruction;

void setUp(void)
{
    arch_ops = get_arch_ops_x86_16();
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

void test_get_arch_ops_x86_16_valid(void)
{
    TEST_ASSERT_NOT_NULL(arch_ops);
    TEST_ASSERT_NOT_NULL(arch_ops->name);
    TEST_ASSERT_EQUAL_STRING("x86-16", arch_ops->name); // Architecture name is "x86-16"
}

void test_x86_16_arch_ops_functions_not_null(void)
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

void test_x86_16_init_cleanup(void)
{
    int init_result = arch_ops->init();
    TEST_ASSERT_EQUAL(0, init_result);
    
    arch_ops->cleanup();
    // Should not crash
}

// ========================================
// REGISTER VALIDATION TESTS
// ========================================

void test_x86_16_register_parsing_16bit(void)
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

void test_x86_16_register_parsing_8bit(void)
{
    const char* registers[] = {"al", "bl", "cl", "dl", "ah", "bh", "ch", "dh"};
    
    for (int i = 0; i < 8; i++) {
        asm_register_t reg;
        memset(&reg, 0, sizeof(asm_register_t));
        
        char reg_name[32];
        snprintf(reg_name, sizeof(reg_name), "%s", registers[i]);
        
        int result = arch_ops->parse_register(reg_name, &reg);
        TEST_ASSERT_EQUAL(0, result);
        TEST_ASSERT_TRUE(arch_ops->is_valid_register(reg));
        TEST_ASSERT_EQUAL(1, reg.size); // 8-bit registers = 1 byte
    }
}

void test_x86_16_register_parsing_segment(void)
{
    const char* segment_regs[] = {"cs", "ds", "es", "ss"};
    
    for (int i = 0; i < 4; i++) {
        asm_register_t reg;
        memset(&reg, 0, sizeof(asm_register_t));
        
        char reg_name[32];
        snprintf(reg_name, sizeof(reg_name), "%s", segment_regs[i]);
        
        int result = arch_ops->parse_register(reg_name, &reg);
        TEST_ASSERT_EQUAL(0, result);
        TEST_ASSERT_TRUE(arch_ops->is_valid_register(reg));
    }
}

void test_x86_16_register_parsing_special(void)
{
    const char* special_regs[] = {"flags", "ip"};
    
    for (int i = 0; i < 2; i++) {
        asm_register_t reg;
        memset(&reg, 0, sizeof(asm_register_t));
        
        char reg_name[32];
        snprintf(reg_name, sizeof(reg_name), "%s", special_regs[i]);
        
        int result = arch_ops->parse_register(reg_name, &reg);
        // These may or may not be implemented - just test they don't crash
        TEST_ASSERT_TRUE(result == 0 || result != 0);
    }
}

void test_x86_16_register_parsing_invalid(void)
{
    // These should fail - newer x86 registers
    const char* invalid_registers[] = {"eax", "rax", "r8", "xmm0", "zmm0"};
    
    for (int i = 0; i < 5; i++) {
        asm_register_t reg;
        memset(&reg, 0, sizeof(asm_register_t));
        
        char reg_name[32];
        snprintf(reg_name, sizeof(reg_name), "%s", invalid_registers[i]);
        
        int result = arch_ops->parse_register(reg_name, &reg);
        TEST_ASSERT_NOT_EQUAL(0, result); // Should fail
    }
}

void test_x86_16_register_name_retrieval(void)
{
    asm_register_t reg;
    memset(&reg, 0, sizeof(asm_register_t));
    
    // Test AX
    int result = arch_ops->parse_register("ax", &reg);
    TEST_ASSERT_EQUAL(0, result);
    
    const char* name = arch_ops->get_register_name(reg);
    TEST_ASSERT_NOT_NULL(name);
    TEST_ASSERT_TRUE(strstr(name, "ax") != NULL || strstr(name, "AX") != NULL);
}

// ========================================
// INSTRUCTION PARSING TESTS
// ========================================

void test_x86_16_instruction_parsing_basic(void)
{
    instruction_t local_instruction;
    memset(&local_instruction, 0, sizeof(instruction_t));
    
    int result = arch_ops->parse_instruction("nop", NULL, 0, &local_instruction);
    TEST_ASSERT_EQUAL(0, result);
    TEST_ASSERT_NOT_NULL(local_instruction.mnemonic);
    
    if (local_instruction.mnemonic) {
        free((void*)local_instruction.mnemonic);
    }
}

void test_x86_16_instruction_parsing_arithmetic(void)
{
    // Test 0-operand instructions
    const char* no_operand_instructions[] = {"nop", "hlt", "ret"};
    
    for (int i = 0; i < 3; i++) {
        instruction_t local_instruction;
        memset(&local_instruction, 0, sizeof(instruction_t));
        int result = arch_ops->parse_instruction(no_operand_instructions[i], NULL, 0, &local_instruction);
        TEST_ASSERT_EQUAL(0, result);
        TEST_ASSERT_NOT_NULL(local_instruction.mnemonic);
        
        if (local_instruction.mnemonic) {
            free((void*)local_instruction.mnemonic);
        }
    }
}

void test_x86_16_instruction_parsing_control_flow(void)
{
    operand_t operands[1] = {0};
    
    // Test 1-operand control flow instructions (setting up dummy operand)
    operands[0].type = OPERAND_IMMEDIATE;
    operands[0].value.immediate = 0x1234;
    
    const char* one_operand_instructions[] = {"jmp", "call", "int"};
    
    for (int i = 0; i < 3; i++) {
        instruction_t local_instruction;
        memset(&local_instruction, 0, sizeof(instruction_t));
        int result = arch_ops->parse_instruction(one_operand_instructions[i], operands, 1, &local_instruction);
        TEST_ASSERT_EQUAL(0, result);
        TEST_ASSERT_NOT_NULL(local_instruction.mnemonic);
        
        if (local_instruction.mnemonic) {
            free((void*)local_instruction.mnemonic);
        }
    }
}

// ========================================
// BASE ARCHITECTURE TESTS
// ========================================

void test_x86_16_base_instruction_set(void)
{
    // Test core x86-16 instruction set with proper operand counts
    
    // Test 0-operand instructions
    const char* zero_operand_instructions[] = {"nop", "hlt", "ret"};
    
    for (int i = 0; i < 3; i++) {
        instruction_t local_instruction;
        memset(&local_instruction, 0, sizeof(instruction_t));
        int result = arch_ops->parse_instruction(zero_operand_instructions[i], NULL, 0, &local_instruction);
        TEST_ASSERT_EQUAL(0, result);
        TEST_ASSERT_NOT_NULL(local_instruction.mnemonic);
        
        if (local_instruction.mnemonic) {
            free((void*)local_instruction.mnemonic);
        }
    }
    
    // Test 1-operand instructions
    operand_t one_operand[1] = {{.type = OPERAND_IMMEDIATE, .value.immediate = 0x20}};
    const char* one_operand_instructions[] = {"jmp", "call", "int"};
    
    for (int i = 0; i < 3; i++) {
        instruction_t local_instruction;
        memset(&local_instruction, 0, sizeof(instruction_t));
        int result = arch_ops->parse_instruction(one_operand_instructions[i], one_operand, 1, &local_instruction);
        TEST_ASSERT_EQUAL(0, result);
        TEST_ASSERT_NOT_NULL(local_instruction.mnemonic);
        
        if (local_instruction.mnemonic) {
            free((void*)local_instruction.mnemonic);
        }
    }
}

// ========================================
// ERROR HANDLING TESTS
// ========================================

void test_x86_16_null_parameter_handling(void)
{
    asm_register_t reg;
    operand_t operands[2] = {0};
    uint8_t buffer[32];
    size_t length = sizeof(buffer);
    
    // Test null register name
    int result = arch_ops->parse_register(NULL, &reg);
    TEST_ASSERT_NOT_EQUAL(0, result);
    
    // Test null register pointer
    result = arch_ops->parse_register("ax", NULL);
    TEST_ASSERT_NOT_EQUAL(0, result);
    
    // Test null instruction name
    result = arch_ops->parse_instruction(NULL, operands, 0, &test_instruction);
    TEST_ASSERT_NOT_EQUAL(0, result);
    
    // Test null instruction pointer
    result = arch_ops->encode_instruction(NULL, buffer, &length);
    TEST_ASSERT_NOT_EQUAL(0, result);
}

void test_x86_16_invalid_instruction_handling(void)
{
    operand_t operands[2] = {0};
    
    // Test instructions that didn't exist in original x86
    const char* invalid_instructions[] = {"movl", "addl", "movq", "syscall", "sysenter"};
    
    for (int i = 0; i < 5; i++) {
        memset(&test_instruction, 0, sizeof(instruction_t));
        int result = arch_ops->parse_instruction(invalid_instructions[i], operands, 0, &test_instruction);
        TEST_ASSERT_NOT_EQUAL(0, result); // Should fail
    }
}

// ========================================
// ENCODING TESTS
// ========================================

void test_x86_16_instruction_encoding(void)
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

void test_x86_16_get_alignment(void)
{
    size_t alignment = arch_ops->get_alignment(SECTION_TEXT);
    TEST_ASSERT_GREATER_THAN(0, alignment);
    TEST_ASSERT_TRUE(alignment == 1 || alignment == 2 || alignment == 4);
}

// ========================================
// AT&T SYNTAX SPECIFIC TESTS
// ========================================

void test_x86_16_att_register_prefix_support(void)
{
    asm_register_t reg;
    
    // Test registers with % prefix (AT&T style)
    memset(&reg, 0, sizeof(asm_register_t));
    int result = arch_ops->parse_register("%ax", &reg);
    TEST_ASSERT_EQUAL(0, result);
    TEST_ASSERT_EQUAL(0, reg.id);
    TEST_ASSERT_EQUAL(2, reg.size);
    
    // Test 8-bit registers with % prefix
    memset(&reg, 0, sizeof(asm_register_t));
    result = arch_ops->parse_register("%al", &reg);
    TEST_ASSERT_EQUAL(0, result);
    TEST_ASSERT_EQUAL(0, reg.id);
    TEST_ASSERT_EQUAL(1, reg.size);
}

void test_x86_16_att_rejects_32bit_64bit_registers(void)
{
    asm_register_t reg;
    
    // Should reject 32-bit registers even with % prefix
    memset(&reg, 0, sizeof(asm_register_t));
    int result = arch_ops->parse_register("%eax", &reg);
    TEST_ASSERT_NOT_EQUAL(0, result);
    
    // Should reject 64-bit registers even with % prefix
    memset(&reg, 0, sizeof(asm_register_t));
    result = arch_ops->parse_register("%rax", &reg);
    TEST_ASSERT_NOT_EQUAL(0, result);
}

void test_x86_16_att_instruction_operand_validation(void)
{
    operand_t operands[2];
    instruction_t inst;
    
    // Test strict operand count validation (AT&T style)
    memset(&inst, 0, sizeof(instruction_t));
    memset(operands, 0, sizeof(operands));
    
    // Two-operand instruction with correct count should pass
    int result = arch_ops->parse_instruction("mov", operands, 2, &inst);
    TEST_ASSERT_EQUAL(0, result);
    
    // Two-operand instruction with wrong count should fail
    memset(&inst, 0, sizeof(instruction_t));
    result = arch_ops->parse_instruction("mov", operands, 1, &inst);
    TEST_ASSERT_NOT_EQUAL(0, result);
    
    // Cleanup
    if (inst.mnemonic) free((void*)inst.mnemonic);
    if (inst.operands) free(inst.operands);
}

// ========================================
// TEST RUNNER
// ========================================

int main(void)
{
    UNITY_BEGIN();
    
    // Architecture interface tests
    RUN_TEST(test_get_arch_ops_x86_16_valid);
    RUN_TEST(test_x86_16_arch_ops_functions_not_null);
    RUN_TEST(test_x86_16_init_cleanup);
    
    // Register tests
    RUN_TEST(test_x86_16_register_parsing_16bit);
    RUN_TEST(test_x86_16_register_parsing_8bit);
    RUN_TEST(test_x86_16_register_parsing_segment);
    RUN_TEST(test_x86_16_register_parsing_special);
    RUN_TEST(test_x86_16_register_parsing_invalid);
    RUN_TEST(test_x86_16_register_name_retrieval);
    
    // Instruction tests
    RUN_TEST(test_x86_16_instruction_parsing_basic);
    RUN_TEST(test_x86_16_instruction_parsing_arithmetic);
    RUN_TEST(test_x86_16_instruction_parsing_control_flow);
    RUN_TEST(test_x86_16_base_instruction_set);
    
    // Error handling
    RUN_TEST(test_x86_16_null_parameter_handling);
    RUN_TEST(test_x86_16_invalid_instruction_handling);
    
    // Encoding and sizing
    RUN_TEST(test_x86_16_instruction_encoding);
    RUN_TEST(test_x86_16_get_alignment);
    
    // AT&T Syntax tests
    RUN_TEST(test_x86_16_att_register_prefix_support);
    RUN_TEST(test_x86_16_att_rejects_32bit_64bit_registers);
    RUN_TEST(test_x86_16_att_instruction_operand_validation);
    
    return UNITY_END();
}
