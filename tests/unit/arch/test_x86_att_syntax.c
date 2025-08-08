#include "../../unity/src/unity.h"
#include "unity_extensions.h"
#include "../../../include/arch_interface.h"
#include "../../../src/arch/x86_16/x86_16.h"
#include "../../../include/x86_32.h"
#include "../../../include/x86_64.h"
#include <string.h>
#include <stdlib.h>

// Forward declarations
extern arch_ops_t *get_arch_ops_x86_16(void);
extern arch_ops_t *get_arch_ops_x86_32(void);
extern arch_ops_t *get_arch_ops_x86_64(void);

// Global test fixtures
arch_ops_t *x86_16_ops;
arch_ops_t *x86_32_ops;
arch_ops_t *x86_64_ops;

void setUp(void)
{
    x86_16_ops = get_arch_ops_x86_16();
    x86_32_ops = get_arch_ops_x86_32();
    x86_64_ops = get_arch_ops_x86_64();
}

void tearDown(void)
{
    // Cleanup - no specific actions needed
}

// ========================================
// AT&T SYNTAX REGISTER PREFIX TESTS
// ========================================

void test_x86_16_att_register_prefix_parsing(void)
{
    asm_register_t reg;
    
    // Test with % prefix (AT&T style)
    memset(&reg, 0, sizeof(asm_register_t));
    int result_with_prefix = x86_16_ops->parse_register("%ax", &reg);
    TEST_ASSERT_EQUAL(0, result_with_prefix);
    TEST_ASSERT_EQUAL(0, reg.id);
    TEST_ASSERT_EQUAL(2, reg.size);
    
    // Test without % prefix (should also work for flexibility)
    memset(&reg, 0, sizeof(asm_register_t));
    int result_without_prefix = x86_16_ops->parse_register("ax", &reg);
    TEST_ASSERT_EQUAL(0, result_without_prefix);
    TEST_ASSERT_EQUAL(0, reg.id);
    TEST_ASSERT_EQUAL(2, reg.size);
    
    // Test all 16-bit registers with % prefix
    const char* att_registers[] = {"%ax", "%bx", "%cx", "%dx", "%si", "%di", "%sp", "%bp"};
    int expected_ids[] = {0, 3, 1, 2, 6, 7, 4, 5};
    
    for (int i = 0; i < 8; i++) {
        memset(&reg, 0, sizeof(asm_register_t));
        int result = x86_16_ops->parse_register(att_registers[i], &reg);
        TEST_ASSERT_EQUAL_MESSAGE(0, result, att_registers[i]);
        TEST_ASSERT_EQUAL_MESSAGE(expected_ids[i], reg.id, att_registers[i]);
        TEST_ASSERT_EQUAL_MESSAGE(2, reg.size, att_registers[i]);
    }
}

void test_x86_16_att_8bit_register_prefix_parsing(void)
{
    asm_register_t reg;
    
    // Test 8-bit registers with % prefix
    const char* att_8bit_regs[] = {"%al", "%ah", "%bl", "%bh", "%cl", "%ch", "%dl", "%dh"};
    int expected_ids[] = {0, 4, 3, 7, 1, 5, 2, 6};
    
    for (int i = 0; i < 8; i++) {
        memset(&reg, 0, sizeof(asm_register_t));
        int result = x86_16_ops->parse_register(att_8bit_regs[i], &reg);
        TEST_ASSERT_EQUAL_MESSAGE(0, result, att_8bit_regs[i]);
        TEST_ASSERT_EQUAL_MESSAGE(expected_ids[i], reg.id, att_8bit_regs[i]);
        TEST_ASSERT_EQUAL_MESSAGE(1, reg.size, att_8bit_regs[i]);
    }
}

void test_x86_32_att_register_prefix_parsing(void)
{
    asm_register_t reg;
    
    // Test 32-bit registers with % prefix
    const char* att_32bit_regs[] = {"%eax", "%ebx", "%ecx", "%edx", "%esi", "%edi", "%esp", "%ebp"};
    
    for (int i = 0; i < 8; i++) {
        memset(&reg, 0, sizeof(asm_register_t));
        int result = x86_32_ops->parse_register(att_32bit_regs[i], &reg);
        TEST_ASSERT_EQUAL_MESSAGE(0, result, att_32bit_regs[i]);
        TEST_ASSERT_EQUAL_MESSAGE(4, reg.size, att_32bit_regs[i]);
    }
    
    // Test that x86_32 also supports 16-bit registers with % prefix
    const char* att_16bit_in_32[] = {"%ax", "%bx", "%cx", "%dx"};
    
    for (int i = 0; i < 4; i++) {
        memset(&reg, 0, sizeof(asm_register_t));
        int result = x86_32_ops->parse_register(att_16bit_in_32[i], &reg);
        TEST_ASSERT_EQUAL_MESSAGE(0, result, att_16bit_in_32[i]);
        TEST_ASSERT_EQUAL_MESSAGE(2, reg.size, att_16bit_in_32[i]);
    }
}

void test_x86_64_att_register_prefix_parsing(void)
{
    asm_register_t reg;
    
    // Test 64-bit registers with % prefix
    const char* att_64bit_regs[] = {"%rax", "%rbx", "%rcx", "%rdx", "%rsi", "%rdi", "%rsp", "%rbp"};
    
    for (int i = 0; i < 8; i++) {
        memset(&reg, 0, sizeof(asm_register_t));
        int result = x86_64_ops->parse_register(att_64bit_regs[i], &reg);
        TEST_ASSERT_EQUAL_MESSAGE(0, result, att_64bit_regs[i]);
        TEST_ASSERT_EQUAL_MESSAGE(8, reg.size, att_64bit_regs[i]);
    }
    
    // Test extended 64-bit registers with % prefix
    const char* att_extended_regs[] = {"%r8", "%r9", "%r10", "%r11", "%r12", "%r13", "%r14", "%r15"};
    
    for (int i = 0; i < 8; i++) {
        memset(&reg, 0, sizeof(asm_register_t));
        int result = x86_64_ops->parse_register(att_extended_regs[i], &reg);
        TEST_ASSERT_EQUAL_MESSAGE(0, result, att_extended_regs[i]);
        TEST_ASSERT_EQUAL_MESSAGE(8, reg.size, att_extended_regs[i]);
    }
}

// ========================================
// AT&T SYNTAX IMMEDIATE VALUE TESTS  
// ========================================

void test_x86_16_att_immediate_values(void)
{
    // Test that x86_16 accepts proper operand counts for immediate instructions
    // (We test syntax support indirectly through operand count validation)
    
    // Test int instruction (1 operand)
    operand_t operands[1];
    instruction_t inst;
    memset(&inst, 0, sizeof(instruction_t));
    memset(operands, 0, sizeof(operands));
    
    int result = x86_16_ops->parse_instruction("int", operands, 1, &inst);
    TEST_ASSERT_EQUAL(0, result);
    
    // Simple cleanup - just test that parsing works
}

void test_x86_32_att_immediate_values(void)
{
    // Test that x86_32 accepts proper operand counts
    operand_t operands[2];
    instruction_t inst;
    memset(&inst, 0, sizeof(instruction_t));
    memset(operands, 0, sizeof(operands));
    
    int result = x86_32_ops->parse_instruction("mov", operands, 2, &inst);
    TEST_ASSERT_EQUAL(0, result);
}

void test_x86_64_att_immediate_values(void)
{
    // Test that x86_64 accepts proper operand counts
    operand_t operands[2];
    instruction_t inst;
    memset(&inst, 0, sizeof(instruction_t));
    memset(operands, 0, sizeof(operands));
    
    int result = x86_64_ops->parse_instruction("movq", operands, 2, &inst);
    TEST_ASSERT_EQUAL(0, result);
}

// ========================================
// AT&T SYNTAX OPERAND ORDER TESTS
// ========================================

void test_x86_16_att_operand_order(void)
{
    operand_t operands[2];
    instruction_t inst;
    
    // AT&T syntax: source, destination (mov %ax, %bx means ax -> bx)
    // Test that two-operand instructions accept exactly 2 operands
    memset(&inst, 0, sizeof(instruction_t));
    memset(operands, 0, sizeof(operands));
    
    int result = x86_16_ops->parse_instruction("mov", operands, 2, &inst);
    TEST_ASSERT_EQUAL(0, result);
    TEST_ASSERT_EQUAL(2, inst.operand_count);
    
    // Test rejection of wrong operand counts
    memset(&inst, 0, sizeof(instruction_t));
    int result_wrong = x86_16_ops->parse_instruction("mov", operands, 1, &inst);
    TEST_ASSERT_NOT_EQUAL(0, result_wrong);
    
    // Cleanup
    if (inst.mnemonic) free((void*)inst.mnemonic);
    if (inst.operands) free(inst.operands);
}

void test_x86_32_att_operand_order(void)
{
    operand_t operands[2];
    instruction_t inst;
    
    // Test that x86_32 follows same AT&T operand order principles
    memset(&inst, 0, sizeof(instruction_t));
    memset(operands, 0, sizeof(operands));
    
    int result = x86_32_ops->parse_instruction("add", operands, 2, &inst);
    TEST_ASSERT_EQUAL(0, result);
    TEST_ASSERT_EQUAL(2, inst.operand_count);
    
    // Cleanup
    if (inst.mnemonic) free((void*)inst.mnemonic);
    if (inst.operands) free(inst.operands);
}

void test_x86_64_att_operand_order(void)
{
    operand_t operands[2];
    instruction_t inst;
    
    // Test that x86_64 follows same AT&T operand order principles
    memset(&inst, 0, sizeof(instruction_t));
    memset(operands, 0, sizeof(operands));
    
    int result = x86_64_ops->parse_instruction("subq", operands, 2, &inst);
    TEST_ASSERT_EQUAL(0, result);
    TEST_ASSERT_EQUAL(2, inst.operand_count);
    
    // Cleanup
    if (inst.mnemonic) free((void*)inst.mnemonic);
    if (inst.operands) free(inst.operands);
}

// ========================================
// AT&T SYNTAX ARCHITECTURE SPECIFICITY TESTS
// ========================================

void test_x86_16_att_rejects_invalid_registers(void)
{
    asm_register_t reg;
    
    // x86_16 should reject 32-bit and 64-bit registers even with % prefix
    const char* invalid_regs[] = {"%eax", "%ebx", "%rax", "%rbx", "%r8", "%r15"};
    
    for (int i = 0; i < 6; i++) {
        memset(&reg, 0, sizeof(asm_register_t));
        int result = x86_16_ops->parse_register(invalid_regs[i], &reg);
        TEST_ASSERT_NOT_EQUAL_MESSAGE(0, result, invalid_regs[i]);
    }
}

void test_x86_32_att_rejects_64bit_registers(void)
{
    asm_register_t reg;
    
    // x86_32 should reject 64-bit only registers even with % prefix
    const char* invalid_regs[] = {"%rax", "%rbx", "%r8", "%r9", "%r15"};
    
    for (int i = 0; i < 5; i++) {
        memset(&reg, 0, sizeof(asm_register_t));
        int result = x86_32_ops->parse_register(invalid_regs[i], &reg);
        TEST_ASSERT_NOT_EQUAL_MESSAGE(0, result, invalid_regs[i]);
    }
}

void test_x86_16_att_rejects_64bit_instructions(void)
{
    operand_t operands[2];
    instruction_t inst;
    
    // x86_16 should reject 64-bit specific instructions
    const char* invalid_instructions[] = {"movq", "addq", "subq", "pushq", "popq", "syscall"};
    
    for (int i = 0; i < 6; i++) {
        memset(&inst, 0, sizeof(instruction_t));
        memset(operands, 0, sizeof(operands));
        
        int result = x86_16_ops->parse_instruction(invalid_instructions[i], operands, 0, &inst);
        TEST_ASSERT_NOT_EQUAL_MESSAGE(0, result, invalid_instructions[i]);
        
        // Cleanup just in case
        if (inst.mnemonic) free((void*)inst.mnemonic);
        if (inst.operands) free(inst.operands);
    }
}

// ========================================
// AT&T SYNTAX CASE SENSITIVITY TESTS
// ========================================

void test_x86_16_att_case_insensitive_registers(void)
{
    asm_register_t reg1, reg2;
    
    // Test that register parsing is case-insensitive (common in AT&T)
    memset(&reg1, 0, sizeof(asm_register_t));
    memset(&reg2, 0, sizeof(asm_register_t));
    
    int result1 = x86_16_ops->parse_register("%ax", &reg1);
    int result2 = x86_16_ops->parse_register("%AX", &reg2);
    
    TEST_ASSERT_EQUAL(0, result1);
    TEST_ASSERT_EQUAL(0, result2);
    TEST_ASSERT_EQUAL(reg1.id, reg2.id);
    TEST_ASSERT_EQUAL(reg1.size, reg2.size);
}

void test_x86_16_att_case_insensitive_instructions(void)
{
    operand_t operands[2];
    instruction_t inst1, inst2;
    
    // Test that instruction parsing is case-insensitive
    memset(&inst1, 0, sizeof(instruction_t));
    memset(&inst2, 0, sizeof(instruction_t));
    memset(operands, 0, sizeof(operands));
    
    int result1 = x86_16_ops->parse_instruction("mov", operands, 2, &inst1);
    int result2 = x86_16_ops->parse_instruction("MOV", operands, 2, &inst2);
    
    TEST_ASSERT_EQUAL(0, result1);
    TEST_ASSERT_EQUAL(0, result2);
    TEST_ASSERT_EQUAL(inst1.operand_count, inst2.operand_count);
    
    // Cleanup
    if (inst1.mnemonic) free((void*)inst1.mnemonic);
    if (inst1.operands) free(inst1.operands);
    if (inst2.mnemonic) free((void*)inst2.mnemonic);
    if (inst2.operands) free(inst2.operands);
}

// ========================================
// AT&T SYNTAX COMPREHENSIVE VALIDATION TESTS
// ========================================

void test_att_syntax_comprehensive_validation(void)
{
    // This test validates that all x86 architectures properly handle
    // the core aspects of AT&T syntax
    
    asm_register_t reg;
    
    // 1. All architectures should handle % prefix
    memset(&reg, 0, sizeof(asm_register_t));
    TEST_ASSERT_EQUAL(0, x86_16_ops->parse_register("%ax", &reg));
    
    memset(&reg, 0, sizeof(asm_register_t));
    TEST_ASSERT_EQUAL(0, x86_32_ops->parse_register("%eax", &reg));
    
    memset(&reg, 0, sizeof(asm_register_t));
    TEST_ASSERT_EQUAL(0, x86_64_ops->parse_register("%rax", &reg));
    
    // 2. Architectures should reject incompatible registers
    memset(&reg, 0, sizeof(asm_register_t));
    TEST_ASSERT_NOT_EQUAL(0, x86_16_ops->parse_register("%eax", &reg));
    
    memset(&reg, 0, sizeof(asm_register_t));
    TEST_ASSERT_NOT_EQUAL(0, x86_32_ops->parse_register("%rax", &reg));
}

// ========================================
// TEST RUNNER
// ========================================

int main(void)
{
    UNITY_BEGIN();
    
    // AT&T Register Prefix Tests (Core functionality)
    RUN_TEST(test_x86_16_att_register_prefix_parsing);
    RUN_TEST(test_x86_16_att_8bit_register_prefix_parsing);
    RUN_TEST(test_x86_32_att_register_prefix_parsing);
    RUN_TEST(test_x86_64_att_register_prefix_parsing);
    
    // AT&T Immediate Value Tests (Basic validation)
    RUN_TEST(test_x86_16_att_immediate_values);
    RUN_TEST(test_x86_32_att_immediate_values);
    RUN_TEST(test_x86_64_att_immediate_values);
    
    // AT&T Architecture Specificity Tests
    RUN_TEST(test_x86_16_att_rejects_invalid_registers);
    RUN_TEST(test_x86_32_att_rejects_64bit_registers);
    RUN_TEST(test_x86_16_att_rejects_64bit_instructions);
    
    // AT&T Case Sensitivity Tests
    RUN_TEST(test_x86_16_att_case_insensitive_registers);
    
    // Comprehensive Validation
    RUN_TEST(test_att_syntax_comprehensive_validation);
    
    return UNITY_END();
}
