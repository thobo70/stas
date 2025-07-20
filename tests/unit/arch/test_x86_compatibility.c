#include "unity.h"
#include "unity_extensions.h"
#include "../../../include/arch_interface.h"
#include "../../../include/x86_64.h"
#include "../../../include/x86_32.h"
#include "../../../include/x86_16.h"
#include <string.h>
#include <stdlib.h>

// Forward declarations
extern arch_ops_t *get_arch_ops_x86_64(void);
extern arch_ops_t *get_arch_ops_x86_32(void);
extern arch_ops_t *get_arch_ops_x86_16(void);

// Global test fixtures
arch_ops_t *x86_64_ops;
arch_ops_t *x86_32_ops;
arch_ops_t *x86_16_ops;

void setUp(void)
{
    x86_64_ops = get_arch_ops_x86_64();
    x86_32_ops = get_arch_ops_x86_32();
    x86_16_ops = get_arch_ops_x86_16();
}

void tearDown(void)
{
    // No cleanup needed for architecture operations
}

// ========================================
// x86_64 BACKWARD COMPATIBILITY TESTS
// ========================================

void test_x86_64_supports_x86_32_registers(void)
{
    // Test that x86_64 can handle x86_32 registers
    const char* x86_32_registers[] = {"eax", "ebx", "ecx", "edx", "esi", "edi", "esp", "ebp"};
    
    for (int i = 0; i < 8; i++) {
        asm_register_t reg;
        memset(&reg, 0, sizeof(asm_register_t));
        
        char reg_name[32];
        snprintf(reg_name, sizeof(reg_name), "%%%s", x86_32_registers[i]);
        
        int result = x86_64_ops->parse_register(reg_name, &reg);
        TEST_ASSERT_EQUAL(0, result);
        TEST_ASSERT_TRUE(x86_64_ops->is_valid_register(reg));
    }
}

void test_x86_64_supports_x86_16_registers(void)
{
    // Test that x86_64 can handle x86_16 registers
    const char* x86_16_registers[] = {"ax", "bx", "cx", "dx", "si", "di", "sp", "bp"};
    
    for (int i = 0; i < 8; i++) {
        asm_register_t reg;
        memset(&reg, 0, sizeof(asm_register_t));
        
        char reg_name[32];
        snprintf(reg_name, sizeof(reg_name), "%%%s", x86_16_registers[i]);
        
        int result = x86_64_ops->parse_register(reg_name, &reg);
        TEST_ASSERT_EQUAL(0, result);
        TEST_ASSERT_TRUE(x86_64_ops->is_valid_register(reg));
    }
}

void test_x86_64_supports_8bit_registers(void)
{
    // Test that x86_64 can handle 8-bit registers
    const char* x86_8_registers[] = {"al", "bl", "cl", "dl", "ah", "bh", "ch", "dh"};
    
    for (int i = 0; i < 8; i++) {
        asm_register_t reg;
        memset(&reg, 0, sizeof(asm_register_t));
        
        char reg_name[32];
        snprintf(reg_name, sizeof(reg_name), "%%%s", x86_8_registers[i]);
        
        int result = x86_64_ops->parse_register(reg_name, &reg);
        TEST_ASSERT_EQUAL(0, result);
        TEST_ASSERT_TRUE(x86_64_ops->is_valid_register(reg));
    }
}

// ========================================
// x86_32 BACKWARD COMPATIBILITY TESTS
// ========================================

void test_x86_32_supports_x86_16_registers(void)
{
    // Test that x86_32 can handle x86_16 registers
    const char* x86_16_registers[] = {"ax", "bx", "cx", "dx", "si", "di", "sp", "bp"};
    
    for (int i = 0; i < 8; i++) {
        asm_register_t reg;
        memset(&reg, 0, sizeof(asm_register_t));
        
        char reg_name[32];
        snprintf(reg_name, sizeof(reg_name), "%%%s", x86_16_registers[i]);
        
        int result = x86_32_ops->parse_register(reg_name, &reg);
        TEST_ASSERT_EQUAL(0, result);
        TEST_ASSERT_TRUE(x86_32_ops->is_valid_register(reg));
    }
}

void test_x86_32_supports_8bit_registers(void)
{
    // Test that x86_32 can handle 8-bit registers
    const char* x86_8_registers[] = {"al", "bl", "cl", "dl", "ah", "bh", "ch", "dh"};
    
    for (int i = 0; i < 8; i++) {
        asm_register_t reg;
        memset(&reg, 0, sizeof(asm_register_t));
        
        char reg_name[32];
        snprintf(reg_name, sizeof(reg_name), "%%%s", x86_8_registers[i]);
        
        int result = x86_32_ops->parse_register(reg_name, &reg);
        TEST_ASSERT_EQUAL(0, result);
        TEST_ASSERT_TRUE(x86_32_ops->is_valid_register(reg));
    }
}

void test_x86_32_rejects_x86_64_only_registers(void)
{
    // Test that x86_32 properly rejects x86_64-only registers
    const char* x86_64_only_registers[] = {"rax", "r8", "r9", "r15"};
    
    for (int i = 0; i < 4; i++) {
        asm_register_t reg;
        memset(&reg, 0, sizeof(asm_register_t));
        
        char reg_name[32];
        snprintf(reg_name, sizeof(reg_name), "%%%s", x86_64_only_registers[i]);
        
        int result = x86_32_ops->parse_register(reg_name, &reg);
        TEST_ASSERT_NOT_EQUAL(0, result); // Should fail
    }
}

// ========================================
// CROSS-ARCHITECTURE COMPATIBILITY MATRIX
// ========================================

typedef struct {
    const char *reg_name;
    bool x86_16_should_support;
    bool x86_32_should_support;
    bool x86_64_should_support;
} register_compatibility_t;

void test_register_compatibility_matrix(void)
{
    register_compatibility_t register_matrix[] = {
        // x86_16 base registers
        {"ax", true, true, true},
        {"bx", true, true, true},
        {"cx", true, true, true},
        {"dx", true, true, true},
        {"si", true, true, true},
        {"di", true, true, true},
        {"sp", true, true, true},
        {"bp", true, true, true},
        
        // 8-bit registers
        {"al", true, true, true},
        {"ah", true, true, true},
        {"bl", true, true, true},
        {"bh", true, true, true},
        
        // x86_32 only registers
        {"eax", false, true, true},
        {"ebx", false, true, true},
        {"ecx", false, true, true},
        {"edx", false, true, true},
        
        // x86_64 only registers
        {"rax", false, false, true},
        {"r8", false, false, true},
        {"r15", false, false, true}
    };
    
    size_t matrix_size = sizeof(register_matrix) / sizeof(register_compatibility_t);
    
    for (int i = 0; i < (int)matrix_size; i++) {
        asm_register_t reg;
        char reg_name[32];
        snprintf(reg_name, sizeof(reg_name), "%%%s", register_matrix[i].reg_name);
        
        // Test x86_16 support
        memset(&reg, 0, sizeof(asm_register_t));
        int x86_16_result = x86_16_ops->parse_register(reg_name, &reg);
        bool x86_16_valid = (x86_16_result == 0);
        
        // Test x86_32 support
        memset(&reg, 0, sizeof(asm_register_t));
        int x86_32_result = x86_32_ops->parse_register(reg_name, &reg);
        bool x86_32_valid = (x86_32_result == 0);
        
        // Test x86_64 support
        memset(&reg, 0, sizeof(asm_register_t));
        int x86_64_result = x86_64_ops->parse_register(reg_name, &reg);
        bool x86_64_valid = (x86_64_result == 0);
        
        // Verify compatibility expectations
        TEST_ASSERT_EQUAL(register_matrix[i].x86_16_should_support, x86_16_valid);
        TEST_ASSERT_EQUAL(register_matrix[i].x86_32_should_support, x86_32_valid);
        TEST_ASSERT_EQUAL(register_matrix[i].x86_64_should_support, x86_64_valid);
    }
}

// ========================================
// INSTRUCTION COMPATIBILITY TESTS
// ========================================

void test_instruction_compatibility_basic(void)
{
    // Test that basic zero-operand instructions work across all x86 variants
    const char* basic_instructions[] = {"nop", "ret"};
    operand_t operands[2] = {0};
    
    for (int i = 0; i < 2; i++) {
        instruction_t inst16, inst32, inst64;
        memset(&inst16, 0, sizeof(instruction_t));
        memset(&inst32, 0, sizeof(instruction_t));
        memset(&inst64, 0, sizeof(instruction_t));
        
        // All should support basic zero-operand instructions
        int result16 = x86_16_ops->parse_instruction(basic_instructions[i], operands, 0, &inst16);
        int result32 = x86_32_ops->parse_instruction(basic_instructions[i], operands, 0, &inst32);
        int result64 = x86_64_ops->parse_instruction(basic_instructions[i], operands, 0, &inst64);
        
        TEST_ASSERT_EQUAL(0, result16);
        TEST_ASSERT_EQUAL(0, result32);
        TEST_ASSERT_EQUAL(0, result64);
        
        // Cleanup
        if (inst16.mnemonic) free((void*)inst16.mnemonic);
        if (inst32.mnemonic) free((void*)inst32.mnemonic);
        if (inst64.mnemonic) free((void*)inst64.mnemonic);
    }
}

// ========================================
// INCOMPATIBLE REGISTER REJECTION TESTS
// ========================================

void test_incompatible_register_rejection(void)
{
    // Test that architectures properly reject incompatible registers
    asm_register_t reg;
    
    // x86_16 should reject 32-bit registers
    memset(&reg, 0, sizeof(asm_register_t));
    int result = x86_16_ops->parse_register("%eax", &reg);
    TEST_ASSERT_NOT_EQUAL(0, result);
    
    result = x86_16_ops->parse_register("%rax", &reg);
    TEST_ASSERT_NOT_EQUAL(0, result);
    
    // x86_32 should reject 64-bit registers
    result = x86_32_ops->parse_register("%rax", &reg);
    TEST_ASSERT_NOT_EQUAL(0, result);
    
    result = x86_32_ops->parse_register("%r8", &reg);
    TEST_ASSERT_NOT_EQUAL(0, result);
    
    // All x86 should reject non-x86 registers
    const char* non_x86_registers[] = {"x0", "w0", "sp_el0", "v0", "f0"};
    
    for (int i = 0; i < 5; i++) {
        char reg_name[32];
        snprintf(reg_name, sizeof(reg_name), "%s", non_x86_registers[i]);
        
        memset(&reg, 0, sizeof(asm_register_t));
        int result16 = x86_16_ops->parse_register(reg_name, &reg);
        int result32 = x86_32_ops->parse_register(reg_name, &reg);
        int result64 = x86_64_ops->parse_register(reg_name, &reg);
        
        TEST_ASSERT_NOT_EQUAL(0, result16);
        TEST_ASSERT_NOT_EQUAL(0, result32);
        TEST_ASSERT_NOT_EQUAL(0, result64);
    }
}

// ========================================
// TEST RUNNER
// ========================================

int main(void)
{
    UNITY_BEGIN();
    
    // x86_64 backward compatibility
    RUN_TEST(test_x86_64_supports_x86_32_registers);
    RUN_TEST(test_x86_64_supports_x86_16_registers);
    RUN_TEST(test_x86_64_supports_8bit_registers);
    
    // x86_32 backward compatibility
    RUN_TEST(test_x86_32_supports_x86_16_registers);
    RUN_TEST(test_x86_32_supports_8bit_registers);
    RUN_TEST(test_x86_32_rejects_x86_64_only_registers);
    
    // Cross-architecture compatibility matrix
    RUN_TEST(test_register_compatibility_matrix);
    
    // Instruction compatibility
    RUN_TEST(test_instruction_compatibility_basic);
    
    // Incompatibility tests
    RUN_TEST(test_incompatible_register_rejection);
    
    return UNITY_END();
}
