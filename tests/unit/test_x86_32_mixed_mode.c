#include "../unity/src/unity.h"
#include "x86_32.h"
#include <string.h>

// Test setup and teardown
void setUp(void) {
    x86_32_init();
    x86_32_set_code_mode(32); // Start in 32-bit mode
}

void tearDown(void) {
    x86_32_cleanup();
}

// Test 16-bit mode real mode operations
void test_real_mode_16bit(void) {
    instruction_t inst;
    operand_t operands[2];
    uint8_t buffer[16];
    size_t length;
    
    // Switch to 16-bit mode
    x86_32_set_code_mode(16);
    
    // Test movw $0x1234, %ax (16-bit immediate to 16-bit register)
    operands[0].type = OPERAND_IMMEDIATE;
    operands[0].value.immediate = 0x1234;
    operands[1].type = OPERAND_REGISTER;
    operands[1].value.reg.name = "ax";
    operands[1].value.reg.encoding = 0;
    operands[1].value.reg.size = 2;
    
    TEST_ASSERT_EQUAL(0, x86_32_parse_instruction("movw", operands, 2, &inst));
    TEST_ASSERT_EQUAL(0, x86_32_encode_instruction(&inst, buffer, &length));
    TEST_ASSERT_EQUAL(3, length);
    TEST_ASSERT_EQUAL(0xB8, buffer[0]); // MOV AX, imm16
    TEST_ASSERT_EQUAL(0x34, buffer[1]); // Low byte
    TEST_ASSERT_EQUAL(0x12, buffer[2]); // High byte
    
    if (inst.mnemonic) free(inst.mnemonic);
}

// Test 32-bit operations in 16-bit mode (with operand size prefix)
void test_32bit_in_16bit_mode(void) {
    instruction_t inst;
    operand_t operands[2];
    uint8_t buffer[16];
    size_t length;
    
    // Switch to 16-bit mode
    x86_32_set_code_mode(16);
    
    // Test movl $0x12345678, %eax (32-bit immediate in 16-bit mode)
    operands[0].type = OPERAND_IMMEDIATE;
    operands[0].value.immediate = 0x12345678;
    operands[1].type = OPERAND_REGISTER;
    operands[1].value.reg.name = "eax";
    operands[1].value.reg.encoding = 0;
    operands[1].value.reg.size = 4;
    
    TEST_ASSERT_EQUAL(0, x86_32_parse_instruction("movl", operands, 2, &inst));
    TEST_ASSERT_EQUAL(0, x86_32_encode_instruction(&inst, buffer, &length));
    TEST_ASSERT_EQUAL(6, length);
    TEST_ASSERT_EQUAL(0x66, buffer[0]); // Operand size prefix
    TEST_ASSERT_EQUAL(0xB8, buffer[1]); // MOV EAX, imm32
    TEST_ASSERT_EQUAL(0x78, buffer[2]); // Little-endian immediate
    TEST_ASSERT_EQUAL(0x56, buffer[3]);
    TEST_ASSERT_EQUAL(0x34, buffer[4]);
    TEST_ASSERT_EQUAL(0x12, buffer[5]);
    
    if (inst.mnemonic) free(inst.mnemonic);
}

// Test 16-bit operations in 32-bit mode (with operand size prefix)
void test_16bit_in_32bit_mode(void) {
    instruction_t inst;
    operand_t operands[2];
    uint8_t buffer[16];
    size_t length;
    
    // Ensure we're in 32-bit mode
    x86_32_set_code_mode(32);
    
    // Test movw $0x1234, %ax (16-bit immediate in 32-bit mode)
    operands[0].type = OPERAND_IMMEDIATE;
    operands[0].value.immediate = 0x1234;
    operands[1].type = OPERAND_REGISTER;
    operands[1].value.reg.name = "ax";
    operands[1].value.reg.encoding = 0;
    operands[1].value.reg.size = 2;
    
    TEST_ASSERT_EQUAL(0, x86_32_parse_instruction("movw", operands, 2, &inst));
    TEST_ASSERT_EQUAL(0, x86_32_encode_instruction(&inst, buffer, &length));
    TEST_ASSERT_EQUAL(4, length);
    TEST_ASSERT_EQUAL(0x66, buffer[0]); // Operand size prefix
    TEST_ASSERT_EQUAL(0xB8, buffer[1]); // MOV AX, imm16
    TEST_ASSERT_EQUAL(0x34, buffer[2]); // Little-endian immediate
    TEST_ASSERT_EQUAL(0x12, buffer[3]);
    
    if (inst.mnemonic) free(inst.mnemonic);
}

// Test protected mode transition simulation
void test_protected_mode_sequence(void) {
    instruction_t inst;
    operand_t operands[2];
    uint8_t buffer[16];
    size_t length;
    
    // Start in 16-bit real mode
    x86_32_set_code_mode(16);
    
    // Test CLI (disable interrupts)
    TEST_ASSERT_EQUAL(0, x86_32_parse_instruction("cli", NULL, 0, &inst));
    TEST_ASSERT_EQUAL(0, x86_32_encode_instruction(&inst, buffer, &length));
    TEST_ASSERT_EQUAL(1, length);
    TEST_ASSERT_EQUAL(0xFA, buffer[0]);
    if (inst.mnemonic) free(inst.mnemonic);
    
    // Test loading CR0 value (simulation - movl %eax, %cr0 would be privileged)
    // Instead test a typical setup sequence: movl $0x80000001, %eax
    operands[0].type = OPERAND_IMMEDIATE;
    operands[0].value.immediate = 0x80000001; // PE + PG bits
    operands[1].type = OPERAND_REGISTER;
    operands[1].value.reg.name = "eax";
    operands[1].value.reg.encoding = 0;
    operands[1].value.reg.size = 4;
    
    TEST_ASSERT_EQUAL(0, x86_32_parse_instruction("movl", operands, 2, &inst));
    TEST_ASSERT_EQUAL(0, x86_32_encode_instruction(&inst, buffer, &length));
    TEST_ASSERT_EQUAL(6, length); // Includes operand size prefix
    TEST_ASSERT_EQUAL(0x66, buffer[0]); // Operand size prefix for 32-bit in 16-bit mode
    TEST_ASSERT_EQUAL(0xB8, buffer[1]); // MOV EAX, imm32
    
    if (inst.mnemonic) free(inst.mnemonic);
    
    // Switch to 32-bit mode (simulating mode switch)
    x86_32_set_code_mode(32);
    
    // Test 32-bit operations without prefix
    operands[0].value.immediate = 0x12345678;
    TEST_ASSERT_EQUAL(0, x86_32_parse_instruction("movl", operands, 2, &inst));
    TEST_ASSERT_EQUAL(0, x86_32_encode_instruction(&inst, buffer, &length));
    TEST_ASSERT_EQUAL(5, length); // No prefix needed in 32-bit mode
    TEST_ASSERT_EQUAL(0xB8, buffer[0]); // MOV EAX, imm32
    
    if (inst.mnemonic) free(inst.mnemonic);
}

// Test virtual 8086 mode functionality
void test_virtual_8086_mode(void) {
    instruction_t inst;
    operand_t operands[1];
    uint8_t buffer[16];
    size_t length;
    
    // In virtual 8086 mode, we can use 16-bit instructions
    x86_32_set_code_mode(16);
    
    // Test typical 8086 operations
    // INT 21h (DOS system call)
    operands[0].type = OPERAND_IMMEDIATE;
    operands[0].value.immediate = 0x21;
    
    TEST_ASSERT_EQUAL(0, x86_32_parse_instruction("int", operands, 1, &inst));
    TEST_ASSERT_EQUAL(0, x86_32_encode_instruction(&inst, buffer, &length));
    TEST_ASSERT_EQUAL(2, length);
    TEST_ASSERT_EQUAL(0xCD, buffer[0]); // INT imm8
    TEST_ASSERT_EQUAL(0x21, buffer[1]);
    
    if (inst.mnemonic) free(inst.mnemonic);
    
    // Test IRET (return from interrupt in V86 mode)
    TEST_ASSERT_EQUAL(0, x86_32_parse_instruction("iret", NULL, 0, &inst));
    // Note: IRET encoding would be implemented in full instruction set
    
    if (inst.mnemonic) free(inst.mnemonic);
}

// Test flag manipulation in different modes
void test_flag_operations(void) {
    instruction_t inst;
    uint8_t buffer[16];
    size_t length;
    
    // Test CLC (clear carry flag)
    TEST_ASSERT_EQUAL(0, x86_32_parse_instruction("clc", NULL, 0, &inst));
    TEST_ASSERT_EQUAL(0, x86_32_encode_instruction(&inst, buffer, &length));
    TEST_ASSERT_EQUAL(1, length);
    TEST_ASSERT_EQUAL(0xF8, buffer[0]);
    if (inst.mnemonic) free(inst.mnemonic);
    
    // Test STC (set carry flag)
    TEST_ASSERT_EQUAL(0, x86_32_parse_instruction("stc", NULL, 0, &inst));
    TEST_ASSERT_EQUAL(0, x86_32_encode_instruction(&inst, buffer, &length));
    TEST_ASSERT_EQUAL(1, length);
    TEST_ASSERT_EQUAL(0xF9, buffer[0]);
    if (inst.mnemonic) free(inst.mnemonic);
    
    // Test CLD (clear direction flag)
    TEST_ASSERT_EQUAL(0, x86_32_parse_instruction("cld", NULL, 0, &inst));
    TEST_ASSERT_EQUAL(0, x86_32_encode_instruction(&inst, buffer, &length));
    TEST_ASSERT_EQUAL(1, length);
    TEST_ASSERT_EQUAL(0xFC, buffer[0]);
    if (inst.mnemonic) free(inst.mnemonic);
    
    // Test STD (set direction flag)
    TEST_ASSERT_EQUAL(0, x86_32_parse_instruction("std", NULL, 0, &inst));
    TEST_ASSERT_EQUAL(0, x86_32_encode_instruction(&inst, buffer, &length));
    TEST_ASSERT_EQUAL(1, length);
    TEST_ASSERT_EQUAL(0xFD, buffer[0]);
    if (inst.mnemonic) free(inst.mnemonic);
}

// Test segment register operations
void test_segment_registers(void) {
    asm_register_t reg;
    
    // Test all segment registers
    TEST_ASSERT_EQUAL(0, x86_32_parse_register("cs", &reg));
    TEST_ASSERT_EQUAL_STRING("cs", reg.name);
    TEST_ASSERT_EQUAL(1, reg.encoding);
    TEST_ASSERT_EQUAL(2, reg.size);
    if (reg.name) free(reg.name);
    
    TEST_ASSERT_EQUAL(0, x86_32_parse_register("ds", &reg));
    TEST_ASSERT_EQUAL(3, reg.encoding);
    if (reg.name) free(reg.name);
    
    TEST_ASSERT_EQUAL(0, x86_32_parse_register("es", &reg));
    TEST_ASSERT_EQUAL(0, reg.encoding);
    if (reg.name) free(reg.name);
    
    TEST_ASSERT_EQUAL(0, x86_32_parse_register("ss", &reg));
    TEST_ASSERT_EQUAL(2, reg.encoding);
    if (reg.name) free(reg.name);
    
    TEST_ASSERT_EQUAL(0, x86_32_parse_register("fs", &reg));
    TEST_ASSERT_EQUAL(4, reg.encoding);
    if (reg.name) free(reg.name);
    
    TEST_ASSERT_EQUAL(0, x86_32_parse_register("gs", &reg));
    TEST_ASSERT_EQUAL(5, reg.encoding);
    if (reg.name) free(reg.name);
}

// Test mixed mode bootloader sequence
void test_bootloader_sequence(void) {
    instruction_t inst;
    operand_t operands[2];
    uint8_t buffer[16];
    size_t length;
    
    // Start in 16-bit real mode (like BIOS boot)
    x86_32_set_code_mode(16);
    
    // Step 1: Disable interrupts
    TEST_ASSERT_EQUAL(0, x86_32_parse_instruction("cli", NULL, 0, &inst));
    TEST_ASSERT_EQUAL(0, x86_32_encode_instruction(&inst, buffer, &length));
    TEST_ASSERT_EQUAL(1, length);
    TEST_ASSERT_EQUAL(0xFA, buffer[0]);
    if (inst.mnemonic) free(inst.mnemonic);
    
    // Step 2: Set up data segments (movw $0x1000, %ax)
    operands[0].type = OPERAND_IMMEDIATE;
    operands[0].value.immediate = 0x1000;
    operands[1].type = OPERAND_REGISTER;
    operands[1].value.reg.name = "ax";
    operands[1].value.reg.encoding = 0;
    operands[1].value.reg.size = 2;
    
    TEST_ASSERT_EQUAL(0, x86_32_parse_instruction("movw", operands, 2, &inst));
    TEST_ASSERT_EQUAL(0, x86_32_encode_instruction(&inst, buffer, &length));
    TEST_ASSERT_EQUAL(3, length);
    TEST_ASSERT_EQUAL(0xB8, buffer[0]);
    TEST_ASSERT_EQUAL(0x00, buffer[1]);
    TEST_ASSERT_EQUAL(0x10, buffer[2]);
    if (inst.mnemonic) free(inst.mnemonic);
    
    // Step 3: Prepare for 32-bit (movl $0x80000001, %eax)
    operands[0].value.immediate = 0x80000001;
    operands[1].value.reg.name = "eax";
    operands[1].value.reg.size = 4;
    
    TEST_ASSERT_EQUAL(0, x86_32_parse_instruction("movl", operands, 2, &inst));
    TEST_ASSERT_EQUAL(0, x86_32_encode_instruction(&inst, buffer, &length));
    TEST_ASSERT_EQUAL(6, length);
    TEST_ASSERT_EQUAL(0x66, buffer[0]); // Operand size prefix in 16-bit mode
    if (inst.mnemonic) free(inst.mnemonic);
    
    // Step 4: Switch to 32-bit protected mode
    x86_32_set_code_mode(32);
    
    // Step 5: Now in protected mode - 32-bit operations
    operands[0].value.immediate = 0x12345678;
    TEST_ASSERT_EQUAL(0, x86_32_parse_instruction("movl", operands, 2, &inst));
    TEST_ASSERT_EQUAL(0, x86_32_encode_instruction(&inst, buffer, &length));
    TEST_ASSERT_EQUAL(5, length); // No prefix needed in 32-bit mode
    TEST_ASSERT_EQUAL(0xB8, buffer[0]);
    if (inst.mnemonic) free(inst.mnemonic);
    
    // Step 6: Enable interrupts in protected mode
    TEST_ASSERT_EQUAL(0, x86_32_parse_instruction("sti", NULL, 0, &inst));
    TEST_ASSERT_EQUAL(0, x86_32_encode_instruction(&inst, buffer, &length));
    TEST_ASSERT_EQUAL(1, length);
    TEST_ASSERT_EQUAL(0xFB, buffer[0]);
    if (inst.mnemonic) free(inst.mnemonic);
}

// Test comprehensive CPU mode features
void test_cpu_modes(void) {
    // Test code mode switching
    x86_32_set_code_mode(16);
    TEST_ASSERT_EQUAL(16, x86_32_get_code_mode());
    
    x86_32_set_code_mode(32);
    TEST_ASSERT_EQUAL(32, x86_32_get_code_mode());
    
    // Test invalid mode (should not change)
    x86_32_set_code_mode(64);
    TEST_ASSERT_EQUAL(32, x86_32_get_code_mode()); // Should remain 32
    
    // Test CPU level support
    x86_32_set_cpu_level(0); // 386
    TEST_ASSERT_TRUE(x86_32_supports_feature(0));
    TEST_ASSERT_FALSE(x86_32_supports_feature(1));
    
    x86_32_set_cpu_level(3); // 686/Pentium Pro
    TEST_ASSERT_TRUE(x86_32_supports_feature(0));
    TEST_ASSERT_TRUE(x86_32_supports_feature(1));
    TEST_ASSERT_TRUE(x86_32_supports_feature(2));
    TEST_ASSERT_TRUE(x86_32_supports_feature(3));
}

// Main test runner
int main(void) {
    UNITY_BEGIN();
    
    // Mixed mode operation tests
    RUN_TEST(test_real_mode_16bit);
    RUN_TEST(test_32bit_in_16bit_mode);
    RUN_TEST(test_16bit_in_32bit_mode);
    RUN_TEST(test_protected_mode_sequence);
    RUN_TEST(test_virtual_8086_mode);
    
    // Flag and system tests
    RUN_TEST(test_flag_operations);
    RUN_TEST(test_segment_registers);
    
    // Comprehensive mode tests
    RUN_TEST(test_bootloader_sequence);
    RUN_TEST(test_cpu_modes);
    
    return UNITY_END();
}
