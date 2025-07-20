#include "unity.h"
#include "x86_32.h"
#include <string.h>

// Test setup and teardown
void setUp(void) {
    x86_32_init();
}

void tearDown(void) {
    x86_32_cleanup();
}

// Test .code16/.code32 directive handling
void test_code_mode_directives(void) {
    // Test .code32 directive (default)
    TEST_ASSERT_EQUAL(0, x86_32_handle_directive(".code32", NULL));
    TEST_ASSERT_EQUAL(32, x86_32_get_code_mode());
    
    // Test .code16 directive
    TEST_ASSERT_EQUAL(0, x86_32_handle_directive(".code16", NULL));
    TEST_ASSERT_EQUAL(16, x86_32_get_code_mode());
    
    // Test CPU level directives
    TEST_ASSERT_EQUAL(0, x86_32_handle_directive(".386", NULL));
    TEST_ASSERT_EQUAL(0, x86_32_handle_directive(".486", NULL));
    TEST_ASSERT_EQUAL(0, x86_32_handle_directive(".586", NULL));
    TEST_ASSERT_EQUAL(0, x86_32_handle_directive(".686", NULL));
    
    // Test invalid directive
    TEST_ASSERT_EQUAL(-1, x86_32_handle_directive(".invalid", NULL));
}

// Test basic data movement instructions
void test_mov_instructions(void) {
    instruction_t inst;
    operand_t operands[2];
    uint8_t buffer[16];
    size_t length;
    
    // Setup operands for movl $0x12345678, %eax
    operands[0].type = OPERAND_IMMEDIATE;
    operands[0].value.immediate = 0x12345678;
    operands[1].type = OPERAND_REGISTER;
    operands[1].value.reg.name = "eax";
    operands[1].value.reg.encoding = 0;
    operands[1].value.reg.size = 4;
    
    // Parse instruction
    TEST_ASSERT_EQUAL(0, x86_32_parse_instruction("movl", operands, 2, &inst));
    
    // Encode instruction
    TEST_ASSERT_EQUAL(0, x86_32_encode_instruction(&inst, buffer, &length));
    TEST_ASSERT_EQUAL(5, length);
    TEST_ASSERT_EQUAL(0xB8, buffer[0]); // MOV EAX, imm32
    TEST_ASSERT_EQUAL(0x78, buffer[1]); // Little-endian: 0x78563412
    TEST_ASSERT_EQUAL(0x56, buffer[2]);
    TEST_ASSERT_EQUAL(0x34, buffer[3]);
    TEST_ASSERT_EQUAL(0x12, buffer[4]);
    
    // Cleanup
    if (inst.mnemonic) free(inst.mnemonic);
}

// Test 16-bit MOV instruction
void test_mov_16bit(void) {
    instruction_t inst;
    operand_t operands[2];
    uint8_t buffer[16];
    size_t length;
    
    // Set 16-bit mode
    x86_32_set_code_mode(16);
    
    // Setup operands for movw $0x1234, %ax
    operands[0].type = OPERAND_IMMEDIATE;
    operands[0].value.immediate = 0x1234;
    operands[1].type = OPERAND_REGISTER;
    operands[1].value.reg.name = "ax";
    operands[1].value.reg.encoding = 0;
    operands[1].value.reg.size = 2;
    
    // Parse and encode
    TEST_ASSERT_EQUAL(0, x86_32_parse_instruction("movw", operands, 2, &inst));
    TEST_ASSERT_EQUAL(0, x86_32_encode_instruction(&inst, buffer, &length));
    TEST_ASSERT_EQUAL(3, length);
    TEST_ASSERT_EQUAL(0xB8, buffer[0]); // MOV AX, imm16
    TEST_ASSERT_EQUAL(0x34, buffer[1]); // Little-endian: 0x3412
    TEST_ASSERT_EQUAL(0x12, buffer[2]);
    
    // Reset to 32-bit mode
    x86_32_set_code_mode(32);
    
    // Cleanup
    if (inst.mnemonic) free(inst.mnemonic);
}

// Test 8-bit MOV instruction
void test_mov_8bit(void) {
    instruction_t inst;
    operand_t operands[2];
    uint8_t buffer[16];
    size_t length;
    
    // Setup operands for movb $0x42, %al
    operands[0].type = OPERAND_IMMEDIATE;
    operands[0].value.immediate = 0x42;
    operands[1].type = OPERAND_REGISTER;
    operands[1].value.reg.name = "al";
    operands[1].value.reg.encoding = 0;
    operands[1].value.reg.size = 1;
    
    // Parse and encode
    TEST_ASSERT_EQUAL(0, x86_32_parse_instruction("movb", operands, 2, &inst));
    TEST_ASSERT_EQUAL(0, x86_32_encode_instruction(&inst, buffer, &length));
    TEST_ASSERT_EQUAL(2, length);
    TEST_ASSERT_EQUAL(0xB0, buffer[0]); // MOV AL, imm8
    TEST_ASSERT_EQUAL(0x42, buffer[1]);
    
    // Cleanup
    if (inst.mnemonic) free(inst.mnemonic);
}

// Test register-to-register MOV
void test_mov_reg_to_reg(void) {
    instruction_t inst;
    operand_t operands[2];
    uint8_t buffer[16];
    size_t length;
    
    // Setup operands for movl %eax, %ebx
    operands[0].type = OPERAND_REGISTER;
    operands[0].value.reg.name = "eax";
    operands[0].value.reg.encoding = 0;
    operands[0].value.reg.size = 4;
    operands[1].type = OPERAND_REGISTER;
    operands[1].value.reg.name = "ebx";
    operands[1].value.reg.encoding = 3;
    operands[1].value.reg.size = 4;
    
    // Parse and encode
    TEST_ASSERT_EQUAL(0, x86_32_parse_instruction("movl", operands, 2, &inst));
    TEST_ASSERT_EQUAL(0, x86_32_encode_instruction(&inst, buffer, &length));
    TEST_ASSERT_EQUAL(2, length);
    TEST_ASSERT_EQUAL(0x89, buffer[0]); // MOV r/m32, r32
    TEST_ASSERT_EQUAL(0xC3, buffer[1]); // ModR/M: mod=11, reg=000(EAX), r/m=011(EBX)
    
    // Cleanup
    if (inst.mnemonic) free(inst.mnemonic);
}

// Test arithmetic instructions
void test_add_instructions(void) {
    instruction_t inst;
    operand_t operands[2];
    uint8_t buffer[16];
    size_t length;
    
    // Test addl %eax, %ebx
    operands[0].type = OPERAND_REGISTER;
    operands[0].value.reg.name = "eax";
    operands[0].value.reg.encoding = 0;
    operands[0].value.reg.size = 4;
    operands[1].type = OPERAND_REGISTER;
    operands[1].value.reg.name = "ebx";
    operands[1].value.reg.encoding = 3;
    operands[1].value.reg.size = 4;
    
    TEST_ASSERT_EQUAL(0, x86_32_parse_instruction("addl", operands, 2, &inst));
    TEST_ASSERT_EQUAL(0, x86_32_encode_instruction(&inst, buffer, &length));
    TEST_ASSERT_EQUAL(2, length);
    TEST_ASSERT_EQUAL(0x01, buffer[0]); // ADD r/m32, r32
    TEST_ASSERT_EQUAL(0xC3, buffer[1]); // ModR/M byte
    
    // Cleanup
    if (inst.mnemonic) free(inst.mnemonic);
}

// Test immediate arithmetic
void test_add_immediate(void) {
    instruction_t inst;
    operand_t operands[2];
    uint8_t buffer[16];
    size_t length;
    
    // Test addl $100, %eax
    operands[0].type = OPERAND_IMMEDIATE;
    operands[0].value.immediate = 100;
    operands[1].type = OPERAND_REGISTER;
    operands[1].value.reg.name = "eax";
    operands[1].value.reg.encoding = 0;
    operands[1].value.reg.size = 4;
    
    TEST_ASSERT_EQUAL(0, x86_32_parse_instruction("addl", operands, 2, &inst));
    TEST_ASSERT_EQUAL(0, x86_32_encode_instruction(&inst, buffer, &length));
    TEST_ASSERT_EQUAL(5, length);
    TEST_ASSERT_EQUAL(0x05, buffer[0]); // ADD EAX, imm32
    TEST_ASSERT_EQUAL(100, buffer[1]);  // Immediate value
    TEST_ASSERT_EQUAL(0, buffer[2]);
    TEST_ASSERT_EQUAL(0, buffer[3]);
    TEST_ASSERT_EQUAL(0, buffer[4]);
    
    // Cleanup
    if (inst.mnemonic) free(inst.mnemonic);
}

// Test stack operations
void test_push_pop(void) {
    instruction_t inst;
    operand_t operands[1];
    uint8_t buffer[16];
    size_t length;
    
    // Test pushl %eax
    operands[0].type = OPERAND_REGISTER;
    operands[0].value.reg.name = "eax";
    operands[0].value.reg.encoding = 0;
    operands[0].value.reg.size = 4;
    
    TEST_ASSERT_EQUAL(0, x86_32_parse_instruction("push", operands, 1, &inst));
    TEST_ASSERT_EQUAL(0, x86_32_encode_instruction(&inst, buffer, &length));
    TEST_ASSERT_EQUAL(1, length);
    TEST_ASSERT_EQUAL(0x50, buffer[0]); // PUSH EAX
    
    if (inst.mnemonic) free(inst.mnemonic);
    
    // Test popl %ebx
    operands[0].value.reg.name = "ebx";
    operands[0].value.reg.encoding = 3;
    
    TEST_ASSERT_EQUAL(0, x86_32_parse_instruction("pop", operands, 1, &inst));
    TEST_ASSERT_EQUAL(0, x86_32_encode_instruction(&inst, buffer, &length));
    TEST_ASSERT_EQUAL(1, length);
    TEST_ASSERT_EQUAL(0x5B, buffer[0]); // POP EBX
    
    // Cleanup
    if (inst.mnemonic) free(inst.mnemonic);
}

// Test push immediate
void test_push_immediate(void) {
    instruction_t inst;
    operand_t operands[1];
    uint8_t buffer[16];
    size_t length;
    
    // Test push $42 (8-bit immediate)
    operands[0].type = OPERAND_IMMEDIATE;
    operands[0].value.immediate = 42;
    
    TEST_ASSERT_EQUAL(0, x86_32_parse_instruction("push", operands, 1, &inst));
    TEST_ASSERT_EQUAL(0, x86_32_encode_instruction(&inst, buffer, &length));
    TEST_ASSERT_EQUAL(2, length);
    TEST_ASSERT_EQUAL(0x6A, buffer[0]); // PUSH imm8
    TEST_ASSERT_EQUAL(42, buffer[1]);
    
    if (inst.mnemonic) free(inst.mnemonic);
    
    // Test push $0x12345678 (32-bit immediate)
    operands[0].value.immediate = 0x12345678;
    
    TEST_ASSERT_EQUAL(0, x86_32_parse_instruction("push", operands, 1, &inst));
    TEST_ASSERT_EQUAL(0, x86_32_encode_instruction(&inst, buffer, &length));
    TEST_ASSERT_EQUAL(5, length);
    TEST_ASSERT_EQUAL(0x68, buffer[0]); // PUSH imm32
    TEST_ASSERT_EQUAL(0x78, buffer[1]); // Little-endian
    TEST_ASSERT_EQUAL(0x56, buffer[2]);
    TEST_ASSERT_EQUAL(0x34, buffer[3]);
    TEST_ASSERT_EQUAL(0x12, buffer[4]);
    
    // Cleanup
    if (inst.mnemonic) free(inst.mnemonic);
}

// Test control flow instructions
void test_control_flow(void) {
    instruction_t inst;
    operand_t operands[1];
    uint8_t buffer[16];
    size_t length;
    
    // Test ret
    TEST_ASSERT_EQUAL(0, x86_32_parse_instruction("ret", NULL, 0, &inst));
    TEST_ASSERT_EQUAL(0, x86_32_encode_instruction(&inst, buffer, &length));
    TEST_ASSERT_EQUAL(1, length);
    TEST_ASSERT_EQUAL(0xC3, buffer[0]);
    
    if (inst.mnemonic) free(inst.mnemonic);
    
    // Test nop
    TEST_ASSERT_EQUAL(0, x86_32_parse_instruction("nop", NULL, 0, &inst));
    TEST_ASSERT_EQUAL(0, x86_32_encode_instruction(&inst, buffer, &length));
    TEST_ASSERT_EQUAL(1, length);
    TEST_ASSERT_EQUAL(0x90, buffer[0]);
    
    if (inst.mnemonic) free(inst.mnemonic);
    
    // Test hlt
    TEST_ASSERT_EQUAL(0, x86_32_parse_instruction("hlt", NULL, 0, &inst));
    TEST_ASSERT_EQUAL(0, x86_32_encode_instruction(&inst, buffer, &length));
    TEST_ASSERT_EQUAL(1, length);
    TEST_ASSERT_EQUAL(0xF4, buffer[0]);
    
    // Cleanup
    if (inst.mnemonic) free(inst.mnemonic);
}

// Test conditional jumps
void test_conditional_jumps(void) {
    instruction_t inst;
    operand_t operands[1];
    uint8_t buffer[16];
    size_t length;
    
    // Test je with 8-bit offset
    operands[0].type = OPERAND_IMMEDIATE;
    operands[0].value.immediate = 10;
    
    TEST_ASSERT_EQUAL(0, x86_32_parse_instruction("je", operands, 1, &inst));
    TEST_ASSERT_EQUAL(0, x86_32_encode_instruction(&inst, buffer, &length));
    TEST_ASSERT_EQUAL(2, length);
    TEST_ASSERT_EQUAL(0x74, buffer[0]); // JE rel8
    TEST_ASSERT_EQUAL(10, buffer[1]);
    
    if (inst.mnemonic) free(inst.mnemonic);
    
    // Test jne
    TEST_ASSERT_EQUAL(0, x86_32_parse_instruction("jne", operands, 1, &inst));
    TEST_ASSERT_EQUAL(0, x86_32_encode_instruction(&inst, buffer, &length));
    TEST_ASSERT_EQUAL(2, length);
    TEST_ASSERT_EQUAL(0x75, buffer[0]); // JNE rel8
    
    // Cleanup
    if (inst.mnemonic) free(inst.mnemonic);
}

// Test system instructions
void test_system_instructions(void) {
    instruction_t inst;
    operand_t operands[1];
    uint8_t buffer[16];
    size_t length;
    
    // Test int $0x80
    operands[0].type = OPERAND_IMMEDIATE;
    operands[0].value.immediate = 0x80;
    
    TEST_ASSERT_EQUAL(0, x86_32_parse_instruction("int", operands, 1, &inst));
    TEST_ASSERT_EQUAL(0, x86_32_encode_instruction(&inst, buffer, &length));
    TEST_ASSERT_EQUAL(2, length);
    TEST_ASSERT_EQUAL(0xCD, buffer[0]); // INT imm8
    TEST_ASSERT_EQUAL(0x80, buffer[1]);
    
    if (inst.mnemonic) free(inst.mnemonic);
    
    // Test cli
    TEST_ASSERT_EQUAL(0, x86_32_parse_instruction("cli", NULL, 0, &inst));
    TEST_ASSERT_EQUAL(0, x86_32_encode_instruction(&inst, buffer, &length));
    TEST_ASSERT_EQUAL(1, length);
    TEST_ASSERT_EQUAL(0xFA, buffer[0]);
    
    if (inst.mnemonic) free(inst.mnemonic);
    
    // Test sti
    TEST_ASSERT_EQUAL(0, x86_32_parse_instruction("sti", NULL, 0, &inst));
    TEST_ASSERT_EQUAL(0, x86_32_encode_instruction(&inst, buffer, &length));
    TEST_ASSERT_EQUAL(1, length);
    TEST_ASSERT_EQUAL(0xFB, buffer[0]);
    
    // Cleanup
    if (inst.mnemonic) free(inst.mnemonic);
}

// Test increment/decrement instructions
void test_inc_dec(void) {
    instruction_t inst;
    operand_t operands[1];
    uint8_t buffer[16];
    size_t length;
    
    // Test incl %eax
    operands[0].type = OPERAND_REGISTER;
    operands[0].value.reg.name = "eax";
    operands[0].value.reg.encoding = 0;
    operands[0].value.reg.size = 4;
    
    TEST_ASSERT_EQUAL(0, x86_32_parse_instruction("incl", operands, 1, &inst));
    TEST_ASSERT_EQUAL(0, x86_32_encode_instruction(&inst, buffer, &length));
    TEST_ASSERT_EQUAL(1, length);
    TEST_ASSERT_EQUAL(0x40, buffer[0]); // INC EAX
    
    if (inst.mnemonic) free(inst.mnemonic);
    
    // Test decl %ebx
    operands[0].value.reg.name = "ebx";
    operands[0].value.reg.encoding = 3;
    
    TEST_ASSERT_EQUAL(0, x86_32_parse_instruction("decl", operands, 1, &inst));
    TEST_ASSERT_EQUAL(0, x86_32_encode_instruction(&inst, buffer, &length));
    TEST_ASSERT_EQUAL(1, length);
    TEST_ASSERT_EQUAL(0x4B, buffer[0]); // DEC EBX
    
    // Cleanup
    if (inst.mnemonic) free(inst.mnemonic);
}

// Test register parsing
void test_register_parsing(void) {
    asm_register_t reg;
    
    // Test 32-bit registers
    TEST_ASSERT_EQUAL(0, x86_32_parse_register("eax", &reg));
    TEST_ASSERT_EQUAL_STRING("eax", reg.name);
    TEST_ASSERT_EQUAL(0, reg.encoding);
    TEST_ASSERT_EQUAL(4, reg.size);
    
    TEST_ASSERT_EQUAL(0, x86_32_parse_register("ebx", &reg));
    TEST_ASSERT_EQUAL(3, reg.encoding);
    TEST_ASSERT_EQUAL(4, reg.size);
    
    // Test 16-bit registers
    TEST_ASSERT_EQUAL(0, x86_32_parse_register("ax", &reg));
    TEST_ASSERT_EQUAL(0, reg.encoding);
    TEST_ASSERT_EQUAL(2, reg.size);
    
    // Test 8-bit registers
    TEST_ASSERT_EQUAL(0, x86_32_parse_register("al", &reg));
    TEST_ASSERT_EQUAL(0, reg.encoding);
    TEST_ASSERT_EQUAL(1, reg.size);
    
    TEST_ASSERT_EQUAL(0, x86_32_parse_register("ah", &reg));
    TEST_ASSERT_EQUAL(4, reg.encoding);
    TEST_ASSERT_EQUAL(1, reg.size);
    
    // Test segment registers
    TEST_ASSERT_EQUAL(0, x86_32_parse_register("cs", &reg));
    TEST_ASSERT_EQUAL(1, reg.encoding);
    TEST_ASSERT_EQUAL(2, reg.size);
    
    // Test invalid register
    TEST_ASSERT_EQUAL(-1, x86_32_parse_register("invalid", &reg));
    
    // Cleanup allocated names
    if (reg.name) free(reg.name);
}

// Test comprehensive instruction set validation
void test_instruction_validation(void) {
    instruction_t inst;
    
    // Test valid i386 instructions
    TEST_ASSERT_EQUAL(0, x86_32_parse_instruction("movl", NULL, 0, &inst));
    if (inst.mnemonic) free(inst.mnemonic);
    
    TEST_ASSERT_EQUAL(0, x86_32_parse_instruction("addl", NULL, 0, &inst));
    if (inst.mnemonic) free(inst.mnemonic);
    
    TEST_ASSERT_EQUAL(0, x86_32_parse_instruction("jmp", NULL, 0, &inst));
    if (inst.mnemonic) free(inst.mnemonic);
    
    TEST_ASSERT_EQUAL(0, x86_32_parse_instruction("pushl", NULL, 0, &inst));
    if (inst.mnemonic) free(inst.mnemonic);
    
    TEST_ASSERT_EQUAL(0, x86_32_parse_instruction("cmpl", NULL, 0, &inst));
    if (inst.mnemonic) free(inst.mnemonic);
    
    // Test floating point
    TEST_ASSERT_EQUAL(0, x86_32_parse_instruction("fld", NULL, 0, &inst));
    if (inst.mnemonic) free(inst.mnemonic);
    
    // Test MMX
    TEST_ASSERT_EQUAL(0, x86_32_parse_instruction("movq", NULL, 0, &inst));
    if (inst.mnemonic) free(inst.mnemonic);
    
    // Test SSE
    TEST_ASSERT_EQUAL(0, x86_32_parse_instruction("movss", NULL, 0, &inst));
    if (inst.mnemonic) free(inst.mnemonic);
    
    // Test invalid instructions
    TEST_ASSERT_EQUAL(-1, x86_32_parse_instruction("invalid_instruction", NULL, 0, &inst));
    TEST_ASSERT_EQUAL(-1, x86_32_parse_instruction("", NULL, 0, &inst));
}

// Main test runner
int main(void) {
    UNITY_BEGIN();
    
    // Code mode and directive tests
    RUN_TEST(test_code_mode_directives);
    
    // Data movement tests
    RUN_TEST(test_mov_instructions);
    RUN_TEST(test_mov_16bit);
    RUN_TEST(test_mov_8bit);
    RUN_TEST(test_mov_reg_to_reg);
    
    // Arithmetic tests
    RUN_TEST(test_add_instructions);
    RUN_TEST(test_add_immediate);
    
    // Stack operation tests
    RUN_TEST(test_push_pop);
    RUN_TEST(test_push_immediate);
    
    // Control flow tests
    RUN_TEST(test_control_flow);
    RUN_TEST(test_conditional_jumps);
    
    // System instruction tests
    RUN_TEST(test_system_instructions);
    
    // Increment/decrement tests
    RUN_TEST(test_inc_dec);
    
    // Register parsing tests
    RUN_TEST(test_register_parsing);
    
    // Comprehensive validation tests
    RUN_TEST(test_instruction_validation);
    
    return UNITY_END();
}
