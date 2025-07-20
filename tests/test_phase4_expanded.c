#include "unity.h"
#include "arch_interface.h"

// x86-64 architecture operations
extern arch_ops_t *x86_64_get_arch_ops(void);

void setUp(void) {}
void tearDown(void) {}

void test_x86_64_expanded_instruction_set(void) {
    printf("\n=== Testing x86-64 Expanded Instruction Set ===\n");
    
    arch_ops_t *arch = x86_64_get_arch_ops();
    uint8_t buffer[32];
    size_t length;
    instruction_t inst;
    operand_t operands[2];
    
    // Test logical operations
    operands[0].type = OPERAND_REGISTER;
    arch->parse_register("rax", &operands[0].value.reg);
    operands[1].type = OPERAND_REGISTER;
    arch->parse_register("rbx", &operands[1].value.reg);
    
    // AND
    arch->parse_instruction("andq", operands, 2, &inst);
    TEST_ASSERT_EQUAL(0, arch->encode_instruction(&inst, buffer, &length));
    TEST_ASSERT_EQUAL(3, length);
    TEST_ASSERT_EQUAL_HEX8(0x48, buffer[0]); // REX.W
    TEST_ASSERT_EQUAL_HEX8(0x21, buffer[1]); // AND opcode
    TEST_ASSERT_EQUAL_HEX8(0xD8, buffer[2]); // ModR/M
    printf("✓ andq %%rbx, %%rax: [0x%02X 0x%02X 0x%02X]\n", buffer[0], buffer[1], buffer[2]);
    
    // OR
    arch->parse_instruction("orq", operands, 2, &inst);
    TEST_ASSERT_EQUAL(0, arch->encode_instruction(&inst, buffer, &length));
    TEST_ASSERT_EQUAL(3, length);
    TEST_ASSERT_EQUAL_HEX8(0x48, buffer[0]); // REX.W
    TEST_ASSERT_EQUAL_HEX8(0x09, buffer[1]); // OR opcode
    printf("✓ orq %%rbx, %%rax: [0x%02X 0x%02X 0x%02X]\n", buffer[0], buffer[1], buffer[2]);
    
    // XOR
    arch->parse_instruction("xorq", operands, 2, &inst);
    TEST_ASSERT_EQUAL(0, arch->encode_instruction(&inst, buffer, &length));
    TEST_ASSERT_EQUAL(3, length);
    TEST_ASSERT_EQUAL_HEX8(0x48, buffer[0]); // REX.W
    TEST_ASSERT_EQUAL_HEX8(0x31, buffer[1]); // XOR opcode
    printf("✓ xorq %%rbx, %%rax: [0x%02X 0x%02X 0x%02X]\n", buffer[0], buffer[1], buffer[2]);
    
    // CMP
    arch->parse_instruction("cmpq", operands, 2, &inst);
    TEST_ASSERT_EQUAL(0, arch->encode_instruction(&inst, buffer, &length));
    TEST_ASSERT_EQUAL(3, length);
    TEST_ASSERT_EQUAL_HEX8(0x48, buffer[0]); // REX.W
    TEST_ASSERT_EQUAL_HEX8(0x39, buffer[1]); // CMP opcode
    printf("✓ cmpq %%rbx, %%rax: [0x%02X 0x%02X 0x%02X]\n", buffer[0], buffer[1], buffer[2]);
}

void test_x86_64_single_operand_instructions(void) {
    printf("\n=== Testing x86-64 Single Operand Instructions ===\n");
    
    arch_ops_t *arch = x86_64_get_arch_ops();
    uint8_t buffer[32];
    size_t length;
    instruction_t inst;
    operand_t operands[1];
    
    operands[0].type = OPERAND_REGISTER;
    arch->parse_register("rax", &operands[0].value.reg);
    
    // INC
    arch->parse_instruction("incq", operands, 1, &inst);
    TEST_ASSERT_EQUAL(0, arch->encode_instruction(&inst, buffer, &length));
    TEST_ASSERT_EQUAL(3, length);
    TEST_ASSERT_EQUAL_HEX8(0x48, buffer[0]); // REX.W
    TEST_ASSERT_EQUAL_HEX8(0xFF, buffer[1]); // INC/DEC opcode
    TEST_ASSERT_EQUAL_HEX8(0xC0, buffer[2]); // ModR/M: INC rax
    printf("✓ incq %%rax: [0x%02X 0x%02X 0x%02X]\n", buffer[0], buffer[1], buffer[2]);
    
    // DEC
    arch->parse_instruction("decq", operands, 1, &inst);
    TEST_ASSERT_EQUAL(0, arch->encode_instruction(&inst, buffer, &length));
    TEST_ASSERT_EQUAL(3, length);
    TEST_ASSERT_EQUAL_HEX8(0x48, buffer[0]); // REX.W
    TEST_ASSERT_EQUAL_HEX8(0xFF, buffer[1]); // INC/DEC opcode
    TEST_ASSERT_EQUAL_HEX8(0xC8, buffer[2]); // ModR/M: DEC rax
    printf("✓ decq %%rax: [0x%02X 0x%02X 0x%02X]\n", buffer[0], buffer[1], buffer[2]);
}

void test_x86_64_conditional_jumps(void) {
    printf("\n=== Testing x86-64 Conditional Jumps ===\n");
    
    arch_ops_t *arch = x86_64_get_arch_ops();
    uint8_t buffer[32];
    size_t length;
    instruction_t inst;
    operand_t operands[1];
    
    // JE (Jump if Equal)
    arch->parse_instruction("je", operands, 0, &inst);
    TEST_ASSERT_EQUAL(0, arch->encode_instruction(&inst, buffer, &length));
    TEST_ASSERT_EQUAL(2, length);
    TEST_ASSERT_EQUAL_HEX8(0x74, buffer[0]); // JE opcode
    printf("✓ je: [0x%02X 0x%02X]\n", buffer[0], buffer[1]);
    
    // JNE (Jump if Not Equal)
    arch->parse_instruction("jne", operands, 0, &inst);
    TEST_ASSERT_EQUAL(0, arch->encode_instruction(&inst, buffer, &length));
    TEST_ASSERT_EQUAL(2, length);
    TEST_ASSERT_EQUAL_HEX8(0x75, buffer[0]); // JNE opcode
    printf("✓ jne: [0x%02X 0x%02X]\n", buffer[0], buffer[1]);
    
    // JMP (Unconditional Jump)
    arch->parse_instruction("jmp", operands, 0, &inst);
    TEST_ASSERT_EQUAL(0, arch->encode_instruction(&inst, buffer, &length));
    TEST_ASSERT_EQUAL(2, length);
    TEST_ASSERT_EQUAL_HEX8(0xEB, buffer[0]); // JMP short opcode
    printf("✓ jmp: [0x%02X 0x%02X]\n", buffer[0], buffer[1]);
}

void test_x86_64_complete_program_sequence(void) {
    printf("\n=== Testing x86-64 Complete Program Sequence ===\n");
    
    arch_ops_t *arch = x86_64_get_arch_ops();
    uint8_t buffer[32];
    size_t length;
    instruction_t inst;
    operand_t operands[2];
    
    printf("Encoding a complete program sequence:\n");
    
    // movq $5, %rax
    operands[0].type = OPERAND_IMMEDIATE; // AT&T: source first
    operands[0].value.immediate = 5;
    operands[1].type = OPERAND_REGISTER;  // AT&T: destination second
    arch->parse_register("rax", &operands[1].value.reg);
    
    arch->parse_instruction("movq", operands, 2, &inst);
    arch->encode_instruction(&inst, buffer, &length);
    printf("  movq $5, %%rax:    ");
    for (size_t i = 0; i < length; i++) printf("%02X ", buffer[i]);
    printf("\n");
    
    // movq $3, %rbx
    operands[0].type = OPERAND_IMMEDIATE; // AT&T: source first
    operands[0].value.immediate = 3;
    operands[1].type = OPERAND_REGISTER;  // AT&T: destination second
    arch->parse_register("rbx", &operands[1].value.reg);
    
    arch->parse_instruction("movq", operands, 2, &inst);
    arch->encode_instruction(&inst, buffer, &length);
    printf("  movq $3, %%rbx:    ");
    for (size_t i = 0; i < length; i++) printf("%02X ", buffer[i]);
    printf("\n");
    
    // cmpq %rbx, %rax
    operands[0].type = OPERAND_REGISTER;
    arch->parse_register("rax", &operands[0].value.reg);
    operands[1].type = OPERAND_REGISTER;
    arch->parse_register("rbx", &operands[1].value.reg);
    
    arch->parse_instruction("cmpq", operands, 2, &inst);
    arch->encode_instruction(&inst, buffer, &length);
    printf("  cmpq %%rbx, %%rax:   ");
    for (size_t i = 0; i < length; i++) printf("%02X ", buffer[i]);
    printf("\n");
    
    // je (placeholder jump)
    arch->parse_instruction("je", operands, 0, &inst);
    arch->encode_instruction(&inst, buffer, &length);
    printf("  je:               ");
    for (size_t i = 0; i < length; i++) printf("%02X ", buffer[i]);
    printf("\n");
    
    printf("✓ Complete program sequence encoded successfully!\n");
}

int main(void) {
    UNITY_BEGIN();
    
    RUN_TEST(test_x86_64_expanded_instruction_set);
    RUN_TEST(test_x86_64_single_operand_instructions);
    RUN_TEST(test_x86_64_conditional_jumps);
    RUN_TEST(test_x86_64_complete_program_sequence);
    
    return UNITY_END();
}
