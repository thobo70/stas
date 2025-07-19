#include "unity.h"
#include "arch_interface.h"

// x86-64 architecture operations
extern arch_ops_t *x86_64_get_arch_ops(void);

void setUp(void) {
    // This is run before each test
}

void tearDown(void) {
    // This is run after each test
}

void test_x86_64_comprehensive_instruction_encoding(void) {
    printf("\n=== Comprehensive x86-64 Instruction Encoding Test ===\n");
    
    arch_ops_t *arch = x86_64_get_arch_ops();
    uint8_t buffer[32];
    size_t length;
    instruction_t inst;
    operand_t operands[2];
    
    // Test 1: movq $60, %rax (REX.W + 0xB8 + reg + imm64)
    operands[0].type = OPERAND_REGISTER;
    arch->parse_register("rax", &operands[0].value.reg);
    operands[1].type = OPERAND_IMMEDIATE;
    operands[1].value.immediate = 60;
    
    arch->parse_instruction("movq", operands, 2, &inst);
    TEST_ASSERT_EQUAL(0, arch->encode_instruction(&inst, buffer, &length));
    TEST_ASSERT_EQUAL(10, length);
    TEST_ASSERT_EQUAL_HEX8(0x48, buffer[0]); // REX.W
    TEST_ASSERT_EQUAL_HEX8(0xB8, buffer[1]); // MOV rax, imm64
    TEST_ASSERT_EQUAL_HEX8(60, buffer[2]);   // immediate
    
    printf("✓ movq $60, %%rax: [");
    for (size_t i = 0; i < length; i++) printf("0x%02X ", buffer[i]);
    printf("]\n");
    
    // Test 2: movq %rbx, %rax (REX.W + 0x89 + ModR/M)
    operands[0].type = OPERAND_REGISTER;
    arch->parse_register("rax", &operands[0].value.reg);
    operands[1].type = OPERAND_REGISTER;
    arch->parse_register("rbx", &operands[1].value.reg);
    
    arch->parse_instruction("movq", operands, 2, &inst);
    TEST_ASSERT_EQUAL(0, arch->encode_instruction(&inst, buffer, &length));
    TEST_ASSERT_EQUAL(3, length);
    TEST_ASSERT_EQUAL_HEX8(0x48, buffer[0]); // REX.W
    TEST_ASSERT_EQUAL_HEX8(0x89, buffer[1]); // MOV opcode
    TEST_ASSERT_EQUAL_HEX8(0xD8, buffer[2]); // ModR/M: rbx -> rax
    
    printf("✓ movq %%rbx, %%rax: [");
    for (size_t i = 0; i < length; i++) printf("0x%02X ", buffer[i]);
    printf("]\n");
    
    // Test 3: addq %rbx, %rax
    arch->parse_instruction("addq", operands, 2, &inst);
    TEST_ASSERT_EQUAL(0, arch->encode_instruction(&inst, buffer, &length));
    TEST_ASSERT_EQUAL(3, length);
    TEST_ASSERT_EQUAL_HEX8(0x48, buffer[0]); // REX.W
    TEST_ASSERT_EQUAL_HEX8(0x01, buffer[1]); // ADD opcode
    TEST_ASSERT_EQUAL_HEX8(0xD8, buffer[2]); // ModR/M
    
    printf("✓ addq %%rbx, %%rax: [");
    for (size_t i = 0; i < length; i++) printf("0x%02X ", buffer[i]);
    printf("]\n");
    
    // Test 4: pushq %rax
    arch->parse_instruction("pushq", operands, 1, &inst);
    TEST_ASSERT_EQUAL(0, arch->encode_instruction(&inst, buffer, &length));
    TEST_ASSERT_EQUAL(1, length);
    TEST_ASSERT_EQUAL_HEX8(0x50, buffer[0]); // PUSH rax
    
    printf("✓ pushq %%rax: [0x%02X]\n", buffer[0]);
    
    // Test 5: syscall
    arch->parse_instruction("syscall", operands, 0, &inst);
    TEST_ASSERT_EQUAL(0, arch->encode_instruction(&inst, buffer, &length));
    TEST_ASSERT_EQUAL(2, length);
    TEST_ASSERT_EQUAL_HEX8(0x0F, buffer[0]); // SYSCALL
    TEST_ASSERT_EQUAL_HEX8(0x05, buffer[1]);
    
    printf("✓ syscall: [0x%02X 0x%02X]\n", buffer[0], buffer[1]);
}

void test_x86_64_hello_world_program_encoding(void) {
    printf("\n=== x86-64 Hello World Program Instruction Encoding ===\n");
    
    arch_ops_t *arch = x86_64_get_arch_ops();
    uint8_t buffer[32];
    size_t length;
    instruction_t inst;
    operand_t operands[2];
    
    printf("Encoding Hello World program instructions:\n");
    
    // movq $1, %rax
    operands[0].type = OPERAND_REGISTER;
    arch->parse_register("rax", &operands[0].value.reg);
    operands[1].type = OPERAND_IMMEDIATE;
    operands[1].value.immediate = 1;
    
    arch->parse_instruction("movq", operands, 2, &inst);
    TEST_ASSERT_EQUAL(0, arch->encode_instruction(&inst, buffer, &length));
    printf("  movq $1, %%rax:      ");
    for (size_t i = 0; i < length; i++) printf("%02X ", buffer[i]);
    printf("\n");
    
    // movq $1, %rdi  
    operands[0].type = OPERAND_REGISTER;
    arch->parse_register("rdi", &operands[0].value.reg);
    operands[1].type = OPERAND_IMMEDIATE;
    operands[1].value.immediate = 1;
    
    arch->parse_instruction("movq", operands, 2, &inst);
    TEST_ASSERT_EQUAL(0, arch->encode_instruction(&inst, buffer, &length));
    printf("  movq $1, %%rdi:      ");
    for (size_t i = 0; i < length; i++) printf("%02X ", buffer[i]);
    printf("\n");
    
    // movq $14, %rdx
    operands[0].type = OPERAND_REGISTER;
    arch->parse_register("rdx", &operands[0].value.reg);
    operands[1].type = OPERAND_IMMEDIATE;
    operands[1].value.immediate = 14;
    
    arch->parse_instruction("movq", operands, 2, &inst);
    TEST_ASSERT_EQUAL(0, arch->encode_instruction(&inst, buffer, &length));
    printf("  movq $14, %%rdx:     ");
    for (size_t i = 0; i < length; i++) printf("%02X ", buffer[i]);
    printf("\n");
    
    // syscall
    arch->parse_instruction("syscall", operands, 0, &inst);
    TEST_ASSERT_EQUAL(0, arch->encode_instruction(&inst, buffer, &length));
    printf("  syscall:            ");
    for (size_t i = 0; i < length; i++) printf("%02X ", buffer[i]);
    printf("\n");
    
    // movq $60, %rax
    operands[0].type = OPERAND_REGISTER;
    arch->parse_register("rax", &operands[0].value.reg);
    operands[1].type = OPERAND_IMMEDIATE;
    operands[1].value.immediate = 60;
    
    arch->parse_instruction("movq", operands, 2, &inst);
    TEST_ASSERT_EQUAL(0, arch->encode_instruction(&inst, buffer, &length));
    printf("  movq $60, %%rax:     ");
    for (size_t i = 0; i < length; i++) printf("%02X ", buffer[i]);
    printf("\n");
    
    printf("✓ All Hello World instructions encoded successfully!\n");
}

int main(void) {
    UNITY_BEGIN();
    
    RUN_TEST(test_x86_64_comprehensive_instruction_encoding);
    RUN_TEST(test_x86_64_hello_world_program_encoding);
    
    return UNITY_END();
}
