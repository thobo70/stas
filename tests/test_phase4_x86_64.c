#include "unity.h"
#include "lexer.h"
#include "parser.h"
#include "arch_interface.h"

// x86-64 architecture operations
extern arch_ops_t *x86_64_get_arch_ops(void);

void setUp(void) {
    // This is run before each test
}

void tearDown(void) {
    // This is run after each test
}

void test_x86_64_basic_instruction_encoding(void) {
    printf("\n=== Testing x86-64 Basic Instruction Encoding ===\n");
    
    arch_ops_t *arch = x86_64_get_arch_ops();
    TEST_ASSERT_NOT_NULL(arch);
    TEST_ASSERT_EQUAL_STRING("x86_64", arch->name);
    
    // Test register parsing
    asm_register_t reg;
    int result = arch->parse_register("rax", &reg);
    TEST_ASSERT_EQUAL(0, result);
    TEST_ASSERT_TRUE(arch->is_valid_register(reg));
    
    printf("✓ Register parsing works\n");
    
    // Test 64-bit register parsing
    result = arch->parse_register("r8", &reg);
    TEST_ASSERT_EQUAL(0, result);
    TEST_ASSERT_TRUE(arch->is_valid_register(reg));
    
    printf("✓ Extended register parsing works\n");
}

void test_x86_64_instruction_parsing(void) {
    printf("\n=== Testing x86-64 Instruction Parsing ===\n");
    
    arch_ops_t *arch = x86_64_get_arch_ops();
    
    // Test basic instruction parsing
    operand_t operands[2];
    operands[0].type = OPERAND_REGISTER;
    arch->parse_register("rax", &operands[0].value.reg);
    
    operands[1].type = OPERAND_IMMEDIATE;
    operands[1].value.immediate = 60;
    
    instruction_t inst;
    int result = arch->parse_instruction("movq", operands, 2, &inst);
    TEST_ASSERT_EQUAL(0, result);
    TEST_ASSERT_EQUAL_STRING("movq", inst.mnemonic);
    TEST_ASSERT_EQUAL(2, inst.operand_count);
    
    printf("✓ Instruction parsing works\n");
}

void test_x86_64_instruction_encoding(void) {
    printf("\n=== Testing x86-64 Instruction Encoding ===\n");
    
    arch_ops_t *arch = x86_64_get_arch_ops();
    
    // Test syscall instruction (should produce 0x0F 0x05)
    operand_t operands[1];
    instruction_t inst;
    int result = arch->parse_instruction("syscall", operands, 0, &inst);
    TEST_ASSERT_EQUAL(0, result);
    
    uint8_t buffer[32];
    size_t length;
    result = arch->encode_instruction(&inst, buffer, &length);
    TEST_ASSERT_EQUAL(0, result);
    TEST_ASSERT_EQUAL(2, length);
    TEST_ASSERT_EQUAL_HEX8(0x0F, buffer[0]);
    TEST_ASSERT_EQUAL_HEX8(0x05, buffer[1]);
    
    printf("✓ SYSCALL encoding: 0x%02X 0x%02X\n", buffer[0], buffer[1]);
    
    // Test NOP instruction (should produce 0x90)
    result = arch->parse_instruction("nop", operands, 0, &inst);
    TEST_ASSERT_EQUAL(0, result);
    
    result = arch->encode_instruction(&inst, buffer, &length);
    TEST_ASSERT_EQUAL(0, result);
    TEST_ASSERT_EQUAL(1, length);
    TEST_ASSERT_EQUAL_HEX8(0x90, buffer[0]);
    
    printf("✓ NOP encoding: 0x%02X\n", buffer[0]);
}

void test_x86_64_register_to_register_mov(void) {
    printf("\n=== Testing x86-64 Register-to-Register MOV ===\n");
    
    arch_ops_t *arch = x86_64_get_arch_ops();
    
    // Test movq %rbx, %rax (should produce REX.W + 0x89 + ModR/M)
    operand_t operands[2];
    operands[0].type = OPERAND_REGISTER; // destination
    arch->parse_register("rax", &operands[0].value.reg);
    
    operands[1].type = OPERAND_REGISTER; // source
    arch->parse_register("rbx", &operands[1].value.reg);
    
    instruction_t inst;
    int result = arch->parse_instruction("movq", operands, 2, &inst);
    TEST_ASSERT_EQUAL(0, result);
    
    uint8_t buffer[32];
    size_t length;
    result = arch->encode_instruction(&inst, buffer, &length);
    
    TEST_ASSERT_EQUAL(0, result);
    TEST_ASSERT_EQUAL(3, length);
    TEST_ASSERT_EQUAL_HEX8(0x48, buffer[0]); // REX.W prefix
    TEST_ASSERT_EQUAL_HEX8(0x89, buffer[1]); // MOV opcode
    TEST_ASSERT_EQUAL_HEX8(0xD8, buffer[2]); // ModR/M: mod=11, reg=rbx(011), r/m=rax(000) = 11011000 = 0xD8
    
    printf("✓ MOV reg,reg encoding: REX.W(0x%02X) + 0x%02X + ModR/M(0x%02X)\n", 
           buffer[0], buffer[1], buffer[2]);
}

void test_x86_64_immediate_mov(void) {
    printf("\n=== Testing x86-64 Immediate MOV ===\n");
    
    arch_ops_t *arch = x86_64_get_arch_ops();
    
    // Test movq $60, %rax
    operand_t operands[2];
    operands[0].type = OPERAND_REGISTER;
    arch->parse_register("rax", &operands[0].value.reg);
    
    operands[1].type = OPERAND_IMMEDIATE;
    operands[1].value.immediate = 60;
    
    instruction_t inst;
    int result = arch->parse_instruction("movq", operands, 2, &inst);
    TEST_ASSERT_EQUAL(0, result);
    
    uint8_t buffer[32];
    size_t length;
    result = arch->encode_instruction(&inst, buffer, &length);
    
    TEST_ASSERT_EQUAL(0, result);
    TEST_ASSERT_EQUAL(10, length); // REX + opcode + 8-byte immediate
    TEST_ASSERT_EQUAL_HEX8(0x48, buffer[0]); // REX.W prefix
    TEST_ASSERT_EQUAL_HEX8(0xB8, buffer[1]); // MOV rax, imm64 opcode (0xB8+0)
    TEST_ASSERT_EQUAL_HEX8(60, buffer[2]);   // Immediate low byte
    TEST_ASSERT_EQUAL_HEX8(0, buffer[3]);    // Immediate bytes (little-endian)
    TEST_ASSERT_EQUAL_HEX8(0, buffer[4]);
    TEST_ASSERT_EQUAL_HEX8(0, buffer[5]);
    TEST_ASSERT_EQUAL_HEX8(0, buffer[6]);
    TEST_ASSERT_EQUAL_HEX8(0, buffer[7]);
    TEST_ASSERT_EQUAL_HEX8(0, buffer[8]);
    TEST_ASSERT_EQUAL_HEX8(0, buffer[9]);
    
    printf("✓ MOV reg,imm64 encoding: REX.W(0x%02X) + 0x%02X + imm64(%d)\n", 
           buffer[0], buffer[1], (int)operands[1].value.immediate);
}

void test_x86_64_arithmetic_instructions(void) {
    printf("\n=== Testing x86-64 Arithmetic Instructions ===\n");
    
    arch_ops_t *arch = x86_64_get_arch_ops();
    
    // Test addq %rbx, %rax
    operand_t operands[2];
    operands[0].type = OPERAND_REGISTER; // destination
    arch->parse_register("rax", &operands[0].value.reg);
    operands[1].type = OPERAND_REGISTER; // source
    arch->parse_register("rbx", &operands[1].value.reg);
    
    instruction_t inst;
    int result = arch->parse_instruction("addq", operands, 2, &inst);
    TEST_ASSERT_EQUAL(0, result);
    
    uint8_t buffer[32];
    size_t length;
    result = arch->encode_instruction(&inst, buffer, &length);
    
    TEST_ASSERT_EQUAL(0, result);
    TEST_ASSERT_EQUAL(3, length);
    TEST_ASSERT_EQUAL_HEX8(0x48, buffer[0]); // REX.W prefix
    TEST_ASSERT_EQUAL_HEX8(0x01, buffer[1]); // ADD opcode
    TEST_ASSERT_EQUAL_HEX8(0xD8, buffer[2]); // ModR/M
    
    printf("✓ ADD encoding: REX.W(0x%02X) + 0x%02X + ModR/M(0x%02X)\n", 
           buffer[0], buffer[1], buffer[2]);
    
    // Test subq %rbx, %rax
    result = arch->parse_instruction("subq", operands, 2, &inst);
    TEST_ASSERT_EQUAL(0, result);
    
    result = arch->encode_instruction(&inst, buffer, &length);
    
    TEST_ASSERT_EQUAL(0, result);
    TEST_ASSERT_EQUAL(3, length);
    TEST_ASSERT_EQUAL_HEX8(0x48, buffer[0]); // REX.W prefix
    TEST_ASSERT_EQUAL_HEX8(0x29, buffer[1]); // SUB opcode
    TEST_ASSERT_EQUAL_HEX8(0xD8, buffer[2]); // ModR/M
    
    printf("✓ SUB encoding: REX.W(0x%02X) + 0x%02X + ModR/M(0x%02X)\n", 
           buffer[0], buffer[1], buffer[2]);
}

void test_x86_64_stack_instructions(void) {
    printf("\n=== Testing x86-64 Stack Instructions ===\n");
    
    arch_ops_t *arch = x86_64_get_arch_ops();
    
    // Test push %rax
    operand_t operands[1];
    operands[0].type = OPERAND_REGISTER;
    arch->parse_register("rax", &operands[0].value.reg);
    
    instruction_t inst;
    int result = arch->parse_instruction("pushq", operands, 1, &inst);
    TEST_ASSERT_EQUAL(0, result);
    
    uint8_t buffer[32];
    size_t length;
    result = arch->encode_instruction(&inst, buffer, &length);
    
    TEST_ASSERT_EQUAL(0, result);
    TEST_ASSERT_EQUAL(1, length);
    TEST_ASSERT_EQUAL_HEX8(0x50, buffer[0]); // PUSH rax
    
    printf("✓ PUSH encoding: 0x%02X\n", buffer[0]);
    
    // Test pop %rax
    result = arch->parse_instruction("popq", operands, 1, &inst);
    TEST_ASSERT_EQUAL(0, result);
    
    result = arch->encode_instruction(&inst, buffer, &length);
    
    TEST_ASSERT_EQUAL(0, result);
    TEST_ASSERT_EQUAL(1, length);
    TEST_ASSERT_EQUAL_HEX8(0x58, buffer[0]); // POP rax
    
    printf("✓ POP encoding: 0x%02X\n", buffer[0]);
}

int main(void) {
    UNITY_BEGIN();
    
    RUN_TEST(test_x86_64_basic_instruction_encoding);
    RUN_TEST(test_x86_64_instruction_parsing);
    RUN_TEST(test_x86_64_instruction_encoding);
    RUN_TEST(test_x86_64_register_to_register_mov);
    RUN_TEST(test_x86_64_immediate_mov);
    RUN_TEST(test_x86_64_arithmetic_instructions);
    RUN_TEST(test_x86_64_stack_instructions);
    
    return UNITY_END();
}
