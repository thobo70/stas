/*
 * Comprehensive x86_16 Test with Unicorn Engine
 * Tests STAS x86_16 code generation and validates execution with Unicorn
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <stdbool.h>
#include <assert.h>

// Unicorn Engine includes
#include <unicorn/unicorn.h>

// STAS includes
#include "../src/arch/x86_16/x86_16.h"
#include "../src/core/output_format.h"
#include "../src/arch/arch_interface.h"

// Test configuration
#define CODE_BASE_ADDRESS 0x1000
#define CODE_SIZE 0x1000
#define STACK_BASE 0x2000
#define STACK_SIZE 0x1000

// Test results structure
typedef struct {
    const char *test_name;
    bool passed;
    const char *error_message;
    uint8_t *generated_code;
    size_t code_length;
    uint16_t expected_ax;
    uint16_t actual_ax;
} test_result_t;

// Function prototypes
static test_result_t test_simple_mov(void);
static test_result_t test_arithmetic_operations(void);
static test_result_t test_stack_operations(void);
static test_result_t test_conditional_jumps(void);
static test_result_t test_dos_program(void);
static bool execute_x86_16_code(uint8_t *code, size_t code_size, uint16_t *ax_result);
static void print_test_result(const test_result_t *result);
static void print_code_bytes(const uint8_t *code, size_t length);
static test_result_t create_test_result(const char *name, bool passed, const char *error);

// Helper function to encode a single instruction
static bool encode_instruction_helper(const char *mnemonic, operand_t *operands, 
                                    size_t operand_count, uint8_t *buffer, size_t *length) {
    arch_ops_t *arch = get_arch_ops_x86_16();
    if (!arch) return false;
    
    instruction_t inst = {0};
    
    if (arch->parse_instruction(mnemonic, operands, operand_count, &inst) != 0) {
        return false;
    }
    
    if (arch->encode_instruction(&inst, buffer, length) != 0) {
        // Cleanup
        if (inst.mnemonic) free(inst.mnemonic);
        if (inst.operands) free(inst.operands);
        if (inst.encoding) free(inst.encoding);
        return false;
    }
    
    // Cleanup
    if (inst.mnemonic) free(inst.mnemonic);
    if (inst.operands) free(inst.operands);
    if (inst.encoding) free(inst.encoding);
    
    return true;
}

int main(void) {
    printf("=== STAS x86_16 Comprehensive Test Suite ===\n\n");
    
    // Initialize x86_16 architecture
    arch_ops_t *arch = get_arch_ops_x86_16();
    if (!arch || !arch->init) {
        printf("ERROR: Failed to initialize x86_16 architecture\n");
        return 1;
    }
    
    if (arch->init() != 0) {
        printf("ERROR: x86_16 architecture initialization failed\n");
        return 1;
    }
    
    printf("x86_16 architecture initialized successfully\n\n");
    
    // Run tests
    test_result_t tests[] = {
        test_simple_mov(),
        test_arithmetic_operations(),
        test_stack_operations(),
        test_conditional_jumps(),
        test_dos_program()
    };
    
    size_t test_count = sizeof(tests) / sizeof(tests[0]);
    size_t passed_count = 0;
    
    // Print results
    printf("=== Test Results ===\n");
    for (size_t i = 0; i < test_count; i++) {
        print_test_result(&tests[i]);
        if (tests[i].passed) {
            passed_count++;
        }
    }
    
    printf("\n=== Summary ===\n");
    printf("Tests passed: %zu/%zu\n", passed_count, test_count);
    printf("Success rate: %.1f%%\n", (double)passed_count / test_count * 100.0);
    
    // Cleanup
    if (arch->cleanup) {
        arch->cleanup();
    }
    
    return (passed_count == test_count) ? 0 : 1;
}

// Test 1: Simple MOV instruction
static test_result_t test_simple_mov(void) {
    const char *test_name = "Simple MOV instruction";
    uint8_t code_buffer[16];
    size_t code_length = 0;
    
    // Create MOV AX, 0x1234 instruction (AT&T syntax: movw $0x1234, %ax)
    operand_t operands[2];
    
    // Source: immediate value 0x1234 (first operand in AT&T)
    operands[0].type = OPERAND_IMMEDIATE;
    operands[0].value.immediate = 0x1234;
    operands[0].size = 2;
    
    // Destination: AX register (second operand in AT&T)
    operands[1].type = OPERAND_REGISTER;
    operands[1].value.reg.id = AX_16;
    operands[1].value.reg.name = "ax";
    operands[1].value.reg.size = 2;
    operands[1].size = 2;
    
    if (!encode_instruction_helper("mov", operands, 2, code_buffer, &code_length)) {
        return create_test_result(test_name, false, "Failed to encode MOV instruction");
    }
    
    printf("Test: %s\n", test_name);
    printf("Generated code (%zu bytes): ", code_length);
    print_code_bytes(code_buffer, code_length);
    
    // Expected: B8 34 12 (mov ax, 0x1234)
    uint8_t expected[] = {0xB8, 0x34, 0x12};
    if (code_length != sizeof(expected) || memcmp(code_buffer, expected, code_length) != 0) {
        printf("Expected: ");
        print_code_bytes(expected, sizeof(expected));
        return create_test_result(test_name, false, "Generated code doesn't match expected");
    }
    
    // Execute with Unicorn Engine
    uint16_t ax_result = 0;
    if (!execute_x86_16_code(code_buffer, code_length, &ax_result)) {
        return create_test_result(test_name, false, "Unicorn execution failed");
    }
    
    if (ax_result != 0x1234) {
        return create_test_result(test_name, false, "AX register value incorrect after execution");
    }
    
    test_result_t result = create_test_result(test_name, true, NULL);
    result.generated_code = malloc(code_length);
    memcpy(result.generated_code, code_buffer, code_length);
    result.code_length = code_length;
    result.expected_ax = 0x1234;
    result.actual_ax = ax_result;
    
    return result;
}

// Test 2: Arithmetic operations
static test_result_t test_arithmetic_operations(void) {
    const char *test_name = "Arithmetic operations";
    uint8_t code_buffer[32];
    size_t total_length = 0;
    
    printf("Test: %s\n", test_name);
    
    // MOV AX, 10 (AT&T syntax: movw $10, %ax)
    operand_t mov_operands[2];
    mov_operands[0].type = OPERAND_IMMEDIATE;
    mov_operands[0].value.immediate = 10;
    mov_operands[0].size = 2;
    mov_operands[1].type = OPERAND_REGISTER;
    mov_operands[1].value.reg.id = AX_16;
    mov_operands[1].value.reg.name = "ax";
    mov_operands[1].value.reg.size = 2;
    mov_operands[1].size = 2;
    mov_operands[1].size = 2;
    
    size_t inst_length = 0;
    if (!encode_instruction_helper("mov", mov_operands, 2, code_buffer + total_length, &inst_length)) {
        return create_test_result(test_name, false, "Failed to encode MOV instruction");
    }
    total_length += inst_length;
    
    // MOV BX, 5 (AT&T syntax: movw $5, %bx)
    operand_t mov_bx_operands[2];
    mov_bx_operands[0].type = OPERAND_IMMEDIATE;
    mov_bx_operands[0].value.immediate = 5;
    mov_bx_operands[0].size = 2;
    mov_bx_operands[1].type = OPERAND_REGISTER;
    mov_bx_operands[1].value.reg.id = BX_16;
    mov_bx_operands[1].value.reg.name = "bx";
    mov_bx_operands[1].value.reg.size = 2;
    mov_bx_operands[1].size = 2;
    
    if (!encode_instruction_helper("mov", mov_bx_operands, 2, code_buffer + total_length, &inst_length)) {
        return create_test_result(test_name, false, "Failed to encode MOV BX instruction");
    }
    total_length += inst_length;
    
    // ADD AX, BX (10 + 5 = 15) (AT&T syntax: addw %bx, %ax)
    operand_t add_operands[2];
    add_operands[0].type = OPERAND_REGISTER;
    add_operands[0].value.reg.id = BX_16;
    add_operands[0].value.reg.name = "bx";
    add_operands[0].value.reg.size = 2;
    add_operands[0].size = 2;
    add_operands[1].type = OPERAND_REGISTER;
    add_operands[1].value.reg.id = AX_16;
    add_operands[1].value.reg.name = "ax";
    add_operands[1].value.reg.size = 2;
    add_operands[1].size = 2;
    
    if (!encode_instruction_helper("add", add_operands, 2, code_buffer + total_length, &inst_length)) {
        return create_test_result(test_name, false, "Failed to encode ADD instruction");
    }
    total_length += inst_length;
    
    printf("Generated code (%zu bytes): ", total_length);
    print_code_bytes(code_buffer, total_length);
    
    // Execute with Unicorn Engine
    uint16_t ax_result = 0;
    if (!execute_x86_16_code(code_buffer, total_length, &ax_result)) {
        return create_test_result(test_name, false, "Unicorn execution failed");
    }
    
    if (ax_result != 15) {
        return create_test_result(test_name, false, "Arithmetic result incorrect");
    }
    
    test_result_t result = create_test_result(test_name, true, NULL);
    result.generated_code = malloc(total_length);
    memcpy(result.generated_code, code_buffer, total_length);
    result.code_length = total_length;
    result.expected_ax = 15;
    result.actual_ax = ax_result;
    
    return result;
}

// Test 3: Stack operations
static test_result_t test_stack_operations(void) {
    const char *test_name = "Stack operations";
    uint8_t code_buffer[32];
    size_t total_length = 0;
    
    printf("Test: %s\n", test_name);
    
    // MOV AX, 0x5678 (AT&T syntax: movw $0x5678, %ax)
    operand_t mov_operands[2];
    mov_operands[0].type = OPERAND_IMMEDIATE;
    mov_operands[0].value.immediate = 0x5678;
    mov_operands[0].size = 2;
    mov_operands[1].type = OPERAND_REGISTER;
    mov_operands[1].value.reg.id = AX_16;
    mov_operands[1].value.reg.name = "ax";
    mov_operands[1].value.reg.size = 2;
    mov_operands[1].size = 2;
    
    size_t inst_length = 0;
    if (!encode_instruction_helper("mov", mov_operands, 2, code_buffer + total_length, &inst_length)) {
        return create_test_result(test_name, false, "Failed to encode MOV instruction");
    }
    total_length += inst_length;
    
    // PUSH AX
    operand_t push_operands[1];
    push_operands[0].type = OPERAND_REGISTER;
    push_operands[0].value.reg.id = AX_16;
    push_operands[0].value.reg.name = "ax";
    push_operands[0].value.reg.size = 2;
    push_operands[0].size = 2;
    
    if (!encode_instruction_helper("push", push_operands, 1, code_buffer + total_length, &inst_length)) {
        return create_test_result(test_name, false, "Failed to encode PUSH instruction");
    }
    total_length += inst_length;
    
    // MOV AX, 0x1234 (overwrite AX)
    mov_operands[1].value.immediate = 0x1234;
    if (!encode_instruction_helper("mov", mov_operands, 2, code_buffer + total_length, &inst_length)) {
        return create_test_result(test_name, false, "Failed to encode second MOV instruction");
    }
    total_length += inst_length;
    
    // POP AX (should restore 0x5678)
    operand_t pop_operands[1];
    pop_operands[0].type = OPERAND_REGISTER;
    pop_operands[0].value.reg.id = AX_16;
    pop_operands[0].value.reg.name = "ax";
    pop_operands[0].value.reg.size = 2;
    pop_operands[0].size = 2;
    
    if (!encode_instruction_helper("pop", pop_operands, 1, code_buffer + total_length, &inst_length)) {
        return create_test_result(test_name, false, "Failed to encode POP instruction");
    }
    total_length += inst_length;
    
    printf("Generated code (%zu bytes): ", total_length);
    print_code_bytes(code_buffer, total_length);
    
    // Execute with Unicorn Engine
    uint16_t ax_result = 0;
    if (!execute_x86_16_code(code_buffer, total_length, &ax_result)) {
        return create_test_result(test_name, false, "Unicorn execution failed");
    }
    
    if (ax_result != 0x5678) {
        return create_test_result(test_name, false, "Stack operation result incorrect");
    }
    
    test_result_t result = create_test_result(test_name, true, NULL);
    result.generated_code = malloc(total_length);
    memcpy(result.generated_code, code_buffer, total_length);
    result.code_length = total_length;
    result.expected_ax = 0x5678;
    result.actual_ax = ax_result;
    
    return result;
}

// Test 4: Conditional jumps
static test_result_t test_conditional_jumps(void) {
    const char *test_name = "Conditional jumps";
    uint8_t code_buffer[32];
    size_t total_length = 0;
    
    printf("Test: %s\n", test_name);
    
    // MOV AX, 5 (AT&T syntax: movw $5, %ax)
    operand_t mov_operands[2];
    mov_operands[0].type = OPERAND_IMMEDIATE;
    mov_operands[0].value.immediate = 5;
    mov_operands[0].size = 2;
    mov_operands[1].type = OPERAND_REGISTER;
    mov_operands[1].value.reg.id = AX_16;
    mov_operands[1].value.reg.name = "ax";
    mov_operands[1].value.reg.size = 2;
    mov_operands[1].size = 2;
    
    size_t inst_length = 0;
    if (!encode_instruction_helper("mov", mov_operands, 2, code_buffer + total_length, &inst_length)) {
        return create_test_result(test_name, false, "Failed to encode MOV instruction");
    }
    total_length += inst_length;
    
    // CMP AX, 5 (AT&T syntax: cmpw $5, %ax)
    operand_t cmp_operands[2];
    cmp_operands[0].type = OPERAND_IMMEDIATE;
    cmp_operands[0].value.immediate = 5;
    cmp_operands[0].size = 2;
    cmp_operands[1].type = OPERAND_REGISTER;
    cmp_operands[1].value.reg.id = AX_16;
    cmp_operands[1].value.reg.name = "ax";
    cmp_operands[1].value.reg.size = 2;
    cmp_operands[1].size = 2;
    
    if (!encode_instruction_helper("cmp", cmp_operands, 2, code_buffer + total_length, &inst_length)) {
        return create_test_result(test_name, false, "Failed to encode CMP instruction");
    }
    total_length += inst_length;
    
    // JE +3 (jump over the next instruction if equal)
    operand_t je_operands[1];
    je_operands[0].type = OPERAND_IMMEDIATE;
    je_operands[0].value.immediate = 3; // Skip 3 bytes ahead (MOV AX, 0xFFFF)
    je_operands[0].size = 1;
    
    if (!encode_instruction_helper("je", je_operands, 1, code_buffer + total_length, &inst_length)) {
        return create_test_result(test_name, false, "Failed to encode JE instruction");
    }
    total_length += inst_length;
    
    // MOV AX, 0xFFFF (should be skipped)
    mov_operands[1].value.immediate = 0xFFFF;
    if (!encode_instruction_helper("mov", mov_operands, 2, code_buffer + total_length, &inst_length)) {
        return create_test_result(test_name, false, "Failed to encode conditional MOV instruction");
    }
    total_length += inst_length;
    
    // MOV AX, 0x9999 (should be executed)
    mov_operands[1].value.immediate = 0x9999;
    if (!encode_instruction_helper("mov", mov_operands, 2, code_buffer + total_length, &inst_length)) {
        return create_test_result(test_name, false, "Failed to encode final MOV instruction");
    }
    total_length += inst_length;
    
    printf("Generated code (%zu bytes): ", total_length);
    print_code_bytes(code_buffer, total_length);
    
    // Execute with Unicorn Engine
    uint16_t ax_result = 0;
    if (!execute_x86_16_code(code_buffer, total_length, &ax_result)) {
        return create_test_result(test_name, false, "Unicorn execution failed");
    }
    
    // Since 5 == 5, the jump should be taken, skipping the 0xFFFF assignment
    // AX should contain 0x9999
    if (ax_result != 0x9999) {
        return create_test_result(test_name, false, "Conditional jump logic incorrect");
    }
    
    test_result_t result = create_test_result(test_name, true, NULL);
    result.generated_code = malloc(total_length);
    memcpy(result.generated_code, code_buffer, total_length);
    result.code_length = total_length;
    result.expected_ax = 0x9999;
    result.actual_ax = ax_result;
    
    return result;
}

// Test 5: Complete DOS program
static test_result_t test_dos_program(void) {
    const char *test_name = "DOS exit program";
    uint8_t code_buffer[16];
    size_t total_length = 0;
    
    printf("Test: %s\n", test_name);
    
    // MOV AX, 0x4C00 (DOS exit function) (AT&T syntax: movw $0x4C00, %ax)
    operand_t mov_operands[2];
    mov_operands[0].type = OPERAND_IMMEDIATE;
    mov_operands[0].value.immediate = 0x4C00;
    mov_operands[0].size = 2;
    mov_operands[1].type = OPERAND_REGISTER;
    mov_operands[1].value.reg.id = AX_16;
    mov_operands[1].value.reg.name = "ax";
    mov_operands[1].value.reg.size = 2;
    mov_operands[1].size = 2;
    
    size_t inst_length = 0;
    if (!encode_instruction_helper("mov", mov_operands, 2, code_buffer + total_length, &inst_length)) {
        return create_test_result(test_name, false, "Failed to encode MOV instruction");
    }
    total_length += inst_length;
    
    // INT 0x21 (DOS interrupt)
    operand_t int_operands[1];
    int_operands[0].type = OPERAND_IMMEDIATE;
    int_operands[0].value.immediate = 0x21;
    int_operands[0].size = 1;
    
    if (!encode_instruction_helper("int", int_operands, 1, code_buffer + total_length, &inst_length)) {
        return create_test_result(test_name, false, "Failed to encode INT instruction");
    }
    total_length += inst_length;
    
    printf("Generated code (%zu bytes): ", total_length);
    print_code_bytes(code_buffer, total_length);
    
    // Expected DOS exit program: B8 00 4C CD 21
    uint8_t expected[] = {0xB8, 0x00, 0x4C, 0xCD, 0x21};
    if (total_length != sizeof(expected) || memcmp(code_buffer, expected, total_length) != 0) {
        printf("Expected: ");
        print_code_bytes(expected, sizeof(expected));
        return create_test_result(test_name, false, "Generated DOS program doesn't match expected");
    }
    
    // For DOS program, we don't execute with Unicorn (would try to call DOS)
    // Just verify the code generation is correct
    
    test_result_t result = create_test_result(test_name, true, NULL);
    result.generated_code = malloc(total_length);
    memcpy(result.generated_code, code_buffer, total_length);
    result.code_length = total_length;
    result.expected_ax = 0x4C00;
    result.actual_ax = 0x4C00; // We know this from the MOV instruction
    
    return result;
}

// Execute x86_16 code using Unicorn Engine
static bool execute_x86_16_code(uint8_t *code, size_t code_size, uint16_t *ax_result) {
    uc_engine *uc;
    uc_err err;
    
    // Initialize Unicorn Engine for x86 16-bit
    err = uc_open(UC_ARCH_X86, UC_MODE_16, &uc);
    if (err != UC_ERR_OK) {
        printf("Unicorn Engine error: Failed to initialize - %s\n", uc_strerror(err));
        return false;
    }
    
    // Map memory for code
    err = uc_mem_map(uc, CODE_BASE_ADDRESS, CODE_SIZE, UC_PROT_ALL);
    if (err != UC_ERR_OK) {
        printf("Unicorn Engine error: Failed to map code memory - %s\n", uc_strerror(err));
        uc_close(uc);
        return false;
    }
    
    // Map memory for stack
    err = uc_mem_map(uc, STACK_BASE, STACK_SIZE, UC_PROT_READ | UC_PROT_WRITE);
    if (err != UC_ERR_OK) {
        printf("Unicorn Engine error: Failed to map stack memory - %s\n", uc_strerror(err));
        uc_close(uc);
        return false;
    }
    
    // Write code to memory
    err = uc_mem_write(uc, CODE_BASE_ADDRESS, code, code_size);
    if (err != UC_ERR_OK) {
        printf("Unicorn Engine error: Failed to write code - %s\n", uc_strerror(err));
        uc_close(uc);
        return false;
    }
    
    // Set up stack pointer
    uint16_t sp = STACK_BASE + STACK_SIZE - 2;
    err = uc_reg_write(uc, UC_X86_REG_SP, &sp);
    if (err != UC_ERR_OK) {
        printf("Unicorn Engine error: Failed to set SP - %s\n", uc_strerror(err));
        uc_close(uc);
        return false;
    }
    
    // Execute the code
    err = uc_emu_start(uc, CODE_BASE_ADDRESS, CODE_BASE_ADDRESS + code_size, 0, 0);
    if (err != UC_ERR_OK) {
        printf("Unicorn Engine error: Failed to execute code - %s\n", uc_strerror(err));
        uc_close(uc);
        return false;
    }
    
    // Read AX register result
    err = uc_reg_read(uc, UC_X86_REG_AX, ax_result);
    if (err != UC_ERR_OK) {
        printf("Unicorn Engine error: Failed to read AX register - %s\n", uc_strerror(err));
        uc_close(uc);
        return false;
    }
    
    uc_close(uc);
    return true;
}

// Helper functions
static void print_test_result(const test_result_t *result) {
    printf("\n--- %s ---\n", result->test_name);
    printf("Status: %s\n", result->passed ? "PASSED" : "FAILED");
    
    if (result->generated_code && result->code_length > 0) {
        printf("Generated code (%zu bytes): ", result->code_length);
        print_code_bytes(result->generated_code, result->code_length);
    }
    
    if (result->passed) {
        printf("Expected AX: 0x%04X, Actual AX: 0x%04X\n", 
               result->expected_ax, result->actual_ax);
    } else if (result->error_message) {
        printf("Error: %s\n", result->error_message);
    }
    
    if (result->generated_code) {
        free(result->generated_code);
    }
}

static void print_code_bytes(const uint8_t *code, size_t length) {
    for (size_t i = 0; i < length; i++) {
        printf("%02X ", code[i]);
    }
    printf("\n");
}

static test_result_t create_test_result(const char *name, bool passed, const char *error) {
    test_result_t result = {0};
    result.test_name = name;
    result.passed = passed;
    result.error_message = error;
    result.generated_code = NULL;
    result.code_length = 0;
    result.expected_ax = 0;
    result.actual_ax = 0;
    return result;
}
