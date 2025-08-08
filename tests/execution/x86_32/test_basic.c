#include "../../unity/src/unity.h"
#include "../../framework/unicorn_test_framework.h"
#include "parser.h"
#include "lexer.h"
#include "codegen.h"
#include "../../src/core/output_format.h"
#include "symbols.h"
#include "arch_interface.h"
#include "../../src/arch/x86_32/x86_32.h"
#include <stdint.h>
#include <string.h>
#include <stdio.h>
#include <stdlib.h>

void setUp(void) {
    // Setup before each test
}

void tearDown(void) {
    // Cleanup after each test
}

// Helper function to assemble STAS source code and get machine code
typedef struct {
    uint8_t *code;
    size_t code_size;
    int success;
} assembly_result_t;

static assembly_result_t assemble_stas_source(const char *source_code) {
    assembly_result_t result = {0};
    
    // Initialize lexer
    lexer_t *lexer = lexer_create(source_code, "<test>");
    if (!lexer) {
        printf("Failed to create lexer\n");
        return result;
    }
    
    // Get x86-32 architecture operations first
    arch_ops_t *arch_ops = x86_32_get_arch_ops();
    if (!arch_ops) {
        printf("Failed to get x86-32 architecture operations\n");
        lexer_destroy(lexer);
        return result;
    }
    
    // Initialize parser (parser will create its own symbol table)
    parser_t *parser = parser_create(lexer, arch_ops);
    if (!parser) {
        printf("Failed to create parser\n");
        lexer_destroy(lexer);
        return result;
    }
    
    // Parse the source code
    ast_node_t *ast = parser_parse(parser);
    if (!ast) {
        printf("Failed to parse source code\n");
        parser_destroy(parser);
        lexer_destroy(lexer);
        return result;
    }
    
    // Create output context
    output_context_t *output = calloc(1, sizeof(output_context_t));
    if (!output) {
        printf("Failed to create output context\n");
        parser_destroy(parser);
        lexer_destroy(lexer);
        return result;
    }
    
    output->format = FORMAT_FLAT_BIN;
    output->base_address = 0x1000000;  // Match arch_x86_32.code_addr
    output->verbose = false;
    
    // Create codegen context (use parser's symbol table)
    codegen_ctx_t *codegen = codegen_create(arch_ops, output, parser->symbols);
    if (!codegen) {
        printf("Failed to create codegen context\n");
        free(output);
        parser_destroy(parser);
        lexer_destroy(lexer);
        return result;
    }
    
    // Generate machine code
    int gen_result = codegen_generate(codegen, ast);
    if (gen_result != 0) {
        printf("Failed to generate machine code: error %d\n", gen_result);
        codegen_destroy(codegen);
        free(output);
        parser_destroy(parser);
        lexer_destroy(lexer);
        return result;
    }
    
    // Extract the generated code
    if (codegen->total_code_size > 0) {
        result.code = malloc(codegen->total_code_size);
        if (result.code) {
            // We need to get the code from the output format
            // For now, let's try to get it from a flat binary format
            output_format_ops_t *format_ops = get_output_format(output->format);
            if (format_ops && format_ops->write_file) {
                // For flat binary, we can try to extract from sections
                if (output->section_count > 0 && output->sections) {
                    // Get the first section which should contain our code
                    output_section_t *section = &output->sections[0];
                    if (section->data && section->size > 0) {
                        memcpy(result.code, section->data, section->size);
                        result.code_size = section->size;
                        result.success = 1;
                    }
                }
            }
            
            // If format approach failed, try direct access (this might not work after flush)
            if (!result.success && codegen->code_buffer && codegen->code_size > 0) {
                memcpy(result.code, codegen->code_buffer, codegen->code_size);
                result.code_size = codegen->code_size;
                result.success = 1;
            }
        }
    }
    
    if (!result.success) {
        printf("Failed to extract generated machine code\n");
        if (result.code) {
            free(result.code);
            result.code = NULL;
        }
    } else {
        printf("Successfully assembled %zu bytes of machine code\n", result.code_size);
        printf("Machine code: ");
        for (size_t i = 0; i < result.code_size; i++) {
            printf("%02X ", result.code[i]);
        }
        printf("\n");
    }
    
    // Cleanup
    codegen_destroy(codegen);
    free(output);
    parser_destroy(parser);
    lexer_destroy(lexer);
    
    return result;
}

static void free_assembly_result(assembly_result_t *result) {
    if (result && result->code) {
        free(result->code);
        result->code = NULL;
        result->code_size = 0;
        result->success = 0;
    }
}

// Test STAS translation of basic MOV instruction with immediate value
void test_stas_mov_immediate_translation(void) {
    const char *source = "movl $0x12345678, %eax\n";
    
    assembly_result_t asm_result = assemble_stas_source(source);
    TEST_ASSERT_TRUE_MESSAGE(asm_result.success, "STAS failed to translate MOV immediate instruction");
    TEST_ASSERT_NOT_NULL_MESSAGE(asm_result.code, "No machine code generated for MOV immediate");
    
    // Verify the exact machine code bytes for movl $0x12345678, %eax
    // Expected: B8 78 56 34 12 (little-endian)
    TEST_ASSERT_EQUAL_MESSAGE(5, asm_result.code_size, "Incorrect machine code size for MOV immediate");
    TEST_ASSERT_EQUAL_HEX8_MESSAGE(0xB8, asm_result.code[0], "Incorrect opcode for MOV immediate to EAX");
    TEST_ASSERT_EQUAL_HEX8_MESSAGE(0x78, asm_result.code[1], "Incorrect immediate byte 0");
    TEST_ASSERT_EQUAL_HEX8_MESSAGE(0x56, asm_result.code[2], "Incorrect immediate byte 1");
    TEST_ASSERT_EQUAL_HEX8_MESSAGE(0x34, asm_result.code[3], "Incorrect immediate byte 2");
    TEST_ASSERT_EQUAL_HEX8_MESSAGE(0x12, asm_result.code[4], "Incorrect immediate byte 3");
    
    // Test execution behavior
    test_case_t* test = create_test_case(asm_result.code, asm_result.code_size);
    set_expected_register(test, X86_32_EAX, 0x12345678);
    
    TEST_ASSERT_EXECUTION_SUCCESS(&arch_x86_32, test);
    
    destroy_test_case(test);
    free_assembly_result(&asm_result);
}

// Test STAS translation of MOV between registers
void test_stas_mov_register_translation(void) {
    const char *source = 
        "movl $0x87654321, %eax\n"
        "movl %eax, %ebx\n";
    
    assembly_result_t asm_result = assemble_stas_source(source);
    TEST_ASSERT_TRUE_MESSAGE(asm_result.success, "STAS failed to translate MOV register instructions");
    TEST_ASSERT_NOT_NULL_MESSAGE(asm_result.code, "No machine code generated for MOV register");
    
    // Verify the machine code sequence
    // movl $0x87654321, %eax: B8 21 43 65 87
    // movl %eax, %ebx:        89 C3
    TEST_ASSERT_EQUAL_MESSAGE(7, asm_result.code_size, "Incorrect machine code size for MOV sequence");
    
    // First instruction: movl $0x87654321, %eax
    TEST_ASSERT_EQUAL_HEX8_MESSAGE(0xB8, asm_result.code[0], "Incorrect opcode for first MOV");
    TEST_ASSERT_EQUAL_HEX8_MESSAGE(0x21, asm_result.code[1], "Incorrect immediate byte 0");
    TEST_ASSERT_EQUAL_HEX8_MESSAGE(0x43, asm_result.code[2], "Incorrect immediate byte 1");
    TEST_ASSERT_EQUAL_HEX8_MESSAGE(0x65, asm_result.code[3], "Incorrect immediate byte 2");
    TEST_ASSERT_EQUAL_HEX8_MESSAGE(0x87, asm_result.code[4], "Incorrect immediate byte 3");
    
    // Second instruction: movl %eax, %ebx
    TEST_ASSERT_EQUAL_HEX8_MESSAGE(0x89, asm_result.code[5], "Incorrect opcode for second MOV");
    TEST_ASSERT_EQUAL_HEX8_MESSAGE(0xC3, asm_result.code[6], "Incorrect ModR/M byte for MOV EAX->EBX");
    
    // Test execution behavior
    test_case_t* test = create_test_case(asm_result.code, asm_result.code_size);
    set_expected_register(test, X86_32_EAX, 0x87654321);
    set_expected_register(test, X86_32_EBX, 0x87654321);
    
    TEST_ASSERT_EXECUTION_SUCCESS(&arch_x86_32, test);
    
    destroy_test_case(test);
    free_assembly_result(&asm_result);
}

// Test STAS translation of ADD instruction
void test_stas_add_instruction_translation(void) {
    const char *source = 
        "movl $100, %eax\n"
        "movl $50, %ebx\n"
        "addl %ebx, %eax\n";
    
    assembly_result_t asm_result = assemble_stas_source(source);
    TEST_ASSERT_TRUE_MESSAGE(asm_result.success, "STAS failed to translate ADD instruction sequence");
    TEST_ASSERT_NOT_NULL_MESSAGE(asm_result.code, "No machine code generated for ADD sequence");
    
    // Verify the machine code sequence
    // movl $100, %eax:  B8 64 00 00 00
    // movl $50, %ebx:   BB 32 00 00 00
    // addl %ebx, %eax:  01 D8
    TEST_ASSERT_EQUAL_MESSAGE(12, asm_result.code_size, "Incorrect machine code size for ADD sequence");
    
    // First instruction: movl $100, %eax
    TEST_ASSERT_EQUAL_HEX8_MESSAGE(0xB8, asm_result.code[0], "Incorrect opcode for first MOV");
    TEST_ASSERT_EQUAL_HEX8_MESSAGE(0x64, asm_result.code[1], "Incorrect immediate value 100");
    
    // Second instruction: movl $50, %ebx
    TEST_ASSERT_EQUAL_HEX8_MESSAGE(0xBB, asm_result.code[5], "Incorrect opcode for second MOV");
    TEST_ASSERT_EQUAL_HEX8_MESSAGE(0x32, asm_result.code[6], "Incorrect immediate value 50");
    
    // Third instruction: addl %ebx, %eax
    TEST_ASSERT_EQUAL_HEX8_MESSAGE(0x01, asm_result.code[10], "Incorrect opcode for ADD");
    TEST_ASSERT_EQUAL_HEX8_MESSAGE(0xD8, asm_result.code[11], "Incorrect ModR/M byte for ADD EBX->EAX");
    
    // Test execution behavior
    test_case_t* test = create_test_case(asm_result.code, asm_result.code_size);
    set_expected_register(test, X86_32_EAX, 150);  // 100 + 50
    set_expected_register(test, X86_32_EBX, 50);
    
    TEST_ASSERT_EXECUTION_SUCCESS(&arch_x86_32, test);
    
    destroy_test_case(test);
    free_assembly_result(&asm_result);
}

// Test STAS translation of SUB instruction
void test_stas_sub_instruction_translation(void) {
    const char *source = 
        "movl $200, %eax\n"
        "movl $80, %ebx\n"
        "subl %ebx, %eax\n";
    
    assembly_result_t asm_result = assemble_stas_source(source);
    TEST_ASSERT_TRUE_MESSAGE(asm_result.success, "STAS failed to translate SUB instruction sequence");
    TEST_ASSERT_NOT_NULL_MESSAGE(asm_result.code, "No machine code generated for SUB sequence");
    
    // Verify the SUB instruction specifically
    // subl %ebx, %eax should generate: 29 D8
    TEST_ASSERT_GREATER_THAN_MESSAGE(11, asm_result.code_size, "Machine code too short for SUB sequence");
    
    // Find the SUB instruction (should be at the end)
    size_t sub_offset = asm_result.code_size - 2;
    TEST_ASSERT_EQUAL_HEX8_MESSAGE(0x29, asm_result.code[sub_offset], "Incorrect opcode for SUB");
    TEST_ASSERT_EQUAL_HEX8_MESSAGE(0xD8, asm_result.code[sub_offset + 1], "Incorrect ModR/M byte for SUB EBX->EAX");
    
    // Test execution behavior
    test_case_t* test = create_test_case(asm_result.code, asm_result.code_size);
    set_expected_register(test, X86_32_EAX, 120);  // 200 - 80
    set_expected_register(test, X86_32_EBX, 80);
    
    TEST_ASSERT_EXECUTION_SUCCESS(&arch_x86_32, test);
    
    destroy_test_case(test);
    free_assembly_result(&asm_result);
}

// Test STAS translation of memory operations
void test_stas_memory_operations_translation(void) {
    const char *source = 
        "movl $0x1234, %eax\n"
        "movl %eax, (%esp)\n"
        "movl (%esp), %ebx\n";
    
    assembly_result_t asm_result = assemble_stas_source(source);
    TEST_ASSERT_TRUE_MESSAGE(asm_result.success, "STAS failed to translate memory operations");
    TEST_ASSERT_NOT_NULL_MESSAGE(asm_result.code, "No machine code generated for memory operations");
    
    // Verify key memory operation instructions
    // movl %eax, (%esp): 89 04 24
    // movl (%esp), %ebx: 8B 1C 24
    TEST_ASSERT_GREATER_THAN_MESSAGE(10, asm_result.code_size, "Machine code too short for memory operations");
    
    // Test execution behavior
    test_case_t* test = create_test_case(asm_result.code, asm_result.code_size);
    set_expected_register(test, X86_32_EAX, 0x1234);
    set_expected_register(test, X86_32_EBX, 0x1234);
    
    // Also verify memory contents
    uint8_t expected_mem[] = {0x34, 0x12, 0x00, 0x00};
    set_expected_memory(test, arch_x86_32.stack_addr + arch_x86_32.stack_size - 4, 
                       expected_mem, 4);
    
    TEST_ASSERT_EXECUTION_SUCCESS(&arch_x86_32, test);
    
    destroy_test_case(test);
    free_assembly_result(&asm_result);
}

// Test STAS translation of push/pop operations
void test_stas_push_pop_translation(void) {
    const char *source = 
        "movl $0x56789ABC, %eax\n"
        "pushl %eax\n"
        "popl %ebx\n";
    
    assembly_result_t asm_result = assemble_stas_source(source);
    TEST_ASSERT_TRUE_MESSAGE(asm_result.success, "STAS failed to translate push/pop operations");
    TEST_ASSERT_NOT_NULL_MESSAGE(asm_result.code, "No machine code generated for push/pop");
    
    // Verify push/pop instruction encoding
    // pushl %eax: 50
    // popl %ebx:  5B
    TEST_ASSERT_GREATER_THAN_MESSAGE(6, asm_result.code_size, "Machine code too short for push/pop");
    
    // Find push instruction (after the 5-byte MOV)
    TEST_ASSERT_EQUAL_HEX8_MESSAGE(0x50, asm_result.code[5], "Incorrect opcode for PUSH EAX");
    TEST_ASSERT_EQUAL_HEX8_MESSAGE(0x5B, asm_result.code[6], "Incorrect opcode for POP EBX");
    
    // Test execution behavior
    test_case_t* test = create_test_case(asm_result.code, asm_result.code_size);
    set_expected_register(test, X86_32_EAX, 0x56789ABC);
    set_expected_register(test, X86_32_EBX, 0x56789ABC);
    // Stack pointer should be back to original position
    set_expected_register(test, X86_32_ESP, arch_x86_32.stack_addr + arch_x86_32.stack_size - 4);
    
    TEST_ASSERT_EXECUTION_SUCCESS(&arch_x86_32, test);
    
    destroy_test_case(test);
    free_assembly_result(&asm_result);
}

// Test STAS translation of increment/decrement operations
void test_stas_inc_dec_translation(void) {
    const char *source = 
        "movl $100, %eax\n"
        "incl %eax\n"
        "decl %eax\n";
    
    assembly_result_t asm_result = assemble_stas_source(source);
    TEST_ASSERT_TRUE_MESSAGE(asm_result.success, "STAS failed to translate inc/dec operations");
    TEST_ASSERT_NOT_NULL_MESSAGE(asm_result.code, "No machine code generated for inc/dec");
    
    // Verify inc/dec instruction encoding
    // incl %eax: 40
    // decl %eax: 48
    TEST_ASSERT_GREATER_THAN_MESSAGE(6, asm_result.code_size, "Machine code too short for inc/dec");
    
    // Find inc/dec instructions (after the 5-byte MOV)
    TEST_ASSERT_EQUAL_HEX8_MESSAGE(0x40, asm_result.code[5], "Incorrect opcode for INC EAX");
    TEST_ASSERT_EQUAL_HEX8_MESSAGE(0x48, asm_result.code[6], "Incorrect opcode for DEC EAX");
    
    // Test execution behavior
    test_case_t* test = create_test_case(asm_result.code, asm_result.code_size);
    set_expected_register(test, X86_32_EAX, 100); // Should be back to 100
    
    TEST_ASSERT_EXECUTION_SUCCESS(&arch_x86_32, test);
    
    destroy_test_case(test);
    free_assembly_result(&asm_result);
}

// Test STAS translation of bitwise AND operation
void test_stas_and_operation_translation(void) {
    const char *source = 
        "movl $0xFFFF0000, %eax\n"
        "movl $0x0000FFFF, %ebx\n"
        "andl %ebx, %eax\n";
    
    assembly_result_t asm_result = assemble_stas_source(source);
    TEST_ASSERT_TRUE_MESSAGE(asm_result.success, "STAS failed to translate AND operation");
    TEST_ASSERT_NOT_NULL_MESSAGE(asm_result.code, "No machine code generated for AND operation");
    
    // Verify AND instruction encoding
    // andl %ebx, %eax: 21 D8
    TEST_ASSERT_GREATER_THAN_MESSAGE(11, asm_result.code_size, "Machine code too short for AND operation");
    
    // Find AND instruction (should be at the end)
    size_t and_offset = asm_result.code_size - 2;
    TEST_ASSERT_EQUAL_HEX8_MESSAGE(0x21, asm_result.code[and_offset], "Incorrect opcode for AND");
    TEST_ASSERT_EQUAL_HEX8_MESSAGE(0xD8, asm_result.code[and_offset + 1], "Incorrect ModR/M byte for AND EBX->EAX");
    
    // Test execution behavior
    test_case_t* test = create_test_case(asm_result.code, asm_result.code_size);
    set_expected_register(test, X86_32_EAX, 0x00000000); // 0xFFFF0000 & 0x0000FFFF = 0x00000000
    set_expected_register(test, X86_32_EBX, 0x0000FFFF);
    
    TEST_ASSERT_EXECUTION_SUCCESS(&arch_x86_32, test);
    
    destroy_test_case(test);
    free_assembly_result(&asm_result);
}

// Test STAS translation of bitwise OR operation  
void test_stas_or_operation_translation(void) {
    const char *source = 
        "movl $0xFF00FF00, %eax\n"
        "movl $0x00FF00FF, %ebx\n"
        "orl %ebx, %eax\n";
    
    assembly_result_t asm_result = assemble_stas_source(source);
    TEST_ASSERT_TRUE_MESSAGE(asm_result.success, "STAS failed to translate OR operation");
    TEST_ASSERT_NOT_NULL_MESSAGE(asm_result.code, "No machine code generated for OR operation");
    
    // Verify OR instruction encoding
    // orl %ebx, %eax: 09 D8
    TEST_ASSERT_GREATER_THAN_MESSAGE(11, asm_result.code_size, "Machine code too short for OR operation");
    
    // Find OR instruction (should be at the end)
    size_t or_offset = asm_result.code_size - 2;
    TEST_ASSERT_EQUAL_HEX8_MESSAGE(0x09, asm_result.code[or_offset], "Incorrect opcode for OR");
    TEST_ASSERT_EQUAL_HEX8_MESSAGE(0xD8, asm_result.code[or_offset + 1], "Incorrect ModR/M byte for OR EBX->EAX");
    
    // Test execution behavior
    test_case_t* test = create_test_case(asm_result.code, asm_result.code_size);
    set_expected_register(test, X86_32_EAX, 0xFFFFFFFF); // OR should result in all 1s
    set_expected_register(test, X86_32_EBX, 0x00FF00FF);
    
    TEST_ASSERT_EXECUTION_SUCCESS(&arch_x86_32, test);
    
    destroy_test_case(test);
    free_assembly_result(&asm_result);
}

// Test STAS translation of compare instruction
void test_stas_cmp_instruction_translation(void) {
    const char *source = 
        "movl $1000, %eax\n"
        "movl $1000, %ebx\n"
        "cmpl %ebx, %eax\n";
    
    assembly_result_t asm_result = assemble_stas_source(source);
    TEST_ASSERT_TRUE_MESSAGE(asm_result.success, "STAS failed to translate CMP instruction");
    TEST_ASSERT_NOT_NULL_MESSAGE(asm_result.code, "No machine code generated for CMP instruction");
    
    // Verify CMP instruction encoding
    // cmpl %ebx, %eax: 39 D8
    TEST_ASSERT_GREATER_THAN_MESSAGE(11, asm_result.code_size, "Machine code too short for CMP instruction");
    
    // Find CMP instruction (should be at the end)
    size_t cmp_offset = asm_result.code_size - 2;
    TEST_ASSERT_EQUAL_HEX8_MESSAGE(0x39, asm_result.code[cmp_offset], "Incorrect opcode for CMP");
    TEST_ASSERT_EQUAL_HEX8_MESSAGE(0xD8, asm_result.code[cmp_offset + 1], "Incorrect ModR/M byte for CMP EBX->EAX");
    
    // Test execution behavior
    test_case_t* test = create_test_case(asm_result.code, asm_result.code_size);
    set_expected_register(test, X86_32_EAX, 1000);
    set_expected_register(test, X86_32_EBX, 1000);
    
    TEST_ASSERT_EXECUTION_SUCCESS(&arch_x86_32, test);
    
    destroy_test_case(test);
    free_assembly_result(&asm_result);
}

int main(void) {
    UNITY_BEGIN();
    
    // Test STAS translation of basic instructions
    RUN_TEST(test_stas_mov_immediate_translation);
    RUN_TEST(test_stas_mov_register_translation);
    
    // Test STAS translation of arithmetic operations
    RUN_TEST(test_stas_add_instruction_translation);
    RUN_TEST(test_stas_sub_instruction_translation);
    RUN_TEST(test_stas_inc_dec_translation);
    
    // Test STAS translation of memory operations
    RUN_TEST(test_stas_memory_operations_translation);
    RUN_TEST(test_stas_push_pop_translation);
    
    // Test STAS translation of bitwise operations
    RUN_TEST(test_stas_and_operation_translation);
    RUN_TEST(test_stas_or_operation_translation);
    
    // Test STAS translation of comparison operations
    RUN_TEST(test_stas_cmp_instruction_translation);
    
    return UNITY_END();
}
