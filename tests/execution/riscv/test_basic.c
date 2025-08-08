#include "../../unity/src/unity.h"
#include "../../framework/unicorn_test_framework.h"
#include "parser.h"
#include "lexer.h"
#include "codegen.h"
#include "../../src/core/output_format.h"
#include "symbols.h"
#include "arch_interface.h"
#include "riscv.h"
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
    
    // Get RISC-V architecture operations first
    arch_ops_t *arch_ops = get_riscv_arch_ops();
    if (!arch_ops) {
        printf("Failed to get RISC-V architecture operations\n");
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
    output->base_address = 0x1000000;  // Match arch_riscv.code_addr
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
    if (output->sections && output->section_count > 0) {
        // Get the first section which should contain our code
        output_section_t *section = &output->sections[0];
        if (section->data && section->size > 0) {
            result.code = malloc(section->size);
            if (result.code) {
                memcpy(result.code, section->data, section->size);
                result.code_size = section->size;
                result.success = 1;
                printf("Successfully assembled %zu bytes of machine code\n", result.code_size);
                printf("Machine code: ");
                for (size_t i = 0; i < result.code_size; i++) {
                    printf("%02X ", result.code[i]);
                }
                printf("\n");
            }
        }
    }
    
    if (!result.success) {
        printf("Failed to extract generated machine code\n");
        if (result.code) {
            free(result.code);
            result.code = NULL;
        }
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

// Test STAS translation of basic ADDI instruction
void test_stas_addi_immediate_translation(void) {
    const char *source = "addi x1, x0, 100\n";
    
    assembly_result_t asm_result = assemble_stas_source(source);
    TEST_ASSERT_TRUE_MESSAGE(asm_result.success, "STAS failed to translate ADDI immediate instruction");
    TEST_ASSERT_NOT_NULL_MESSAGE(asm_result.code, "No machine code generated for ADDI immediate");
    
    // Test execution behavior
    test_case_t* test = create_test_case(asm_result.code, asm_result.code_size);
    set_expected_register(test, RISCV_X1, 100);
    
    TEST_ASSERT_EXECUTION_SUCCESS(&arch_riscv, test);
    
    destroy_test_case(test);
    free_assembly_result(&asm_result);
}

// Test STAS translation of ADD between registers
void test_stas_add_registers_translation(void) {
    const char *source = 
        "addi x1, x0, 50\n"
        "addi x2, x0, 30\n"
        "add x3, x1, x2\n";
    
    assembly_result_t asm_result = assemble_stas_source(source);
    TEST_ASSERT_TRUE_MESSAGE(asm_result.success, "STAS failed to translate ADD register instructions");
    TEST_ASSERT_NOT_NULL_MESSAGE(asm_result.code, "No machine code generated for ADD registers");
    
    // Test execution behavior
    test_case_t* test = create_test_case(asm_result.code, asm_result.code_size);
    set_expected_register(test, RISCV_X1, 50);
    set_expected_register(test, RISCV_X2, 30);
    set_expected_register(test, RISCV_X3, 80);  // 50 + 30
    
    TEST_ASSERT_EXECUTION_SUCCESS(&arch_riscv, test);
    
    destroy_test_case(test);
    free_assembly_result(&asm_result);
}

// Test STAS translation of SUB instruction
void test_stas_sub_instruction_translation(void) {
    const char *source = 
        "addi x1, x0, 200\n"
        "addi x2, x0, 80\n"
        "sub x3, x1, x2\n";
    
    assembly_result_t asm_result = assemble_stas_source(source);
    TEST_ASSERT_TRUE_MESSAGE(asm_result.success, "STAS failed to translate SUB instruction sequence");
    TEST_ASSERT_NOT_NULL_MESSAGE(asm_result.code, "No machine code generated for SUB sequence");
    
    // Test execution behavior
    test_case_t* test = create_test_case(asm_result.code, asm_result.code_size);
    set_expected_register(test, RISCV_X1, 200);
    set_expected_register(test, RISCV_X2, 80);
    set_expected_register(test, RISCV_X3, 120);  // 200 - 80
    
    TEST_ASSERT_EXECUTION_SUCCESS(&arch_riscv, test);
    
    destroy_test_case(test);
    free_assembly_result(&asm_result);
}

// Test STAS translation of bitwise AND operation
void test_stas_and_operation_translation(void) {
    const char *source = 
        "addi x1, x0, 0xFF0\n"  // Using smaller immediate for RISC-V
        "addi x2, x0, 0x0FF\n"
        "and x3, x1, x2\n";
    
    assembly_result_t asm_result = assemble_stas_source(source);
    TEST_ASSERT_TRUE_MESSAGE(asm_result.success, "STAS failed to translate AND operation");
    TEST_ASSERT_NOT_NULL_MESSAGE(asm_result.code, "No machine code generated for AND operation");
    
    // Test execution behavior
    test_case_t* test = create_test_case(asm_result.code, asm_result.code_size);
    set_expected_register(test, RISCV_X1, 0xFF0);
    set_expected_register(test, RISCV_X2, 0x0FF);
    set_expected_register(test, RISCV_X3, 0x0F0); // 0xFF0 & 0x0FF = 0x0F0
    
    TEST_ASSERT_EXECUTION_SUCCESS(&arch_riscv, test);
    
    destroy_test_case(test);
    free_assembly_result(&asm_result);
}

// Test STAS translation of bitwise OR operation  
void test_stas_or_operation_translation(void) {
    const char *source = 
        "addi x1, x0, 0xF00\n"
        "addi x2, x0, 0x0FF\n"
        "or x3, x1, x2\n";
    
    assembly_result_t asm_result = assemble_stas_source(source);
    TEST_ASSERT_TRUE_MESSAGE(asm_result.success, "STAS failed to translate OR operation");
    TEST_ASSERT_NOT_NULL_MESSAGE(asm_result.code, "No machine code generated for OR operation");
    
    // Test execution behavior
    test_case_t* test = create_test_case(asm_result.code, asm_result.code_size);
    set_expected_register(test, RISCV_X1, 0xF00);
    set_expected_register(test, RISCV_X2, 0x0FF);
    set_expected_register(test, RISCV_X3, 0xFFF); // 0xF00 | 0x0FF = 0xFFF
    
    TEST_ASSERT_EXECUTION_SUCCESS(&arch_riscv, test);
    
    destroy_test_case(test);
    free_assembly_result(&asm_result);
}

// Test STAS translation of XOR operation
void test_stas_xor_operation_translation(void) {
    const char *source = 
        "addi x1, x0, 0xAAA\n"
        "addi x2, x0, 0x555\n"
        "xor x3, x1, x2\n";
    
    assembly_result_t asm_result = assemble_stas_source(source);
    TEST_ASSERT_TRUE_MESSAGE(asm_result.success, "STAS failed to translate XOR operation");
    TEST_ASSERT_NOT_NULL_MESSAGE(asm_result.code, "No machine code generated for XOR operation");
    
    // Test execution behavior
    test_case_t* test = create_test_case(asm_result.code, asm_result.code_size);
    set_expected_register(test, RISCV_X1, 0xAAA);
    set_expected_register(test, RISCV_X2, 0x555);
    set_expected_register(test, RISCV_X3, 0xFFF); // 0xAAA ^ 0x555 = 0xFFF
    
    TEST_ASSERT_EXECUTION_SUCCESS(&arch_riscv, test);
    
    destroy_test_case(test);
    free_assembly_result(&asm_result);
}

int main(void) {
    UNITY_BEGIN();
    
    // Test STAS translation of basic instructions
    RUN_TEST(test_stas_addi_immediate_translation);
    RUN_TEST(test_stas_add_registers_translation);
    
    // Test STAS translation of arithmetic operations
    RUN_TEST(test_stas_sub_instruction_translation);
    
    // Test STAS translation of bitwise operations
    RUN_TEST(test_stas_and_operation_translation);
    RUN_TEST(test_stas_or_operation_translation);
    RUN_TEST(test_stas_xor_operation_translation);
    
    return UNITY_END();
}
