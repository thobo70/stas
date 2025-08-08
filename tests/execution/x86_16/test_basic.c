#include "../../unity/src/unity.h"
#include "../../framework/unicorn_test_framework.h"
#include "parser.h"
#include "lexer.h"
#include "codegen.h"
#include "../../src/core/output_format.h"
#include "symbols.h"
#include "arch_interface.h"
#include "x86_16.h"
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
    
    // Get x86-16 architecture operations first
    arch_ops_t *arch_ops = x86_16_get_arch_ops();
    if (!arch_ops) {
        printf("Failed to get x86-16 architecture operations\n");
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
    output->base_address = 0x1000;  // Match arch_x86_16.code_addr
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

// Test STAS translation of basic MOV instruction with immediate value
void test_stas_mov_immediate_translation(void) {
    const char *source = "mov $0x1234, %ax\n";
    
    assembly_result_t asm_result = assemble_stas_source(source);
    TEST_ASSERT_TRUE_MESSAGE(asm_result.success, "STAS failed to translate MOV immediate instruction");
    TEST_ASSERT_NOT_NULL_MESSAGE(asm_result.code, "No machine code generated for MOV immediate");
    
    // Test execution behavior
    test_case_t* test = create_test_case(asm_result.code, asm_result.code_size);
    set_expected_register(test, X86_16_AX, 0x1234);
    
    TEST_ASSERT_EXECUTION_SUCCESS(&arch_x86_16, test);
    
    destroy_test_case(test);
    free_assembly_result(&asm_result);
}

// Test STAS translation of MOV between registers
void test_stas_mov_register_translation(void) {
    const char *source = 
        "mov $0x5678, %ax\n"
        "mov %ax, %bx\n";
    
    assembly_result_t asm_result = assemble_stas_source(source);
    TEST_ASSERT_TRUE_MESSAGE(asm_result.success, "STAS failed to translate MOV register instructions");
    TEST_ASSERT_NOT_NULL_MESSAGE(asm_result.code, "No machine code generated for MOV register");
    
    // Test execution behavior
    test_case_t* test = create_test_case(asm_result.code, asm_result.code_size);
    set_expected_register(test, X86_16_AX, 0x5678);
    set_expected_register(test, X86_16_BX, 0x5678);
    
    TEST_ASSERT_EXECUTION_SUCCESS(&arch_x86_16, test);
    
    destroy_test_case(test);
    free_assembly_result(&asm_result);
}

// Test STAS translation of ADD instruction
void test_stas_add_instruction_translation(void) {
    const char *source = 
        "mov $100, %ax\n"
        "mov $50, %bx\n"
        "add %bx, %ax\n";
    
    assembly_result_t asm_result = assemble_stas_source(source);
    TEST_ASSERT_TRUE_MESSAGE(asm_result.success, "STAS failed to translate ADD instruction sequence");
    TEST_ASSERT_NOT_NULL_MESSAGE(asm_result.code, "No machine code generated for ADD sequence");
    
    // Test execution behavior
    test_case_t* test = create_test_case(asm_result.code, asm_result.code_size);
    set_expected_register(test, X86_16_AX, 150);  // 100 + 50
    set_expected_register(test, X86_16_BX, 50);
    
    TEST_ASSERT_EXECUTION_SUCCESS(&arch_x86_16, test);
    
    destroy_test_case(test);
    free_assembly_result(&asm_result);
}

// Test STAS translation of SUB instruction
void test_stas_sub_instruction_translation(void) {
    const char *source = 
        "mov $200, %ax\n"
        "mov $80, %bx\n"
        "sub %bx, %ax\n";
    
    assembly_result_t asm_result = assemble_stas_source(source);
    TEST_ASSERT_TRUE_MESSAGE(asm_result.success, "STAS failed to translate SUB instruction sequence");
    TEST_ASSERT_NOT_NULL_MESSAGE(asm_result.code, "No machine code generated for SUB sequence");
    
    // Test execution behavior
    test_case_t* test = create_test_case(asm_result.code, asm_result.code_size);
    set_expected_register(test, X86_16_AX, 120);  // 200 - 80
    set_expected_register(test, X86_16_BX, 80);
    
    TEST_ASSERT_EXECUTION_SUCCESS(&arch_x86_16, test);
    
    destroy_test_case(test);
    free_assembly_result(&asm_result);
}

// Test STAS translation of increment/decrement operations
void test_stas_inc_dec_translation(void) {
    const char *source = 
        "mov $100, %ax\n"
        "inc %ax\n"
        "dec %ax\n";
    
    assembly_result_t asm_result = assemble_stas_source(source);
    TEST_ASSERT_TRUE_MESSAGE(asm_result.success, "STAS failed to translate inc/dec operations");
    TEST_ASSERT_NOT_NULL_MESSAGE(asm_result.code, "No machine code generated for inc/dec");
    
    // Test execution behavior
    test_case_t* test = create_test_case(asm_result.code, asm_result.code_size);
    set_expected_register(test, X86_16_AX, 100); // Should be back to 100
    
    TEST_ASSERT_EXECUTION_SUCCESS(&arch_x86_16, test);
    
    destroy_test_case(test);
    free_assembly_result(&asm_result);
}

// Test STAS translation of bitwise AND operation
void test_stas_and_operation_translation(void) {
    const char *source = 
        "mov $0xFF00, %ax\n"
        "mov $0x00FF, %bx\n"
        "and %bx, %ax\n";
    
    assembly_result_t asm_result = assemble_stas_source(source);
    TEST_ASSERT_TRUE_MESSAGE(asm_result.success, "STAS failed to translate AND operation");
    TEST_ASSERT_NOT_NULL_MESSAGE(asm_result.code, "No machine code generated for AND operation");
    
    // Test execution behavior
    test_case_t* test = create_test_case(asm_result.code, asm_result.code_size);
    set_expected_register(test, X86_16_AX, 0x0000); // 0xFF00 & 0x00FF = 0x0000
    set_expected_register(test, X86_16_BX, 0x00FF);
    
    TEST_ASSERT_EXECUTION_SUCCESS(&arch_x86_16, test);
    
    destroy_test_case(test);
    free_assembly_result(&asm_result);
}

// Test STAS translation of bitwise OR operation  
void test_stas_or_operation_translation(void) {
    const char *source = 
        "mov $0xFF00, %ax\n"
        "mov $0x00FF, %bx\n"
        "or %bx, %ax\n";
    
    assembly_result_t asm_result = assemble_stas_source(source);
    TEST_ASSERT_TRUE_MESSAGE(asm_result.success, "STAS failed to translate OR operation");
    TEST_ASSERT_NOT_NULL_MESSAGE(asm_result.code, "No machine code generated for OR operation");
    
    // Test execution behavior
    test_case_t* test = create_test_case(asm_result.code, asm_result.code_size);
    set_expected_register(test, X86_16_AX, 0xFFFF); // OR should result in all 1s
    set_expected_register(test, X86_16_BX, 0x00FF);
    
    TEST_ASSERT_EXECUTION_SUCCESS(&arch_x86_16, test);
    
    destroy_test_case(test);
    free_assembly_result(&asm_result);
}

// Test STAS translation of compare instruction
void test_stas_cmp_instruction_translation(void) {
    const char *source = 
        "mov $1000, %ax\n"
        "mov $1000, %bx\n"
        "cmp %bx, %ax\n";
    
    assembly_result_t asm_result = assemble_stas_source(source);
    TEST_ASSERT_TRUE_MESSAGE(asm_result.success, "STAS failed to translate CMP instruction");
    TEST_ASSERT_NOT_NULL_MESSAGE(asm_result.code, "No machine code generated for CMP instruction");
    
    // Test execution behavior
    test_case_t* test = create_test_case(asm_result.code, asm_result.code_size);
    set_expected_register(test, X86_16_AX, 1000);
    set_expected_register(test, X86_16_BX, 1000);
    
    TEST_ASSERT_EXECUTION_SUCCESS(&arch_x86_16, test);
    
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
    
    // Test STAS translation of bitwise operations
    RUN_TEST(test_stas_and_operation_translation);
    RUN_TEST(test_stas_or_operation_translation);
    
    // Test STAS translation of comparison operations
    RUN_TEST(test_stas_cmp_instruction_translation);
    
    return UNITY_END();
}
