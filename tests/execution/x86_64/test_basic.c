#include "../../unity/src/unity.h"
#include "../../framework/unicorn_test_framework.h"
#include "parser.h"
#include "lexer.h"
#include "codegen.h"
#include "../../src/core/output_format.h"
#include "symbols.h"
#include "arch_interface.h"
#include "../../src/arch/x86_64/x86_64.h"
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
    
    // Get x86-64 architecture operations first
    arch_ops_t *arch_ops = x86_64_get_arch_ops();
    if (!arch_ops) {
        printf("Failed to get x86-64 architecture operations\n");
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
    output->base_address = 0x1000000;  // Match arch_x86_64.code_addr
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
    if (codegen_generate(codegen, ast) != 0) {
        printf("Failed to generate machine code\n");
        codegen_destroy(codegen);
        free(output);
        parser_destroy(parser);
        lexer_destroy(lexer);
        return result;
    }
    
    // Extract the generated machine code from output sections
    if (output->sections && output->section_count > 0) {
        // Find the text section (should be the first one)
        for (size_t i = 0; i < output->section_count; i++) {
            if (output->sections[i].data && output->sections[i].size > 0) {
                result.code_size = output->sections[i].size;
                result.code = malloc(result.code_size);
                if (result.code) {
                    memcpy(result.code, output->sections[i].data, result.code_size);
                    result.success = 1;
                    printf("Successfully assembled %zu bytes of machine code\n", result.code_size);
                    printf("Machine code: ");
                    for (size_t j = 0; j < result.code_size; j++) {
                        printf("%02X ", result.code[j]);
                    }
                    printf("\n");
                } else {
                    printf("Failed to allocate memory for machine code\n");
                }
                break;
            }
        }
    }
    
    if (!result.success) {
        printf("Failed to extract generated machine code\n");
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
void test_stas_movq_immediate_translation(void) {
    const char *source = "movq $0x1234567890ABCDEF, %rax\n";
    
    assembly_result_t asm_result = assemble_stas_source(source);
    TEST_ASSERT_TRUE_MESSAGE(asm_result.success, "STAS failed to translate MOV immediate instruction");
    TEST_ASSERT_NOT_NULL_MESSAGE(asm_result.code, "No machine code generated for MOV immediate");
    
    // Test execution behavior
    test_case_t* test = create_test_case(asm_result.code, asm_result.code_size);
    set_expected_register(test, X86_64_RAX, 0x1234567890ABCDEF);
    
    TEST_ASSERT_EXECUTION_SUCCESS(&arch_x86_64, test);
    
    destroy_test_case(test);
    free_assembly_result(&asm_result);
}

// Test STAS translation of MOV between registers
void test_stas_movq_register_translation(void) {
    const char *source = 
        "movq $0x1234567890ABCDEF, %rax\n"
        "movq %rax, %rbx\n";
    
    assembly_result_t asm_result = assemble_stas_source(source);
    TEST_ASSERT_TRUE_MESSAGE(asm_result.success, "STAS failed to translate MOV register instructions");
    TEST_ASSERT_NOT_NULL_MESSAGE(asm_result.code, "No machine code generated for MOV register");
    
    // Test execution behavior
    test_case_t* test = create_test_case(asm_result.code, asm_result.code_size);
    set_expected_register(test, X86_64_RAX, 0x1234567890ABCDEF);
    set_expected_register(test, X86_64_RBX, 0x1234567890ABCDEF);
    
    TEST_ASSERT_EXECUTION_SUCCESS(&arch_x86_64, test);
    
    destroy_test_case(test);
    free_assembly_result(&asm_result);
}

// Test STAS translation of ADD instruction
void test_stas_addq_instruction_translation(void) {
    const char *source = 
        "movq $1000, %rax\n"
        "movq $500, %rbx\n"
        "addq %rbx, %rax\n";
    
    assembly_result_t asm_result = assemble_stas_source(source);
    TEST_ASSERT_TRUE_MESSAGE(asm_result.success, "STAS failed to translate ADD instruction sequence");
    TEST_ASSERT_NOT_NULL_MESSAGE(asm_result.code, "No machine code generated for ADD sequence");
    
    // Test execution behavior
    test_case_t* test = create_test_case(asm_result.code, asm_result.code_size);
    set_expected_register(test, X86_64_RAX, 1500);  // 1000 + 500
    set_expected_register(test, X86_64_RBX, 500);
    
    TEST_ASSERT_EXECUTION_SUCCESS(&arch_x86_64, test);
    
    destroy_test_case(test);
    free_assembly_result(&asm_result);
}

// Test STAS translation of SUB instruction
void test_stas_subq_instruction_translation(void) {
    const char *source = 
        "movq $2000, %rax\n"
        "movq $800, %rbx\n"
        "subq %rbx, %rax\n";
    
    assembly_result_t asm_result = assemble_stas_source(source);
    TEST_ASSERT_TRUE_MESSAGE(asm_result.success, "STAS failed to translate SUB instruction sequence");
    TEST_ASSERT_NOT_NULL_MESSAGE(asm_result.code, "No machine code generated for SUB sequence");
    
    // Test execution behavior
    test_case_t* test = create_test_case(asm_result.code, asm_result.code_size);
    set_expected_register(test, X86_64_RAX, 1200);  // 2000 - 800
    set_expected_register(test, X86_64_RBX, 800);
    
    TEST_ASSERT_EXECUTION_SUCCESS(&arch_x86_64, test);
    
    destroy_test_case(test);
    free_assembly_result(&asm_result);
}

// Test STAS translation of increment/decrement operations
void test_stas_inc_dec_translation(void) {
    const char *source = 
        "movq $100, %rax\n"
        "incq %rax\n"
        "decq %rax\n";
    
    assembly_result_t asm_result = assemble_stas_source(source);
    TEST_ASSERT_TRUE_MESSAGE(asm_result.success, "STAS failed to translate inc/dec operations");
    TEST_ASSERT_NOT_NULL_MESSAGE(asm_result.code, "No machine code generated for inc/dec");
    
    // Test execution behavior
    test_case_t* test = create_test_case(asm_result.code, asm_result.code_size);
    set_expected_register(test, X86_64_RAX, 100); // Should be back to 100
    
    TEST_ASSERT_EXECUTION_SUCCESS(&arch_x86_64, test);
    
    destroy_test_case(test);
    free_assembly_result(&asm_result);
}

// Test STAS translation of bitwise AND operation
void test_stas_and_operation_translation(void) {
    const char *source = 
        "movq $0xFFFFFFFF00000000, %rax\n"
        "movq $0x00000000FFFFFFFF, %rbx\n"
        "andq %rbx, %rax\n";
    
    assembly_result_t asm_result = assemble_stas_source(source);
    TEST_ASSERT_TRUE_MESSAGE(asm_result.success, "STAS failed to translate AND operation");
    TEST_ASSERT_NOT_NULL_MESSAGE(asm_result.code, "No machine code generated for AND operation");
    
    // Test execution behavior
    test_case_t* test = create_test_case(asm_result.code, asm_result.code_size);
    set_expected_register(test, X86_64_RAX, 0x0000000000000000); // Should be 0
    set_expected_register(test, X86_64_RBX, 0x00000000FFFFFFFF);
    
    TEST_ASSERT_EXECUTION_SUCCESS(&arch_x86_64, test);
    
    destroy_test_case(test);
    free_assembly_result(&asm_result);
}

// Test STAS translation of bitwise OR operation  
void test_stas_or_operation_translation(void) {
    const char *source = 
        "movq $0xFF00FF00FF00FF00, %rax\n"
        "movq $0x00FF00FF00FF00FF, %rbx\n"
        "orq %rbx, %rax\n";
    
    assembly_result_t asm_result = assemble_stas_source(source);
    TEST_ASSERT_TRUE_MESSAGE(asm_result.success, "STAS failed to translate OR operation");
    TEST_ASSERT_NOT_NULL_MESSAGE(asm_result.code, "No machine code generated for OR operation");
    
    // Test execution behavior
    test_case_t* test = create_test_case(asm_result.code, asm_result.code_size);
    set_expected_register(test, X86_64_RAX, 0xFFFFFFFFFFFFFFFF); // OR should result in all 1s
    set_expected_register(test, X86_64_RBX, 0x00FF00FF00FF00FF);
    
    TEST_ASSERT_EXECUTION_SUCCESS(&arch_x86_64, test);
    
    destroy_test_case(test);
    free_assembly_result(&asm_result);
}

// Test STAS translation of compare instruction
void test_stas_cmp_instruction_translation(void) {
    const char *source = 
        "movq $10000, %rax\n"
        "movq $10000, %rbx\n"
        "cmpq %rbx, %rax\n";
    
    assembly_result_t asm_result = assemble_stas_source(source);
    TEST_ASSERT_TRUE_MESSAGE(asm_result.success, "STAS failed to translate CMP instruction");
    TEST_ASSERT_NOT_NULL_MESSAGE(asm_result.code, "No machine code generated for CMP instruction");
    
    // Test execution behavior
    test_case_t* test = create_test_case(asm_result.code, asm_result.code_size);
    set_expected_register(test, X86_64_RAX, 10000);
    set_expected_register(test, X86_64_RBX, 10000);
    
    TEST_ASSERT_EXECUTION_SUCCESS(&arch_x86_64, test);
    
    destroy_test_case(test);
    free_assembly_result(&asm_result);
}

int main(void) {
    UNITY_BEGIN();
    
    // Test STAS translation of basic instructions
    RUN_TEST(test_stas_movq_immediate_translation);
    RUN_TEST(test_stas_movq_register_translation);
    
    // Test STAS translation of arithmetic operations
    RUN_TEST(test_stas_addq_instruction_translation);
    RUN_TEST(test_stas_subq_instruction_translation);
    RUN_TEST(test_stas_inc_dec_translation);
    
    // Test STAS translation of bitwise operations
    RUN_TEST(test_stas_and_operation_translation);
    RUN_TEST(test_stas_or_operation_translation);
    
    // Test STAS translation of comparison operations
    RUN_TEST(test_stas_cmp_instruction_translation);
    
    return UNITY_END();
}
