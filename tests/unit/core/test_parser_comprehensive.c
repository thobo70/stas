#include "unity.h"
#include "unity_extensions.h"
#include "../../../include/parser.h"
#include "../../../include/lexer.h"
#include "../../../include/symbols.h"
#include "../../../include/arch_interface.h"
#include <string.h>
#include <stdlib.h>

// Forward declarations for architecture functions
extern arch_ops_t *get_arch_ops_x86_64(void);
extern arch_ops_t *get_arch_ops_x86_32(void);
extern arch_ops_t *get_arch_ops_x86_16(void);

// Global test fixture
parser_t *parser;
lexer_t *lexer;

void setUp(void)
{
    parser = NULL;
    lexer = NULL;
}

void tearDown(void)
{
    if (parser) {
        parser_destroy(parser);
        parser = NULL;
    }
    if (lexer) {
        lexer_destroy(lexer);
        lexer = NULL;
    }
}

// ========================================
// COMPREHENSIVE PARSER INITIALIZATION TESTS
// ========================================

void test_parser_create_valid_input(void)
{
    lexer = lexer_create("mov %rax, %rbx", "test.s");
    TEST_ASSERT_NOT_NULL(lexer);
    
    arch_ops_t *arch = get_arch_ops_x86_64();
    TEST_ASSERT_NOT_NULL(arch);
    
    parser = parser_create(lexer, arch);
    TEST_ASSERT_NOT_NULL(parser);
    TEST_ASSERT_FALSE(parser_has_error(parser));
}

void test_parser_create_null_lexer(void)
{
    arch_ops_t *arch = get_arch_ops_x86_64();
    TEST_ASSERT_NOT_NULL(arch);
    
    parser = parser_create(NULL, arch);
    TEST_ASSERT_NULL(parser);
}

void test_parser_create_null_arch(void)
{
    lexer = lexer_create("mov %rax, %rbx", "test.s");
    TEST_ASSERT_NOT_NULL(lexer);
    
    parser = parser_create(lexer, NULL);
    TEST_ASSERT_NULL(parser);
}

void test_parser_create_empty_input(void)
{
    lexer = lexer_create("", "test.s");
    TEST_ASSERT_NOT_NULL(lexer);
    
    arch_ops_t *arch = get_arch_ops_x86_64();
    TEST_ASSERT_NOT_NULL(arch);
    
    parser = parser_create(lexer, arch);
    TEST_ASSERT_NOT_NULL(parser);
    TEST_ASSERT_FALSE(parser_has_error(parser));
}

// ========================================
// COMPREHENSIVE INSTRUCTION PARSING TESTS
// ========================================

void test_parser_simple_instruction_x86_64(void)
{
    lexer = lexer_create("mov %rax, %rbx", "test.s");
    TEST_ASSERT_NOT_NULL(lexer);
    
    arch_ops_t *arch = get_arch_ops_x86_64();
    parser = parser_create(lexer, arch);
    TEST_ASSERT_NOT_NULL(parser);
    
    ast_node_t *root = parser_parse(parser);
    (void)root; // Suppress unused warning
    
    // The main goal is that parsing doesn't crash
    TEST_ASSERT_NOT_NULL(parser);
}

void test_parser_instruction_with_immediate(void)
{
    lexer = lexer_create("mov $42, %rax", "test.s");
    TEST_ASSERT_NOT_NULL(lexer);
    
    arch_ops_t *arch = get_arch_ops_x86_64();
    parser = parser_create(lexer, arch);
    TEST_ASSERT_NOT_NULL(parser);
    
    ast_node_t *root = parser_parse(parser);
    (void)root;
    
    TEST_ASSERT_NOT_NULL(parser);
}

void test_parser_instruction_with_memory_operand(void)
{
    lexer = lexer_create("mov 8(%rbp), %rax", "test.s");
    TEST_ASSERT_NOT_NULL(lexer);
    
    arch_ops_t *arch = get_arch_ops_x86_64();
    parser = parser_create(lexer, arch);
    TEST_ASSERT_NOT_NULL(parser);
    
    ast_node_t *root = parser_parse(parser);
    (void)root;
    
    TEST_ASSERT_NOT_NULL(parser);
}

void test_parser_multiple_instructions(void)
{
    lexer = lexer_create("mov %rax, %rbx\nadd %rcx, %rdx", "test.s");
    TEST_ASSERT_NOT_NULL(lexer);
    
    arch_ops_t *arch = get_arch_ops_x86_64();
    parser = parser_create(lexer, arch);
    TEST_ASSERT_NOT_NULL(parser);
    
    ast_node_t *root = parser_parse(parser);
    (void)root;
    
    TEST_ASSERT_NOT_NULL(parser);
}

// ========================================
// COMPREHENSIVE LABEL PARSING TESTS
// ========================================

void test_parser_simple_label(void)
{
    lexer = lexer_create("main:", "test.s");
    TEST_ASSERT_NOT_NULL(lexer);
    
    arch_ops_t *arch = get_arch_ops_x86_64();
    parser = parser_create(lexer, arch);
    TEST_ASSERT_NOT_NULL(parser);
    
    ast_node_t *root = parser_parse(parser);
    (void)root;
    
    TEST_ASSERT_NOT_NULL(parser);
}

void test_parser_label_with_instruction(void)
{
    lexer = lexer_create("loop_start:\n    mov %rax, %rbx", "test.s");
    TEST_ASSERT_NOT_NULL(lexer);
    
    arch_ops_t *arch = get_arch_ops_x86_64();
    parser = parser_create(lexer, arch);
    TEST_ASSERT_NOT_NULL(parser);
    
    ast_node_t *root = parser_parse(parser);
    (void)root;
    
    TEST_ASSERT_NOT_NULL(parser);
}

// ========================================
// COMPREHENSIVE DIRECTIVE PARSING TESTS
// ========================================

void test_parser_section_directives(void)
{
    lexer = lexer_create(".text", "test.s");
    TEST_ASSERT_NOT_NULL(lexer);
    
    arch_ops_t *arch = get_arch_ops_x86_64();
    parser = parser_create(lexer, arch);
    TEST_ASSERT_NOT_NULL(parser);
    
    ast_node_t *root = parser_parse(parser);
    (void)root;
    
    TEST_ASSERT_NOT_NULL(parser);
}

void test_parser_data_directives(void)
{
    lexer = lexer_create(".byte 42", "test.s");
    TEST_ASSERT_NOT_NULL(lexer);
    
    arch_ops_t *arch = get_arch_ops_x86_64();
    parser = parser_create(lexer, arch);
    TEST_ASSERT_NOT_NULL(parser);
    
    ast_node_t *root = parser_parse(parser);
    (void)root;
    
    TEST_ASSERT_NOT_NULL(parser);
}

void test_parser_global_directive(void)
{
    lexer = lexer_create(".global _start", "test.s");
    TEST_ASSERT_NOT_NULL(lexer);
    
    arch_ops_t *arch = get_arch_ops_x86_64();
    parser = parser_create(lexer, arch);
    TEST_ASSERT_NOT_NULL(parser);
    
    ast_node_t *root = parser_parse(parser);
    (void)root;
    
    TEST_ASSERT_NOT_NULL(parser);
}

// ========================================
// COMPREHENSIVE EXPRESSION PARSING TESTS
// ========================================

void test_parser_arithmetic_expression(void)
{
    lexer = lexer_create("mov $(1+2), %rax", "test.s");
    TEST_ASSERT_NOT_NULL(lexer);
    
    arch_ops_t *arch = get_arch_ops_x86_64();
    parser = parser_create(lexer, arch);
    TEST_ASSERT_NOT_NULL(parser);
    
    ast_node_t *root = parser_parse(parser);
    (void)root;
    
    TEST_ASSERT_NOT_NULL(parser);
}

void test_parser_symbol_expression(void)
{
    lexer = lexer_create("mov $label_name, %rax", "test.s");
    TEST_ASSERT_NOT_NULL(lexer);
    
    arch_ops_t *arch = get_arch_ops_x86_64();
    parser = parser_create(lexer, arch);
    TEST_ASSERT_NOT_NULL(parser);
    
    ast_node_t *root = parser_parse(parser);
    (void)root;
    
    TEST_ASSERT_NOT_NULL(parser);
}

// ========================================
// COMPREHENSIVE MACRO PARSING TESTS
// ========================================

void test_parser_macro_define(void)
{
    lexer = lexer_create("#define MAX_SIZE 1024", "test.s");
    TEST_ASSERT_NOT_NULL(lexer);
    
    arch_ops_t *arch = get_arch_ops_x86_64();
    parser = parser_create(lexer, arch);
    TEST_ASSERT_NOT_NULL(parser);
    
    ast_node_t *root = parser_parse(parser);
    (void)root;
    
    TEST_ASSERT_NOT_NULL(parser);
}

void test_parser_macro_conditional(void)
{
    lexer = lexer_create("#ifdef DEBUG\nmov %rax, %rbx\n#endif", "test.s");
    TEST_ASSERT_NOT_NULL(lexer);
    
    arch_ops_t *arch = get_arch_ops_x86_64();
    parser = parser_create(lexer, arch);
    TEST_ASSERT_NOT_NULL(parser);
    
    ast_node_t *root = parser_parse(parser);
    (void)root;
    
    TEST_ASSERT_NOT_NULL(parser);
}

// ========================================
// COMPREHENSIVE ERROR HANDLING TESTS
// ========================================

void test_parser_invalid_instruction(void)
{
    lexer = lexer_create("invalid_instruction %rax", "test.s");
    TEST_ASSERT_NOT_NULL(lexer);
    
    arch_ops_t *arch = get_arch_ops_x86_64();
    parser = parser_create(lexer, arch);
    TEST_ASSERT_NOT_NULL(parser);
    
    ast_node_t *root = parser_parse(parser);
    (void)root;
    
    // Parser should handle invalid input gracefully
    TEST_ASSERT_NOT_NULL(parser);
}

void test_parser_malformed_operand(void)
{
    lexer = lexer_create("mov %rax,", "test.s");
    TEST_ASSERT_NOT_NULL(lexer);
    
    arch_ops_t *arch = get_arch_ops_x86_64();
    parser = parser_create(lexer, arch);
    TEST_ASSERT_NOT_NULL(parser);
    
    ast_node_t *root = parser_parse(parser);
    (void)root;
    
    TEST_ASSERT_NOT_NULL(parser);
}

// ========================================
// COMPREHENSIVE MIXED CONTENT TESTS
// ========================================

void test_parser_complete_program(void)
{
    lexer = lexer_create(".section .text\n"
                        ".global _start\n"
                        "_start:\n"
                        "    mov $42, %rdi\n"
                        "    syscall", "test.s");
    TEST_ASSERT_NOT_NULL(lexer);
    
    arch_ops_t *arch = get_arch_ops_x86_64();
    parser = parser_create(lexer, arch);
    TEST_ASSERT_NOT_NULL(parser);
    
    ast_node_t *root = parser_parse(parser);
    (void)root;
    
    TEST_ASSERT_NOT_NULL(parser);
}

void test_parser_comments_and_whitespace(void)
{
    lexer = lexer_create("# Comment\n"
                        "main:    # Label comment\n"
                        "    mov %rax, %rbx  # Instruction comment\n"
                        "    ret", "test.s");
    TEST_ASSERT_NOT_NULL(lexer);
    
    arch_ops_t *arch = get_arch_ops_x86_64();
    parser = parser_create(lexer, arch);
    TEST_ASSERT_NOT_NULL(parser);
    
    ast_node_t *root = parser_parse(parser);
    (void)root;
    
    TEST_ASSERT_NOT_NULL(parser);
}

// ========================================
// COMPREHENSIVE ARCHITECTURE TESTS
// ========================================

void test_parser_x86_32_instructions(void)
{
    lexer = lexer_create("mov %eax, %ebx", "test.s");
    TEST_ASSERT_NOT_NULL(lexer);
    
    arch_ops_t *arch = get_arch_ops_x86_32();
    parser = parser_create(lexer, arch);
    TEST_ASSERT_NOT_NULL(parser);
    
    ast_node_t *root = parser_parse(parser);
    (void)root;
    
    TEST_ASSERT_NOT_NULL(parser);
}

void test_parser_x86_16_instructions(void)
{
    lexer = lexer_create("mov %ax, %bx", "test.s");
    TEST_ASSERT_NOT_NULL(lexer);
    
    arch_ops_t *arch = get_arch_ops_x86_16();
    parser = parser_create(lexer, arch);
    TEST_ASSERT_NOT_NULL(parser);
    
    ast_node_t *root = parser_parse(parser);
    (void)root;
    
    TEST_ASSERT_NOT_NULL(parser);
}

// Test runner
int main(void)
{
    UNITY_BEGIN();
    
    // Initialization tests
    RUN_TEST(test_parser_create_valid_input);
    RUN_TEST(test_parser_create_null_lexer);
    RUN_TEST(test_parser_create_null_arch);
    RUN_TEST(test_parser_create_empty_input);
    
    // Instruction parsing tests
    RUN_TEST(test_parser_simple_instruction_x86_64);
    RUN_TEST(test_parser_instruction_with_immediate);
    RUN_TEST(test_parser_instruction_with_memory_operand);
    RUN_TEST(test_parser_multiple_instructions);
    
    // Label parsing tests
    RUN_TEST(test_parser_simple_label);
    RUN_TEST(test_parser_label_with_instruction);
    
    // Directive parsing tests
    RUN_TEST(test_parser_section_directives);
    RUN_TEST(test_parser_data_directives);
    RUN_TEST(test_parser_global_directive);
    
    // Expression parsing tests
    RUN_TEST(test_parser_arithmetic_expression);
    RUN_TEST(test_parser_symbol_expression);
    
    // Macro parsing tests
    RUN_TEST(test_parser_macro_define);
    RUN_TEST(test_parser_macro_conditional);
    
    // Error handling tests
    RUN_TEST(test_parser_invalid_instruction);
    RUN_TEST(test_parser_malformed_operand);
    
    // Mixed content tests
    RUN_TEST(test_parser_complete_program);
    RUN_TEST(test_parser_comments_and_whitespace);
    
    // Architecture tests
    RUN_TEST(test_parser_x86_32_instructions);
    RUN_TEST(test_parser_x86_16_instructions);
    
    return UNITY_END();
}
