#include "unity.h"
#include "parser.h"
#include "lexer.h"
#include "arch_interface.h"

// Mock architecture operations
static arch_ops_t mock_arch = {
    .name = "test_arch",
    .init = NULL,
    .cleanup = NULL,
    .parse_instruction = NULL,
    .encode_instruction = NULL,
    .parse_register = NULL,
    .is_valid_register = NULL,
    .get_register_name = NULL,
    .parse_addressing = NULL,
    .validate_addressing = NULL,
    .handle_directive = NULL,
    .get_instruction_size = NULL,
    .get_alignment = NULL
};

void setUp(void) {
    // This is run before each test
}

void tearDown(void) {
    // This is run after each test
}

void test_parse_complete_program(void) {
    const char *source = 
        ".section .text\n"
        ".global _start\n"
        "\n"
        "_start:\n"
        "    movq $60, %rax\n"
        "    movq $0, %rdi\n"
        "    syscall\n";
    
    lexer_t *lexer = lexer_create(source, "test.s");
    TEST_ASSERT_NOT_NULL(lexer);
    
    parser_t *parser = parser_create(lexer, &mock_arch);
    TEST_ASSERT_NOT_NULL(parser);
    
    ast_node_t *ast = parser_parse(parser);
    TEST_ASSERT_NOT_NULL(ast);
    TEST_ASSERT_FALSE(parser_has_error(parser));
    
    // The AST should start with the .section directive
    TEST_ASSERT_EQUAL(AST_DIRECTIVE, ast->type);
    
    // Should have multiple statements linked
    TEST_ASSERT_NOT_NULL(ast->next);
    
    parser_destroy(parser);
    lexer_destroy(lexer);
}

void test_parse_instruction_with_operands(void) {
    const char *source = "movq $60, %rax\n";
    
    lexer_t *lexer = lexer_create(source, "test.s");
    TEST_ASSERT_NOT_NULL(lexer);
    
    parser_t *parser = parser_create(lexer, &mock_arch);
    TEST_ASSERT_NOT_NULL(parser);
    
    ast_node_t *ast = parser_parse(parser);
    TEST_ASSERT_NOT_NULL(ast);
    TEST_ASSERT_FALSE(parser_has_error(parser));
    
    // Should be an instruction node
    TEST_ASSERT_EQUAL(AST_INSTRUCTION, ast->type);
    
    // Should have instruction data with operands
    ast_instruction_t *inst = (ast_instruction_t *)ast->data;
    TEST_ASSERT_NOT_NULL(inst);
    TEST_ASSERT_EQUAL_STRING("movq", inst->mnemonic);
    TEST_ASSERT_EQUAL(2, inst->operand_count);
    
    // First operand should be immediate
    TEST_ASSERT_EQUAL(OPERAND_IMMEDIATE, inst->operands[0].type);
    TEST_ASSERT_EQUAL(60, inst->operands[0].value.immediate);
    
    // Second operand should be register
    TEST_ASSERT_EQUAL(OPERAND_REGISTER, inst->operands[1].type);
    TEST_ASSERT_EQUAL_STRING("rax", inst->operands[1].value.reg.name);
    
    parser_destroy(parser);
    lexer_destroy(lexer);
}

void test_parse_directive_with_arguments(void) {
    const char *source = ".global _start\n";
    
    lexer_t *lexer = lexer_create(source, "test.s");
    TEST_ASSERT_NOT_NULL(lexer);
    
    parser_t *parser = parser_create(lexer, &mock_arch);
    TEST_ASSERT_NOT_NULL(parser);
    
    ast_node_t *ast = parser_parse(parser);
    TEST_ASSERT_NOT_NULL(ast);
    TEST_ASSERT_FALSE(parser_has_error(parser));
    
    // Should be a directive node
    TEST_ASSERT_EQUAL(AST_DIRECTIVE, ast->type);
    
    // Should have directive data with arguments
    ast_directive_t *directive = (ast_directive_t *)ast->data;
    TEST_ASSERT_NOT_NULL(directive);
    TEST_ASSERT_EQUAL_STRING(".global", directive->name);
    TEST_ASSERT_EQUAL(1, directive->arg_count);
    TEST_ASSERT_EQUAL_STRING("_start", directive->args[0]);
    
    parser_destroy(parser);
    lexer_destroy(lexer);
}

void test_parse_label(void) {
    const char *source = "_start:\n";
    
    lexer_t *lexer = lexer_create(source, "test.s");
    TEST_ASSERT_NOT_NULL(lexer);
    
    parser_t *parser = parser_create(lexer, &mock_arch);
    TEST_ASSERT_NOT_NULL(parser);
    
    ast_node_t *ast = parser_parse(parser);
    TEST_ASSERT_NOT_NULL(ast);
    TEST_ASSERT_FALSE(parser_has_error(parser));
    
    // Should be a label node
    TEST_ASSERT_EQUAL(AST_LABEL, ast->type);
    
    // Should have label data
    ast_label_t *label = (ast_label_t *)ast->data;
    TEST_ASSERT_NOT_NULL(label);
    TEST_ASSERT_EQUAL_STRING("_start", label->name);
    
    parser_destroy(parser);
    lexer_destroy(lexer);
}

void test_parse_syscall_instruction(void) {
    const char *source = "syscall\n";
    
    lexer_t *lexer = lexer_create(source, "test.s");
    TEST_ASSERT_NOT_NULL(lexer);
    
    parser_t *parser = parser_create(lexer, &mock_arch);
    TEST_ASSERT_NOT_NULL(parser);
    
    ast_node_t *ast = parser_parse(parser);
    TEST_ASSERT_NOT_NULL(ast);
    TEST_ASSERT_FALSE(parser_has_error(parser));
    
    // Should be an instruction node
    TEST_ASSERT_EQUAL(AST_INSTRUCTION, ast->type);
    
    // Should have instruction data with no operands
    ast_instruction_t *inst = (ast_instruction_t *)ast->data;
    TEST_ASSERT_NOT_NULL(inst);
    TEST_ASSERT_EQUAL_STRING("syscall", inst->mnemonic);
    TEST_ASSERT_EQUAL(0, inst->operand_count);
    
    parser_destroy(parser);
    lexer_destroy(lexer);
}

int main(void) {
    UNITY_BEGIN();
    
    RUN_TEST(test_parse_complete_program);
    RUN_TEST(test_parse_instruction_with_operands);
    RUN_TEST(test_parse_directive_with_arguments);
    RUN_TEST(test_parse_label);
    RUN_TEST(test_parse_syscall_instruction);
    
    return UNITY_END();
}
