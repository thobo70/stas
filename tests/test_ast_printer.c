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

void test_ast_node_type_to_string(void) {
    TEST_ASSERT_EQUAL_STRING("INSTRUCTION", ast_node_type_to_string(AST_INSTRUCTION));
    TEST_ASSERT_EQUAL_STRING("LABEL", ast_node_type_to_string(AST_LABEL));
    TEST_ASSERT_EQUAL_STRING("DIRECTIVE", ast_node_type_to_string(AST_DIRECTIVE));
    TEST_ASSERT_EQUAL_STRING("SECTION", ast_node_type_to_string(AST_SECTION));
    TEST_ASSERT_EQUAL_STRING("EXPRESSION", ast_node_type_to_string(AST_EXPRESSION));
    TEST_ASSERT_EQUAL_STRING("OPERAND", ast_node_type_to_string(AST_OPERAND));
}

void test_ast_print_tree_with_simple_instruction(void) {
    const char *source = "movq $42, %rax\n";
    
    lexer_t *lexer = lexer_create(source, "test.s");
    TEST_ASSERT_NOT_NULL(lexer);
    
    parser_t *parser = parser_create(lexer, &mock_arch);
    TEST_ASSERT_NOT_NULL(parser);
    
    ast_node_t *ast = parser_parse(parser);
    TEST_ASSERT_NOT_NULL(ast);
    TEST_ASSERT_FALSE(parser_has_error(parser));
    
    // Test that the AST printer doesn't crash
    printf("\n=== Test AST Output ===\n");
    ast_print_tree(ast);
    printf("=== End Test AST ===\n");
    
    // Verify the AST structure
    TEST_ASSERT_EQUAL(AST_INSTRUCTION, ast->type);
    ast_instruction_t *inst = (ast_instruction_t *)ast->data;
    TEST_ASSERT_NOT_NULL(inst);
    TEST_ASSERT_EQUAL_STRING("movq", inst->mnemonic);
    TEST_ASSERT_EQUAL(2, inst->operand_count);
    
    parser_destroy(parser);
    lexer_destroy(lexer);
}

void test_ast_print_tree_with_directive(void) {
    const char *source = ".global _start\n";
    
    lexer_t *lexer = lexer_create(source, "test.s");
    TEST_ASSERT_NOT_NULL(lexer);
    
    parser_t *parser = parser_create(lexer, &mock_arch);
    TEST_ASSERT_NOT_NULL(parser);
    
    ast_node_t *ast = parser_parse(parser);
    TEST_ASSERT_NOT_NULL(ast);
    TEST_ASSERT_FALSE(parser_has_error(parser));
    
    // Test that the AST printer works with directives
    printf("\n=== Test Directive AST ===\n");
    ast_print_tree(ast);
    printf("=== End Test Directive AST ===\n");
    
    // Verify the AST structure
    TEST_ASSERT_EQUAL(AST_DIRECTIVE, ast->type);
    ast_directive_t *directive = (ast_directive_t *)ast->data;
    TEST_ASSERT_NOT_NULL(directive);
    TEST_ASSERT_EQUAL_STRING(".global", directive->name);
    TEST_ASSERT_EQUAL(1, directive->arg_count);
    TEST_ASSERT_EQUAL_STRING("_start", directive->args[0]);
    
    parser_destroy(parser);
    lexer_destroy(lexer);
}

void test_ast_print_tree_with_null_ast(void) {
    // Test that printing a NULL AST doesn't crash
    printf("\n=== Test NULL AST ===\n");
    ast_print_tree(NULL);
    printf("=== End Test NULL AST ===\n");
    
    // No assertions needed - just ensuring no crash
}

int main(void) {
    UNITY_BEGIN();
    
    RUN_TEST(test_ast_node_type_to_string);
    RUN_TEST(test_ast_print_tree_with_simple_instruction);
    RUN_TEST(test_ast_print_tree_with_directive);
    RUN_TEST(test_ast_print_tree_with_null_ast);
    
    return UNITY_END();
}
