#include "unity.h"
#include "../include/parser.h"
#include "../include/lexer.h"

void setUp(void) {
    // Set up any test fixtures here
}

void tearDown(void) {
    // Clean up after each test
}

void test_parser_initialization(void) {
    const char *input = "mov";
    lexer_t *lexer = lexer_create(input, "test");
    
    // Just test that we can create a lexer for basic parsing operations
    TEST_ASSERT_NOT_NULL(lexer);
    
    token_t token = lexer_next_token(lexer);
    TEST_ASSERT_EQUAL_INT(TOKEN_INSTRUCTION, token.type);
    TEST_ASSERT_EQUAL_STRING("mov", token.value);
    
    token_free(&token);
    lexer_destroy(lexer);
}

void test_basic_instruction_parsing(void) {
    const char *input = "mov %eax, $42";
    lexer_t *lexer = lexer_create(input, "test");
    
    // Test that we can tokenize a complete instruction
    TEST_ASSERT_NOT_NULL(lexer);
    
    // Test instruction token
    token_t instr = lexer_next_token(lexer);
    TEST_ASSERT_EQUAL_INT(TOKEN_INSTRUCTION, instr.type);
    TEST_ASSERT_EQUAL_STRING("mov", instr.value);
    
    // Test register token  
    token_t reg = lexer_next_token(lexer);
    TEST_ASSERT_EQUAL_INT(TOKEN_REGISTER, reg.type);
    TEST_ASSERT_EQUAL_STRING("eax", reg.value);
    
    token_free(&instr);
    token_free(&reg);
    lexer_destroy(lexer);
}

int main(void) {
    UNITY_BEGIN();
    
    RUN_TEST(test_parser_initialization);
    RUN_TEST(test_basic_instruction_parsing);
    
    return UNITY_END();
}
