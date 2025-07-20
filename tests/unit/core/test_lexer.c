#include "unity.h"
#include "unity_extensions.h"
#include "../../include/lexer.h"
#include "../../include/symbols.h"

// Global test fixture
lexer_t *lexer;

void setUp(void)
{
    lexer = NULL;
}

void tearDown(void)
{
    if (lexer) {
        lexer_destroy(lexer);
        lexer = NULL;
    }
}

// Test lexer initialization with valid input
void test_lexer_init_success(void)
{
    const char *input = "mov %rax, %rbx";
    lexer = lexer_create(input, "test.s");
    
    TEST_ASSERT_NOT_NULL(lexer);
    TEST_ASSERT_FALSE(lexer_has_error(lexer));
}

// Test lexer initialization with NULL input
void test_lexer_init_null_input(void)
{
    lexer = lexer_create(NULL, "test.s");
    TEST_ASSERT_NULL(lexer);
}

// Test lexer initialization with empty input
void test_lexer_init_empty_input(void)
{
    lexer = lexer_create("", "test.s");
    TEST_ASSERT_NOT_NULL(lexer);
    TEST_ASSERT_FALSE(lexer_has_error(lexer));
}

// Test instruction token recognition
void test_lexer_instruction_token(void)
{
    lexer = lexer_create("mov", "test.s");
    token_t token = lexer_next_token(lexer);
    
    TEST_ASSERT_EQUAL(TOKEN_INSTRUCTION, token.type);
    TEST_ASSERT_EQUAL_STRING("mov", token.value);
    TEST_ASSERT_EQUAL(1, token.line);
    TEST_ASSERT_EQUAL(1, token.column);
    
    token_free(&token);
}

// Test register token recognition
void test_lexer_register_token(void)
{
    lexer = lexer_create("%rax", "test.s");
    token_t token = lexer_next_token(lexer);
    
    TEST_ASSERT_EQUAL(TOKEN_REGISTER, token.type);
    TEST_ASSERT_EQUAL_STRING("rax", token.value);  // Lexer strips % prefix
    
    token_free(&token);
}

// Test immediate hex token recognition
void test_lexer_immediate_hex(void)
{
    lexer = lexer_create("$0x1234", "test.s");
    token_t token = lexer_next_token(lexer);
    
    TEST_ASSERT_EQUAL(TOKEN_IMMEDIATE, token.type);
    TEST_ASSERT_EQUAL_STRING("0x1234", token.value);  // Lexer strips $ prefix
    
    token_free(&token);
}

// Test immediate decimal token recognition
void test_lexer_immediate_decimal(void)
{
    lexer = lexer_create("$1234", "test.s");
    token_t token = lexer_next_token(lexer);
    
    TEST_ASSERT_EQUAL(TOKEN_IMMEDIATE, token.type);
    TEST_ASSERT_EQUAL_STRING("1234", token.value);  // Lexer strips $ prefix
    
    token_free(&token);
}

// Test label token recognition
void test_lexer_label_token(void)
{
    lexer = lexer_create("main:", "test.s");
    token_t token = lexer_next_token(lexer);
    
    TEST_ASSERT_EQUAL(TOKEN_LABEL, token.type);
    TEST_ASSERT_EQUAL_STRING("main", token.value);  // Lexer strips : suffix
    
    token_free(&token);
}

// Test directive token recognition
void test_lexer_directive_token(void)
{
    lexer = lexer_create(".section", "test.s");
    token_t token = lexer_next_token(lexer);
    
    TEST_ASSERT_EQUAL(TOKEN_DIRECTIVE, token.type);
    TEST_ASSERT_EQUAL_STRING(".section", token.value);
    
    token_free(&token);
}

// Test symbol token recognition
void test_lexer_symbol_token(void)
{
    lexer = lexer_create("variable", "test.s");
    token_t token = lexer_next_token(lexer);
    
    TEST_ASSERT_EQUAL(TOKEN_SYMBOL, token.type);
    TEST_ASSERT_EQUAL_STRING("variable", token.value);
    
    token_free(&token);
}

// Test string literal recognition
void test_lexer_string_literal(void)
{
    lexer = lexer_create("\"hello world\"", "test.s");
    token_t token = lexer_next_token(lexer);
    
    TEST_ASSERT_EQUAL(TOKEN_STRING, token.type);
    TEST_ASSERT_EQUAL_STRING("hello world", token.value);  // Lexer strips quotes
    
    token_free(&token);
}

// Test comment recognition
void test_lexer_comment(void)
{
    lexer = lexer_create("# This is a comment", "test.s");
    token_t token = lexer_next_token(lexer);
    
    // Comments might be skipped entirely or returned as TOKEN_COMMENT
    // The lexer behavior for comments is implementation-dependent
    TEST_ASSERT_TRUE(token.type == TOKEN_COMMENT || token.type == TOKEN_EOF);
    
    token_free(&token);
}

// Test comma token recognition
void test_lexer_comma_token(void)
{
    lexer = lexer_create(",", "test.s");
    token_t token = lexer_next_token(lexer);
    
    TEST_ASSERT_EQUAL(TOKEN_COMMA, token.type);
    TEST_ASSERT_EQUAL_STRING(",", token.value);
    
    token_free(&token);
}

// Test parentheses recognition
void test_lexer_parentheses(void)
{
    lexer = lexer_create("(", "test.s");
    token_t token1 = lexer_next_token(lexer);
    TEST_ASSERT_EQUAL(TOKEN_LPAREN, token1.type);
    token_free(&token1);

    lexer_destroy(lexer);
    lexer = lexer_create(")", "test.s");
    token_t token2 = lexer_next_token(lexer);
    TEST_ASSERT_EQUAL(TOKEN_RPAREN, token2.type);
    token_free(&token2);
}

// Test newline recognition
void test_lexer_newline(void)
{
    lexer = lexer_create("\n", "test.s");
    token_t token = lexer_next_token(lexer);
    
    TEST_ASSERT_EQUAL(TOKEN_NEWLINE, token.type);
    TEST_ASSERT_EQUAL_STRING("\n", token.value);
    
    token_free(&token);
}

// Test EOF token
void test_lexer_eof(void)
{
    lexer = lexer_create("", "test.s");
    token_t token = lexer_next_token(lexer);
    
    TEST_ASSERT_EQUAL(TOKEN_EOF, token.type);
    
    token_free(&token);
}

// Test multiple tokens parsing
void test_lexer_multiple_tokens(void)
{
    lexer = lexer_create("mov %rax, $0x123", "test.s");
    
    // First token: instruction
    token_t token1 = lexer_next_token(lexer);
    TEST_ASSERT_EQUAL(TOKEN_INSTRUCTION, token1.type);
    TEST_ASSERT_EQUAL_STRING("mov", token1.value);
    token_free(&token1);
    
    // Second token: register
    token_t token2 = lexer_next_token(lexer);
    TEST_ASSERT_EQUAL(TOKEN_REGISTER, token2.type);
    TEST_ASSERT_EQUAL_STRING("rax", token2.value);  // Lexer strips % prefix
    token_free(&token2);
    
    // Third token: comma
    token_t token3 = lexer_next_token(lexer);
    TEST_ASSERT_EQUAL(TOKEN_COMMA, token3.type);
    token_free(&token3);
    
    // Fourth token: immediate
    token_t token4 = lexer_next_token(lexer);
    TEST_ASSERT_EQUAL(TOKEN_IMMEDIATE, token4.type);
    TEST_ASSERT_EQUAL_STRING("0x123", token4.value);  // Lexer strips $ prefix
    token_free(&token4);
}

// Test macro tokens
void test_lexer_macro_tokens(void)
{
    lexer = lexer_create("#define", "test.s");
    token_t token = lexer_next_token(lexer);
    
    TEST_ASSERT_EQUAL(TOKEN_MACRO_DEFINE, token.type);
    TEST_ASSERT_EQUAL_STRING("define", token.value);  // Lexer strips # prefix
    
    token_free(&token);
}

// Test error handling for invalid tokens
void test_lexer_invalid_token(void)
{
    lexer = lexer_create("@@invalid@@", "test.s");
    token_t token = lexer_next_token(lexer);
    
    // Should return error token or handle gracefully
    if (token.type == TOKEN_ERROR) {
        TEST_ASSERT_TRUE(lexer_has_error(lexer));
        TEST_ASSERT_NOT_NULL(lexer_get_error(lexer));
    } else {
        // If lexer handles gracefully, should not be an instruction/register/etc
        TEST_ASSERT_NOT_EQUAL(TOKEN_INSTRUCTION, token.type);
        TEST_ASSERT_NOT_EQUAL(TOKEN_REGISTER, token.type);
    }
    
    token_free(&token);
}

// Test position tracking
void test_lexer_position_tracking(void)
{
    lexer = lexer_create("mov\n%rax", "test.s");
    
    // First token on line 1
    token_t token1 = lexer_next_token(lexer);
    TEST_ASSERT_EQUAL(1, token1.line);
    TEST_ASSERT_EQUAL(1, token1.column);
    token_free(&token1);
    
    // Newline
    token_t token2 = lexer_next_token(lexer);
    TEST_ASSERT_EQUAL(TOKEN_NEWLINE, token2.type);
    token_free(&token2);
    
    // Second token on line 2
    token_t token3 = lexer_next_token(lexer);
    TEST_ASSERT_EQUAL(2, token3.line);
    TEST_ASSERT_EQUAL(1, token3.column);
    token_free(&token3);
}

// Test line and column tracking with complex input
void test_lexer_line_column_tracking(void)
{
    lexer = lexer_create("  mov   %rax\n\t\tadd $5", "test.s");
    
    // mov token - should track column correctly with leading spaces
    token_t token1 = lexer_next_token(lexer);
    TEST_ASSERT_EQUAL(TOKEN_INSTRUCTION, token1.type);
    TEST_ASSERT_EQUAL(1, token1.line);
    token_free(&token1);
    
    // Skip to next line tokens
    token_t token2 = lexer_next_token(lexer); // %rax
    token_free(&token2);
    token_t token3 = lexer_next_token(lexer); // newline
    token_free(&token3);
    token_t token4 = lexer_next_token(lexer); // add
    TEST_ASSERT_EQUAL(2, token4.line);
    token_free(&token4);
}

// Main test runner
int main(void)
{
    UNITY_BEGIN();
    
    // Basic functionality tests
    RUN_TEST(test_lexer_init_success);
    RUN_TEST(test_lexer_init_null_input);
    RUN_TEST(test_lexer_init_empty_input);
    
    // Token recognition tests
    RUN_TEST(test_lexer_instruction_token);
    RUN_TEST(test_lexer_register_token);
    RUN_TEST(test_lexer_immediate_hex);
    RUN_TEST(test_lexer_immediate_decimal);
    RUN_TEST(test_lexer_label_token);
    RUN_TEST(test_lexer_directive_token);
    RUN_TEST(test_lexer_symbol_token);
    RUN_TEST(test_lexer_string_literal);
    RUN_TEST(test_lexer_comment);
    RUN_TEST(test_lexer_comma_token);
    RUN_TEST(test_lexer_parentheses);
    RUN_TEST(test_lexer_newline);
    RUN_TEST(test_lexer_eof);
    
    // Complex parsing tests
    RUN_TEST(test_lexer_multiple_tokens);
    RUN_TEST(test_lexer_macro_tokens);
    
    // Error handling tests
    RUN_TEST(test_lexer_invalid_token);
    
    // Position tracking tests
    RUN_TEST(test_lexer_position_tracking);
    RUN_TEST(test_lexer_line_column_tracking);
    
    return UNITY_END();
}
