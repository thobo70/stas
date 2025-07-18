#ifndef LEXER_H
#define LEXER_H

#include <stddef.h>
#include <stdbool.h>

// Token types for AT&T syntax assembly
typedef enum {
    TOKEN_INSTRUCTION,    // mov, add, sub, etc.
    TOKEN_REGISTER,       // %rax, %rbx, etc.
    TOKEN_IMMEDIATE,      // $123, $0x456, etc.
    TOKEN_SYMBOL,         // labels, variable names
    TOKEN_LABEL,          // symbol followed by ':'
    TOKEN_DIRECTIVE,      // .section, .global, etc.
    TOKEN_STRING,         // "string literal"
    TOKEN_NUMBER,         // 123, 0x456, etc.
    TOKEN_OPERATOR,       // +, -, *, /, etc.
    TOKEN_COMMA,          // ,
    TOKEN_LPAREN,         // (
    TOKEN_RPAREN,         // )
    TOKEN_NEWLINE,        // \n
    TOKEN_COMMENT,        // # comment
    TOKEN_EOF,            // End of file
    TOKEN_ERROR           // Lexical error
} token_type_t;

// Token structure
typedef struct {
    token_type_t type;
    char *value;          // Token string value
    size_t length;        // Length of token
    size_t line;          // Line number (1-based)
    size_t column;        // Column number (1-based)
    size_t position;      // Absolute position in input
} token_t;

// Lexer state
typedef struct {
    const char *input;    // Input string
    size_t length;        // Input length
    size_t position;      // Current position
    size_t line;          // Current line number
    size_t column;        // Current column number
    const char *filename; // Source filename
    bool error;           // Error flag
    char *error_message;  // Error message
} lexer_t;

// Lexer functions
lexer_t *lexer_create(const char *input, const char *filename);
void lexer_destroy(lexer_t *lexer);
token_t lexer_next_token(lexer_t *lexer);
void token_free(token_t *token);
bool lexer_has_error(const lexer_t *lexer);
const char *lexer_get_error(const lexer_t *lexer);

// Utility functions
const char *token_type_to_string(token_type_t type);
bool is_instruction_token(const char *str);
bool is_register_token(const char *str);
bool is_directive_token(const char *str);

#endif // LEXER_H
