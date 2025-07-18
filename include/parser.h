#ifndef PARSER_H
#define PARSER_H

#include "lexer.h"
#include "arch_interface.h"
#include "symbols.h"

// AST node types
typedef enum {
    AST_INSTRUCTION,
    AST_LABEL,
    AST_DIRECTIVE,
    AST_SECTION,
    AST_EXPRESSION,
    AST_OPERAND
} ast_node_type_t;

// AST node structure
typedef struct ast_node {
    ast_node_type_t type;
    token_t token;            // Associated token
    void *data;               // Node-specific data
    struct ast_node *next;    // Next sibling
    struct ast_node *child;   // First child
} ast_node_t;

// Instruction AST data
typedef struct {
    char *mnemonic;
    operand_t *operands;
    size_t operand_count;
    instruction_t *instruction; // Encoded instruction
} ast_instruction_t;

// Label AST data
typedef struct {
    char *name;
    symbol_t *symbol;
} ast_label_t;

// Directive AST data
typedef struct {
    char *name;
    char **args;
    size_t arg_count;
} ast_directive_t;

// Expression AST data
typedef struct {
    enum {
        EXPR_NUMBER,
        EXPR_SYMBOL,
        EXPR_BINARY_OP,
        EXPR_UNARY_OP
    } type;
    
    union {
        int64_t number;
        char *symbol;
        struct {
            struct ast_node *left;
            struct ast_node *right;
            char operator;
        } binary;
        struct {
            struct ast_node *operand;
            char operator;
        } unary;
    } value;
} ast_expression_t;

// Parser state
typedef struct {
    lexer_t *lexer;
    token_t current_token;
    ast_node_t *root;         // AST root
    symbol_table_t *symbols;  // Symbol table
    arch_ops_t *arch;         // Current architecture
    bool error;
    char *error_message;
    size_t current_section;   // Current section ID
    size_t current_address;   // Current address in section
} parser_t;

// Parser functions
parser_t *parser_create(lexer_t *lexer, arch_ops_t *arch);
void parser_destroy(parser_t *parser);
ast_node_t *parser_parse(parser_t *parser);
bool parser_has_error(const parser_t *parser);
const char *parser_get_error(const parser_t *parser);

// AST manipulation
ast_node_t *ast_node_create(ast_node_type_t type, token_t token);
void ast_node_destroy(ast_node_t *node);
void ast_add_child(ast_node_t *parent, ast_node_t *child);
void ast_add_sibling(ast_node_t *node, ast_node_t *sibling);

// Parsing functions
ast_node_t *parse_instruction(parser_t *parser);
ast_node_t *parse_label(parser_t *parser);
ast_node_t *parse_directive(parser_t *parser);
ast_node_t *parse_operand(parser_t *parser);
ast_node_t *parse_expression(parser_t *parser);

// Operand parsing
int parse_register_operand(parser_t *parser, operand_t *operand);
int parse_immediate_operand(parser_t *parser, operand_t *operand);
int parse_memory_operand(parser_t *parser, operand_t *operand);
int parse_symbol_operand(parser_t *parser, operand_t *operand);

// Utility functions
void parser_advance(parser_t *parser);
bool parser_match(parser_t *parser, token_type_t type);
bool parser_expect(parser_t *parser, token_type_t type);
void parser_error(parser_t *parser, const char *format, ...);

#endif // PARSER_H
