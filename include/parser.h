#ifndef PARSER_H
#define PARSER_H

#include "lexer.h"
#include "arch_interface.h"
#include "symbols.h"
#include "include.h"
#include <stdint.h>
#include <stdbool.h>

// Forward declarations
typedef struct parser parser_t;
typedef struct ast_node ast_node_t;

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
struct ast_node {
    ast_node_type_t type;
    token_t token;
    void *data;
    struct ast_node *next;
    struct ast_node *child;
};

// Expression types
typedef enum {
    EXPR_NUMBER,
    EXPR_SYMBOL,
    EXPR_BINARY_OP,
    EXPR_UNARY_OP
} expr_type_t;

// Expression node structures
typedef struct {
    expr_type_t type;
    union {
        int64_t number;
        char *symbol;
        struct {
            ast_node_t *left;
            ast_node_t *right;
            char operator;
        } binary;
        struct {
            ast_node_t *operand;
            char operator;
        } unary;
    } value;
} ast_expression_t;

// Instruction node structure
typedef struct {
    char *mnemonic;
    operand_t *operands;
    size_t operand_count;
} ast_instruction_t;

// Label node structure
typedef struct {
    char *name;
} ast_label_t;

// Directive node structure
typedef struct {
    char *name;
    char **args;
    size_t arg_count;
} ast_directive_t;

// Parser structure
struct parser {
    lexer_t *lexer;
    arch_ops_t *arch;
    symbol_table_t *symbols;
    include_processor_t *includes;
    ast_node_t *root;
    token_t current_token;
    bool error;
    char *error_message;
    uint64_t current_section;
    uint64_t current_address;
};

// Parser interface
parser_t *parser_create(lexer_t *lexer, arch_ops_t *arch);
void parser_destroy(parser_t *parser);
ast_node_t *parser_parse(parser_t *parser);
bool parser_has_error(const parser_t *parser);
const char *parser_get_error(const parser_t *parser);

// Parsing functions
ast_node_t *parse_instruction(parser_t *parser);
ast_node_t *parse_label(parser_t *parser);
ast_node_t *parse_directive(parser_t *parser);
ast_node_t *parse_operand(parser_t *parser);
ast_node_t *parse_expression(parser_t *parser);

// Operand parsing
bool parse_operand_full(parser_t *parser, operand_t *operand);
int parse_register_operand(parser_t *parser, operand_t *operand);
int parse_immediate_operand(parser_t *parser, operand_t *operand);
int parse_memory_operand(parser_t *parser, operand_t *operand);
int parse_symbol_operand(parser_t *parser, operand_t *operand);

// Parser utilities
void parser_advance(parser_t *parser);
bool parser_match(parser_t *parser, token_type_t type);
bool parser_expect(parser_t *parser, token_type_t type);
void parser_error(parser_t *parser, const char *format, ...);

// AST utilities
ast_node_t *ast_node_create(ast_node_type_t type, token_t token);
void ast_node_destroy(ast_node_t *node);
void ast_add_child(ast_node_t *parent, ast_node_t *child);
void ast_add_sibling(ast_node_t *node, ast_node_t *sibling);

// AST printing functions
const char *ast_node_type_to_string(ast_node_type_t type);
const char *operand_type_to_string(operand_type_t type);
void ast_print_tree(const ast_node_t *root);
void ast_print_compact(const ast_node_t *root);

#endif // PARSER_H
