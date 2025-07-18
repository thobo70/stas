/*
 * STAS Expression Parser Header
 * Expression parsing and evaluation for the STIX Modular Assembler
 */

#ifndef EXPR_H
#define EXPR_H

#include <stdint.h>
#include <stdbool.h>
#include "lexer.h" // For token_t definition

// Forward declarations to avoid circular dependencies
struct parser;
struct ast_node;

//=============================================================================
// Expression Parsing Functions  
//=============================================================================

// Main expression parsing entry point
struct ast_node *parse_expression(struct parser *parser);

// Expression parsing with operator precedence (Phase 2 Enhancement)
// Precedence levels (lowest to highest):
struct ast_node *parse_expression_or(struct parser *parser);           // 1. OR (||)
struct ast_node *parse_expression_and(struct parser *parser);          // 2. AND (&&) 
struct ast_node *parse_expression_bitwise_or(struct parser *parser);   // 3. Bitwise OR (|)
struct ast_node *parse_expression_bitwise_xor(struct parser *parser);  // 4. Bitwise XOR (^)
struct ast_node *parse_expression_bitwise_and(struct parser *parser);  // 5. Bitwise AND (&)
struct ast_node *parse_expression_equality(struct parser *parser);     // 6. Equality (==, !=)
struct ast_node *parse_expression_relational(struct parser *parser);   // 7. Relational (<, >, <=, >=)
struct ast_node *parse_expression_shift(struct parser *parser);        // 8. Shift (<<, >>)
struct ast_node *parse_expression_additive(struct parser *parser);     // 9. Addition/Subtraction (+, -)
struct ast_node *parse_expression_multiplicative(struct parser *parser); // 10. Multiplication/Division/Modulo (*, /, %)
struct ast_node *parse_expression_unary(struct parser *parser);        // 11. Unary (+, -, ~, !)
struct ast_node *parse_expression_primary(struct parser *parser);      // 12. Primary (numbers, symbols, parentheses)

//=============================================================================
// Expression Creation Functions
//=============================================================================

// Create binary expression node
struct ast_node *create_binary_expression(struct parser *parser, struct ast_node *left, struct ast_node *right, 
                                    const char *operator, token_t op_token);

// Create unary expression node
struct ast_node *create_unary_expression(struct parser *parser, struct ast_node *operand, 
                                   const char *operator, token_t op_token);

//=============================================================================
// Expression Evaluation Functions
//=============================================================================

// Expression evaluation function for constant folding and symbol resolution
int64_t evaluate_expression_ast(struct parser *parser, struct ast_node *node);

// Symbol resolution function
bool resolve_symbol_value(struct parser *parser, const char *symbol, int64_t *value);

//=============================================================================
// Expression Utility Functions
//=============================================================================

// Helper function to match operators
bool parser_match_operator(struct parser *parser, const char *operator);

#endif // EXPR_H
