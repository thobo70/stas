/*
 * STAS Expression Parser Implementation
 * Expression parsing and evaluation for the STIX Modular Assembler
 */

#include "expr.h"
#include "parser.h"
#include "lexer.h"
#include "utils.h"
#include "symbols.h"
#include <stdlib.h>
#include <string.h>
#include <stdio.h>

//=============================================================================
// Main Expression Parsing Entry Point
//=============================================================================

ast_node_t *parse_expression(parser_t *parser) {
    if (!parser) return NULL;
    
    return parse_expression_or(parser);
}

//=============================================================================
// Expression Parsing with Operator Precedence (Phase 2 Enhancement)
//=============================================================================

ast_node_t *parse_expression_or(parser_t *parser) {
    if (!parser) return NULL;
    
    ast_node_t *left = parse_expression_and(parser);
    if (!left) return NULL;
    
    while (parser_match_operator(parser, "||")) {
        token_t op_token = parser->current_token;
        parser_advance(parser);
        
        ast_node_t *right = parse_expression_and(parser);
        if (!right) {
            ast_node_destroy(left);
            return NULL;
        }
        
        left = create_binary_expression(parser, left, right, "||", op_token);
        if (!left) {
            ast_node_destroy(right);
            return NULL;
        }
    }
    
    return left;
}

ast_node_t *parse_expression_and(parser_t *parser) {
    if (!parser) return NULL;
    
    ast_node_t *left = parse_expression_bitwise_or(parser);
    if (!left) return NULL;
    
    while (parser_match_operator(parser, "&&")) {
        token_t op_token = parser->current_token;
        parser_advance(parser);
        
        ast_node_t *right = parse_expression_bitwise_or(parser);
        if (!right) {
            ast_node_destroy(left);
            return NULL;
        }
        
        left = create_binary_expression(parser, left, right, "&&", op_token);
        if (!left) {
            ast_node_destroy(right);
            return NULL;
        }
    }
    
    return left;
}

ast_node_t *parse_expression_bitwise_or(parser_t *parser) {
    if (!parser) return NULL;
    
    ast_node_t *left = parse_expression_bitwise_xor(parser);
    if (!left) return NULL;
    
    while (parser_match_operator(parser, "|")) {
        token_t op_token = parser->current_token;
        parser_advance(parser);
        
        ast_node_t *right = parse_expression_bitwise_xor(parser);
        if (!right) {
            ast_node_destroy(left);
            return NULL;
        }
        
        left = create_binary_expression(parser, left, right, "|", op_token);
        if (!left) {
            ast_node_destroy(right);
            return NULL;
        }
    }
    
    return left;
}

ast_node_t *parse_expression_bitwise_xor(parser_t *parser) {
    if (!parser) return NULL;
    
    ast_node_t *left = parse_expression_bitwise_and(parser);
    if (!left) return NULL;
    
    while (parser_match_operator(parser, "^")) {
        token_t op_token = parser->current_token;
        parser_advance(parser);
        
        ast_node_t *right = parse_expression_bitwise_and(parser);
        if (!right) {
            ast_node_destroy(left);
            return NULL;
        }
        
        left = create_binary_expression(parser, left, right, "^", op_token);
        if (!left) {
            ast_node_destroy(right);
            return NULL;
        }
    }
    
    return left;
}

ast_node_t *parse_expression_bitwise_and(parser_t *parser) {
    if (!parser) return NULL;
    
    ast_node_t *left = parse_expression_equality(parser);
    if (!left) return NULL;
    
    while (parser_match_operator(parser, "&")) {
        token_t op_token = parser->current_token;
        parser_advance(parser);
        
        ast_node_t *right = parse_expression_equality(parser);
        if (!right) {
            ast_node_destroy(left);
            return NULL;
        }
        
        left = create_binary_expression(parser, left, right, "&", op_token);
        if (!left) {
            ast_node_destroy(right);
            return NULL;
        }
    }
    
    return left;
}

ast_node_t *parse_expression_equality(parser_t *parser) {
    if (!parser) return NULL;
    
    ast_node_t *left = parse_expression_relational(parser);
    if (!left) return NULL;
    
    while (parser_match_operator(parser, "==") || parser_match_operator(parser, "!=")) {
        token_t op_token = parser->current_token;
        parser_advance(parser);
        
        ast_node_t *right = parse_expression_relational(parser);
        if (!right) {
            ast_node_destroy(left);
            return NULL;
        }
        
        left = create_binary_expression(parser, left, right, op_token.value, op_token);
        if (!left) {
            ast_node_destroy(right);
            return NULL;
        }
    }
    
    return left;
}

ast_node_t *parse_expression_relational(parser_t *parser) {
    if (!parser) return NULL;
    
    ast_node_t *left = parse_expression_shift(parser);
    if (!left) return NULL;
    
    while (parser_match_operator(parser, "<") || parser_match_operator(parser, ">") ||
           parser_match_operator(parser, "<=") || parser_match_operator(parser, ">=")) {
        token_t op_token = parser->current_token;
        parser_advance(parser);
        
        ast_node_t *right = parse_expression_shift(parser);
        if (!right) {
            ast_node_destroy(left);
            return NULL;
        }
        
        left = create_binary_expression(parser, left, right, op_token.value, op_token);
        if (!left) {
            ast_node_destroy(right);
            return NULL;
        }
    }
    
    return left;
}

ast_node_t *parse_expression_shift(parser_t *parser) {
    if (!parser) return NULL;
    
    ast_node_t *left = parse_expression_additive(parser);
    if (!left) return NULL;
    
    while (parser_match_operator(parser, "<<") || parser_match_operator(parser, ">>")) {
        token_t op_token = parser->current_token;
        parser_advance(parser);
        
        ast_node_t *right = parse_expression_additive(parser);
        if (!right) {
            ast_node_destroy(left);
            return NULL;
        }
        
        left = create_binary_expression(parser, left, right, op_token.value, op_token);
        if (!left) {
            ast_node_destroy(right);
            return NULL;
        }
    }
    
    return left;
}

ast_node_t *parse_expression_additive(parser_t *parser) {
    if (!parser) return NULL;
    
    ast_node_t *left = parse_expression_multiplicative(parser);
    if (!left) return NULL;
    
    while (parser_match_operator(parser, "+") || parser_match_operator(parser, "-")) {
        token_t op_token = parser->current_token;
        const char *operator;
        if (parser_match_operator(parser, "+")) {
            operator = "+";
        } else {
            operator = "-";
        }
        parser_advance(parser);
        
        ast_node_t *right = parse_expression_multiplicative(parser);
        if (!right) {
            ast_node_destroy(left);
            return NULL;
        }
        
        left = create_binary_expression(parser, left, right, operator, op_token);
        if (!left) {
            ast_node_destroy(right);
            return NULL;
        }
    }
    
    return left;
}

ast_node_t *parse_expression_multiplicative(parser_t *parser) {
    if (!parser) return NULL;
    
    ast_node_t *left = parse_expression_unary(parser);
    if (!left) return NULL;
    
    while (parser_match_operator(parser, "*") || parser_match_operator(parser, "/") || 
           parser_match_operator(parser, "%")) {
        token_t op_token = parser->current_token;
        const char *operator;
        if (parser_match_operator(parser, "*")) {
            operator = "*";
        } else if (parser_match_operator(parser, "/")) {
            operator = "/";
        } else {
            operator = "%";
        }
        parser_advance(parser);
        
        ast_node_t *right = parse_expression_unary(parser);
        if (!right) {
            ast_node_destroy(left);
            return NULL;
        }
        
        left = create_binary_expression(parser, left, right, operator, op_token);
        if (!left) {
            ast_node_destroy(right);
            return NULL;
        }
    }
    
    return left;
}

ast_node_t *parse_expression_unary(parser_t *parser) {
    if (!parser) return NULL;
    
    // Handle unary operators: +, -, ~, !
    if (parser_match_operator(parser, "+") || parser_match_operator(parser, "-") ||
        parser_match_operator(parser, "~") || parser_match_operator(parser, "!")) {
        token_t op_token = parser->current_token;
        parser_advance(parser);
        
        ast_node_t *operand = parse_expression_unary(parser);
        if (!operand) {
            return NULL;
        }
        
        return create_unary_expression(parser, operand, op_token.value, op_token);
    }
    
    return parse_expression_primary(parser);
}

ast_node_t *parse_expression_primary(parser_t *parser) {
    if (!parser) return NULL;
    
    ast_node_t *node = ast_node_create(AST_EXPRESSION, parser->current_token);
    if (!node) {
        parser_error(parser, "Failed to create expression node");
        return NULL;
    }
    
    ast_expression_t *expr = calloc(1, sizeof(ast_expression_t));
    if (!expr) {
        ast_node_destroy(node);
        parser_error(parser, "Failed to allocate expression data");
        return NULL;
    }
    
    // Handle parentheses for grouping
    if (parser_match(parser, TOKEN_LPAREN)) {
        ast_node_destroy(node);
        free(expr);
        parser_advance(parser); // consume '('
        
        ast_node_t *grouped_expr = parse_expression_or(parser);
        if (!grouped_expr) {
            return NULL;
        }
        
        if (!parser_match(parser, TOKEN_RPAREN)) {
            ast_node_destroy(grouped_expr);
            parser_error(parser, "Expected ')' after grouped expression");
            return NULL;
        }
        parser_advance(parser); // consume ')'
        
        return grouped_expr;
    }
    
    // Handle numbers with different bases
    if (parser_match(parser, TOKEN_NUMBER)) {
        expr->type = EXPR_NUMBER;
        const char *num_str = parser->current_token.value;
        expr->value.number = parse_number_with_base(num_str);
        parser_advance(parser);
    } 
    // Handle symbols with forward reference support
    else if (parser_match(parser, TOKEN_SYMBOL)) {
        expr->type = EXPR_SYMBOL;
        expr->value.symbol = safe_strdup(parser->current_token.value);
        
        // Register forward reference for later resolution
        if (parser->symbols) {
            symbol_add_forward_reference(parser->symbols, parser->current_token.value, 
                                       parser->current_address);
        }
        parser_advance(parser);
    } 
    // Handle immediate values with $ prefix
    else if (parser_match(parser, TOKEN_IMMEDIATE)) {
        expr->type = EXPR_NUMBER;
        // Remove $ prefix and parse the number
        const char *imm_str = parser->current_token.value + 1; // skip '$'
        expr->value.number = parse_number_with_base(imm_str);
        parser_advance(parser);
    }
    else {
        free(expr);
        ast_node_destroy(node);
        parser_error(parser, "Expected number, symbol, or '(' in expression");
        return NULL;
    }
    
    node->data = expr;
    return node;
}

//=============================================================================
// Expression Creation Functions
//=============================================================================

ast_node_t *create_binary_expression(parser_t *parser, ast_node_t *left, ast_node_t *right, 
                                    const char *operator, token_t op_token) {
    if (!parser || !left || !right || !operator) {
        return NULL;
    }
    
    ast_node_t *node = ast_node_create(AST_EXPRESSION, op_token);
    if (!node) {
        parser_error(parser, "Failed to create binary expression node");
        return NULL;
    }
    
    ast_expression_t *expr = calloc(1, sizeof(ast_expression_t));
    if (!expr) {
        ast_node_destroy(node);
        parser_error(parser, "Failed to allocate binary expression data");
        return NULL;
    }
    
    expr->type = EXPR_BINARY_OP;
    expr->value.binary.left = left;
    expr->value.binary.right = right;
    expr->value.binary.operator = operator[0]; // Store first character for now
    
    node->data = expr;
    return node;
}

ast_node_t *create_unary_expression(parser_t *parser, ast_node_t *operand, 
                                   const char *operator, token_t op_token) {
    if (!parser || !operand || !operator) {
        return NULL;
    }
    
    ast_node_t *node = ast_node_create(AST_EXPRESSION, op_token);
    if (!node) {
        parser_error(parser, "Failed to create unary expression node");
        return NULL;
    }
    
    ast_expression_t *expr = calloc(1, sizeof(ast_expression_t));
    if (!expr) {
        ast_node_destroy(node);
        parser_error(parser, "Failed to allocate unary expression data");
        return NULL;
    }
    
    expr->type = EXPR_UNARY_OP;
    expr->value.unary.operand = operand;
    expr->value.unary.operator = operator[0]; // Store first character for now
    
    node->data = expr;
    return node;
}

//=============================================================================
// Expression Evaluation Functions
//=============================================================================

int64_t evaluate_expression_ast(parser_t *parser, ast_node_t *expr_node) {
    if (!parser || !expr_node || expr_node->type != AST_EXPRESSION) {
        return 0;
    }
    
    ast_expression_t *expr = (ast_expression_t *)expr_node->data;
    if (!expr) return 0;
    
    switch (expr->type) {
        case EXPR_NUMBER:
            return expr->value.number;
            
        case EXPR_SYMBOL: {
            int64_t value = 0;
            if (resolve_symbol_value(parser, expr->value.symbol, &value)) {
                return value;
            }
            // Forward reference - return 0 for now, will be resolved later
            return 0;
        }
        
        case EXPR_BINARY_OP: {
            int64_t left_val = evaluate_expression_ast(parser, expr->value.binary.left);
            int64_t right_val = evaluate_expression_ast(parser, expr->value.binary.right);
            
            switch (expr->value.binary.operator) {
                case '+': return left_val + right_val;
                case '-': return left_val - right_val;
                case '*': return left_val * right_val;
                case '/': return right_val != 0 ? left_val / right_val : 0;
                case '%': return right_val != 0 ? left_val % right_val : 0;
                case '&': return left_val & right_val;
                case '|': return left_val | right_val;
                case '^': return left_val ^ right_val;
                case '<': return left_val < right_val ? 1 : 0;
                case '>': return left_val > right_val ? 1 : 0;
                case '=': return left_val == right_val ? 1 : 0; // == operator
                case '!': return left_val != right_val ? 1 : 0; // != operator
                default: return 0;
            }
        }
        
        case EXPR_UNARY_OP: {
            int64_t operand_val = evaluate_expression_ast(parser, expr->value.unary.operand);
            
            switch (expr->value.unary.operator) {
                case '+': return operand_val;
                case '-': return -operand_val;
                case '~': return ~operand_val;
                case '!': return !operand_val ? 1 : 0;
                default: return 0;
            }
        }
        
        default:
            return 0;
    }
}

// Phase 3 Enhancement: Enhanced symbol resolution with forward reference support
bool resolve_symbol_value(parser_t *parser, const char *symbol, int64_t *value) {
    if (!parser || !symbol || !value) {
        return false;
    }
    
    if (!parser->symbols) {
        return false;
    }
    
    // Use enhanced symbol resolution from Phase 3
    if (symbol_is_defined(parser->symbols, symbol)) {
        *value = symbol_resolve_value(parser->symbols, symbol);
        return true;
    }
    
    // Symbol not defined yet - this is a forward reference
    // Add forward reference for later resolution
    symbol_add_forward_reference(parser->symbols, symbol, 
                                parser->current_address);
    
    // For now, return 0 as placeholder value
    // This will be resolved in a second pass
    *value = 0;
    return true; // Return true to allow parsing to continue
}

//=============================================================================
// Expression Utility Functions
//=============================================================================

bool parser_match_operator(parser_t *parser, const char *operator) {
    if (!parser || !operator) return false;
    
    return parser_match(parser, TOKEN_OPERATOR) && 
           strcmp(parser->current_token.value, operator) == 0;
}

//=============================================================================
// Phase 3 Enhancement: Advanced Expression Symbol Integration
//=============================================================================

// Evaluate expression with symbol address calculation
int64_t evaluate_expression_with_address_calc(parser_t *parser, ast_node_t *node, 
                                             uint64_t base_address) {
    if (!parser || !node) {
        return 0;
    }
    
    int64_t base_result = evaluate_expression_ast(parser, node);
    return base_result + (int64_t)base_address;
}

// Resolve all symbols in an expression and calculate final value
int64_t resolve_expression_symbols(parser_t *parser, const char *expression_str) {
    if (!parser || !expression_str) {
        return 0;
    }
    
    // Create a temporary lexer for the expression
    lexer_t *expr_lexer = lexer_create(expression_str, "expression");
    if (!expr_lexer) {
        return 0;
    }
    
    // Save current parser state
    lexer_t *saved_lexer = parser->lexer;
    token_t saved_token = parser->current_token;
    
    // Set up parser for expression
    parser->lexer = expr_lexer;
    parser->current_token = lexer_next_token(expr_lexer);
    
    // Parse and evaluate the expression
    ast_node_t *expr_node = parse_expression(parser);
    int64_t result = 0;
    
    if (expr_node) {
        result = evaluate_expression_ast(parser, expr_node);
        ast_node_destroy(expr_node);
    }
    
    // Restore parser state
    parser->lexer = saved_lexer;
    parser->current_token = saved_token;
    lexer_destroy(expr_lexer);
    
    return result;
}

// Update symbol table with expression results
int update_symbols_from_expressions(parser_t *parser) {
    if (!parser || !parser->symbols) {
        return 0;
    }
    
    // Resolve all forward references
    int resolved = symbol_resolve_all_forward_references(parser->symbols);
    
    return resolved;
}

// Check if expression contains forward references
bool expression_has_forward_refs(parser_t *parser, ast_node_t *node) {
    if (!parser || !node) {
        return false;
    }
    
    if (node->type == AST_EXPRESSION) {
        ast_expression_t *expr = (ast_expression_t *)node->data;
        if (expr && expr->type == EXPR_SYMBOL) {
            return !symbol_is_defined(parser->symbols, expr->value.symbol);
        }
    }
    
    // Check children recursively
    bool has_forward_refs = false;
    if (node->child) {
        has_forward_refs |= expression_has_forward_refs(parser, node->child);
    }
    if (node->next) {
        has_forward_refs |= expression_has_forward_refs(parser, node->next);
    }
    
    return has_forward_refs;
}
