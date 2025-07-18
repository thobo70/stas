/*
 * STAS Parser Implementation
 * AST node creation and management for the STIX Modular Assembler
 */

#define _GNU_SOURCE
#include "parser.h"
#include "utils.h"
#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <stdarg.h>

// Forward declarations
static ast_node_t *parse_statement(parser_t *parser);
static char *safe_strdup(const char *s);

//=============================================================================
// Utility Functions
//=============================================================================

static char *safe_strdup(const char *s) {
    if (!s) return NULL;
    size_t len = strlen(s) + 1;
    char *dup = malloc(len);
    if (dup) {
        memcpy(dup, s, len);
    }
    return dup;
}

//=============================================================================
// Parser Creation and Destruction
//=============================================================================

parser_t *parser_create(lexer_t *lexer, arch_ops_t *arch) {
    if (!lexer || !arch) {
        return NULL;
    }
    
    parser_t *parser = calloc(1, sizeof(parser_t));
    if (!parser) {
        return NULL;
    }
    
    parser->lexer = lexer;
    parser->arch = arch;
    parser->symbols = symbol_table_create(256);
    parser->root = NULL;
    parser->error = false;
    parser->error_message = NULL;
    parser->current_section = 0;
    parser->current_address = 0;
    
    if (!parser->symbols) {
        free(parser);
        return NULL;
    }
    
    // Get first token
    parser->current_token = lexer_next_token(lexer);
    
    return parser;
}

void parser_destroy(parser_t *parser) {
    if (!parser) {
        return;
    }
    
    if (parser->root) {
        ast_node_destroy(parser->root);
    }
    
    if (parser->symbols) {
        symbol_table_destroy(parser->symbols);
    }
    
    if (parser->error_message) {
        free(parser->error_message);
    }
    
    token_free(&parser->current_token);
    free(parser);
}

//=============================================================================
// AST Node Creation and Management
//=============================================================================

ast_node_t *ast_node_create(ast_node_type_t type, token_t token) {
    ast_node_t *node = calloc(1, sizeof(ast_node_t));
    if (!node) {
        return NULL;
    }
    
    node->type = type;
    node->token = token;
    node->data = NULL;
    node->next = NULL;
    node->child = NULL;
    
    return node;
}

void ast_node_destroy(ast_node_t *node) {
    if (!node) {
        return;
    }
    
    // Recursively destroy children and siblings
    if (node->child) {
        ast_node_destroy(node->child);
    }
    
    if (node->next) {
        ast_node_destroy(node->next);
    }
    
    // Free node-specific data
    if (node->data) {
        switch (node->type) {
            case AST_INSTRUCTION: {
                ast_instruction_t *inst = (ast_instruction_t *)node->data;
                free(inst->mnemonic);
                if (inst->operands) {
                    free(inst->operands);
                }
                free(inst);
                break;
            }
            case AST_LABEL: {
                ast_label_t *label = (ast_label_t *)node->data;
                free(label->name);
                free(label);
                break;
            }
            case AST_DIRECTIVE: {
                ast_directive_t *directive = (ast_directive_t *)node->data;
                free(directive->name);
                if (directive->args) {
                    for (size_t i = 0; i < directive->arg_count; i++) {
                        free(directive->args[i]);
                    }
                    free(directive->args);
                }
                free(directive);
                break;
            }
            case AST_EXPRESSION: {
                ast_expression_t *expr = (ast_expression_t *)node->data;
                if (expr->type == EXPR_SYMBOL && expr->value.symbol) {
                    free(expr->value.symbol);
                }
                free(expr);
                break;
            }
            default:
                free(node->data);
                break;
        }
    }
    
    token_free(&node->token);
    free(node);
}

void ast_add_child(ast_node_t *parent, ast_node_t *child) {
    if (!parent || !child) {
        return;
    }
    
    if (!parent->child) {
        parent->child = child;
    } else {
        ast_node_t *current = parent->child;
        while (current->next) {
            current = current->next;
        }
        current->next = child;
    }
}

void ast_add_sibling(ast_node_t *node, ast_node_t *sibling) {
    if (!node || !sibling) {
        return;
    }
    
    ast_node_t *current = node;
    while (current->next) {
        current = current->next;
    }
    current->next = sibling;
}

//=============================================================================
// Parser State Management
//=============================================================================

void parser_advance(parser_t *parser) {
    if (!parser || parser->current_token.type == TOKEN_EOF) {
        return;
    }
    
    token_free(&parser->current_token);
    parser->current_token = lexer_next_token(parser->lexer);
}

bool parser_match(parser_t *parser, token_type_t type) {
    if (!parser) {
        return false;
    }
    return parser->current_token.type == type;
}

bool parser_expect(parser_t *parser, token_type_t type) {
    if (!parser) {
        return false;
    }
    
    if (parser->current_token.type == type) {
        parser_advance(parser);
        return true;
    }
    
    parser_error(parser, "Expected %s, got %s", 
                 token_type_to_string(type),
                 token_type_to_string(parser->current_token.type));
    return false;
}

void parser_error(parser_t *parser, const char *format, ...) {
    if (!parser || parser->error) {
        return;
    }
    
    parser->error = true;
    
    char *message = malloc(512);
    if (!message) {
        parser->error_message = safe_strdup("Memory allocation failed");
        return;
    }
    
    va_list args;
    va_start(args, format);
    vsnprintf(message, 512, format, args);
    va_end(args);
    
    parser->error_message = message;
}

bool parser_has_error(const parser_t *parser) {
    return parser ? parser->error : true;
}

const char *parser_get_error(const parser_t *parser) {
    return parser ? parser->error_message : "Invalid parser";
}

//=============================================================================
// Main Parsing Function
//=============================================================================

ast_node_t *parser_parse(parser_t *parser) {
    if (!parser) {
        return NULL;
    }
    
    // Create root node
    token_t root_token = {TOKEN_EOF, NULL, 0, 0, 0, 0};
    parser->root = ast_node_create(AST_SECTION, root_token);
    if (!parser->root) {
        parser_error(parser, "Failed to create AST root node");
        return NULL;
    }
    
    // Parse statements until EOF
    while (!parser->error && parser->current_token.type != TOKEN_EOF) {
        ast_node_t *stmt = parse_statement(parser);
        if (stmt) {
            ast_add_child(parser->root, stmt);
        }
        
        // Skip newlines
        while (parser_match(parser, TOKEN_NEWLINE)) {
            parser_advance(parser);
        }
    }
    
    return parser->root;
}

//=============================================================================
// Statement Parsing (Simplified)
//=============================================================================

static ast_node_t *parse_statement(parser_t *parser) {
    if (!parser || parser->error) {
        return NULL;
    }
    
    // Skip empty lines
    if (parser_match(parser, TOKEN_NEWLINE)) {
        parser_advance(parser);
        return NULL;
    }
    
    switch (parser->current_token.type) {
        case TOKEN_LABEL:
            return parse_label(parser);
        case TOKEN_DIRECTIVE:
            return parse_directive(parser);
        case TOKEN_INSTRUCTION:
            return parse_instruction(parser);
        case TOKEN_EOF:
            return NULL;
        default:
            parser_error(parser, "Unexpected token: %s", 
                        token_type_to_string(parser->current_token.type));
            return NULL;
    }
}

//=============================================================================
// Specific Parsing Functions (Simplified Implementations)
//=============================================================================

ast_node_t *parse_instruction(parser_t *parser) {
    if (!parser || !parser_match(parser, TOKEN_INSTRUCTION)) {
        return NULL;
    }
    
    ast_node_t *node = ast_node_create(AST_INSTRUCTION, parser->current_token);
    if (!node) {
        parser_error(parser, "Failed to create instruction node");
        return NULL;
    }
    
    ast_instruction_t *inst = calloc(1, sizeof(ast_instruction_t));
    if (!inst) {
        ast_node_destroy(node);
        parser_error(parser, "Failed to allocate instruction data");
        return NULL;
    }
    
    inst->mnemonic = safe_strdup(parser->current_token.value);
    node->data = inst;
    parser_advance(parser);
    
    // Simple operand parsing - skip for now
    while (!parser_match(parser, TOKEN_NEWLINE) && !parser_match(parser, TOKEN_EOF)) {
        parser_advance(parser);
    }
    
    return node;
}

ast_node_t *parse_label(parser_t *parser) {
    if (!parser || !parser_match(parser, TOKEN_LABEL)) {
        return NULL;
    }
    
    ast_node_t *node = ast_node_create(AST_LABEL, parser->current_token);
    if (!node) {
        parser_error(parser, "Failed to create label node");
        return NULL;
    }
    
    ast_label_t *label = calloc(1, sizeof(ast_label_t));
    if (!label) {
        ast_node_destroy(node);
        parser_error(parser, "Failed to allocate label data");
        return NULL;
    }
    
    // Copy label name, removing trailing colon
    char *label_text = safe_strdup(parser->current_token.value);
    if (label_text) {
        size_t len = strlen(label_text);
        if (len > 0 && label_text[len - 1] == ':') {
            label_text[len - 1] = '\0';
        }
        label->name = label_text;
    }
    
    node->data = label;
    parser_advance(parser);
    
    return node;
}

ast_node_t *parse_directive(parser_t *parser) {
    if (!parser || !parser_match(parser, TOKEN_DIRECTIVE)) {
        return NULL;
    }
    
    ast_node_t *node = ast_node_create(AST_DIRECTIVE, parser->current_token);
    if (!node) {
        parser_error(parser, "Failed to create directive node");
        return NULL;
    }
    
    ast_directive_t *directive = calloc(1, sizeof(ast_directive_t));
    if (!directive) {
        ast_node_destroy(node);
        parser_error(parser, "Failed to allocate directive data");
        return NULL;
    }
    
    directive->name = safe_strdup(parser->current_token.value);
    node->data = directive;
    parser_advance(parser);
    
    // Simple directive parsing - skip arguments for now
    while (!parser_match(parser, TOKEN_NEWLINE) && !parser_match(parser, TOKEN_EOF)) {
        parser_advance(parser);
    }
    
    return node;
}

//=============================================================================
// Stub Implementations for Remaining Functions
//=============================================================================

ast_node_t *parse_operand(parser_t *parser) {
    if (!parser) return NULL;
    
    // Stub implementation
    ast_node_t *node = ast_node_create(AST_OPERAND, parser->current_token);
    if (node) {
        parser_advance(parser);
    }
    return node;
}

ast_node_t *parse_expression(parser_t *parser) {
    if (!parser) return NULL;
    
    // Stub implementation
    ast_node_t *node = ast_node_create(AST_EXPRESSION, parser->current_token);
    if (node) {
        parser_advance(parser);
    }
    return node;
}

// Operand parsing stubs
int parse_register_operand(parser_t *parser, operand_t *operand) {
    (void)parser; (void)operand; // Suppress unused warnings
    return 0;
}

int parse_immediate_operand(parser_t *parser, operand_t *operand) {
    (void)parser; (void)operand;
    return 0;
}

int parse_memory_operand(parser_t *parser, operand_t *operand) {
    (void)parser; (void)operand;
    return 0;
}

int parse_symbol_operand(parser_t *parser, operand_t *operand) {
    (void)parser; (void)operand;
    return 0;
}
