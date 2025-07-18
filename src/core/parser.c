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
    
    // Initialize current_token to avoid garbage values
    parser->current_token.type = TOKEN_EOF;
    parser->current_token.value = NULL;
    parser->current_token.length = 0;
    parser->current_token.line = 0;
    parser->current_token.column = 0;
    parser->current_token.position = 0;
    
    if (!parser->symbols) {
        free(parser);
        return NULL;
    }
    
    return parser;
}

bool parser_has_error(const parser_t *parser) {
    return parser ? parser->error : true;
}

const char *parser_get_error(const parser_t *parser) {
    return parser ? parser->error_message : "Invalid parser";
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
    // Make a deep copy of the token to avoid double-free issues
    node->token.type = token.type;
    node->token.value = token.value ? safe_strdup(token.value) : NULL;
    node->token.length = token.length;
    node->token.line = token.line;
    node->token.column = token.column;
    node->token.position = token.position;
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
        ast_node_t *last_child = parent->child;
        while (last_child->next) {
            last_child = last_child->next;
        }
        last_child->next = child;
    }
}

void ast_add_sibling(ast_node_t *node, ast_node_t *sibling) {
    if (!node || !sibling) {
        return;
    }
    
    while (node->next) {
        node = node->next;
    }
    node->next = sibling;
}

//=============================================================================
// Parser Utility Functions  
//=============================================================================

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

//=============================================================================
// Main Parsing Function
//=============================================================================

ast_node_t *parser_parse(parser_t *parser) {
    if (!parser) {
        return NULL;
    }
    
    // Get first token
    parser->current_token = lexer_next_token(parser->lexer);
    
    ast_node_t *root = NULL;
    ast_node_t *last_stmt = NULL;
    
    while (!parser->error && parser->current_token.type != TOKEN_EOF) {
        ast_node_t *stmt = parse_statement(parser);
        
        if (stmt) {
            if (!root) {
                root = stmt;
                last_stmt = stmt;
            } else {
                last_stmt->next = stmt;
                last_stmt = stmt;
            }
        }
        
        // Skip to next line if not already there
        while ((parser->current_token.type == TOKEN_NEWLINE || 
                parser->current_token.type == TOKEN_COMMENT) && !parser->error) {
            parser_advance(parser);
        }
    }
    
    parser->root = root;
    return root;
}

//=============================================================================
// Statement Parsing (Simplified)
//=============================================================================

static ast_node_t *parse_statement(parser_t *parser) {
    if (!parser || parser->error) {
        return NULL;
    }
    
    // Skip empty lines and comments
    while (parser_match(parser, TOKEN_NEWLINE) || parser_match(parser, TOKEN_COMMENT)) {
        parser_advance(parser);
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
    
    // Parse operands
    size_t operand_count = 0;
    operand_t *operands = NULL;
    
    while (!parser_match(parser, TOKEN_NEWLINE) && !parser_match(parser, TOKEN_EOF)) {
        // Skip commas and comments
        if (parser_match(parser, TOKEN_COMMA) || parser_match(parser, TOKEN_COMMENT)) {
            parser_advance(parser);
            continue;
        }
        
        // Parse operand
        operand_t operand = {0};
        if (parse_operand_full(parser, &operand)) {
            // Resize operands array
            operand_t *new_operands = realloc(operands, (operand_count + 1) * sizeof(operand_t));
            if (!new_operands) {
                free(operands);
                ast_node_destroy(node);
                parser_error(parser, "Failed to allocate operands array");
                return NULL;
            }
            operands = new_operands;
            operands[operand_count] = operand;
            operand_count++;
        } else {
            // Failed to parse operand, skip it
            parser_advance(parser);
        }
    }
    
    inst->operands = operands;
    inst->operand_count = operand_count;
    
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
    
    // Parse directive arguments as strings
    size_t arg_count = 0;
    char **args = NULL;
    
    while (!parser_match(parser, TOKEN_NEWLINE) && !parser_match(parser, TOKEN_EOF)) {
        if (parser_match(parser, TOKEN_COMMA) || parser_match(parser, TOKEN_COMMENT)) {
            parser_advance(parser);
            continue;
        }
        
        // Collect argument as string
        if (parser->current_token.value) {
            char **new_args = realloc(args, (arg_count + 1) * sizeof(char*));
            if (!new_args) {
                // Cleanup on error
                for (size_t i = 0; i < arg_count; i++) {
                    free(args[i]);
                }
                free(args);
                ast_node_destroy(node);
                parser_error(parser, "Failed to allocate directive arguments");
                return NULL;
            }
            args = new_args;
            args[arg_count] = safe_strdup(parser->current_token.value);
            arg_count++;
        }
        parser_advance(parser);
    }
    
    directive->args = args;
    directive->arg_count = arg_count;
    
    return node;
}

//=============================================================================
// Stub Implementations for Remaining Functions
//=============================================================================

//=============================================================================
// Complete Operand Parsing Implementation
//=============================================================================

bool parse_operand_full(parser_t *parser, operand_t *operand) {
    if (!parser || !operand) {
        return false;
    }
    
    memset(operand, 0, sizeof(operand_t));
    
    switch (parser->current_token.type) {
        case TOKEN_REGISTER:
            return parse_register_operand(parser, operand) == 0;
            
        case TOKEN_IMMEDIATE:
            return parse_immediate_operand(parser, operand) == 0;
            
        case TOKEN_SYMBOL:
            return parse_symbol_operand(parser, operand) == 0;
            
        case TOKEN_LPAREN:
            return parse_memory_operand(parser, operand) == 0;
            
        default:
            parser_error(parser, "Unexpected token in operand: %s", 
                        token_type_to_string(parser->current_token.type));
            return false;
    }
}

ast_node_t *parse_operand(parser_t *parser) {
    if (!parser) return NULL;
    
    ast_node_t *node = ast_node_create(AST_OPERAND, parser->current_token);
    if (!node) {
        parser_error(parser, "Failed to create operand node");
        return NULL;
    }
    
    operand_t *operand = calloc(1, sizeof(operand_t));
    if (!operand) {
        ast_node_destroy(node);
        parser_error(parser, "Failed to allocate operand data");
        return NULL;
    }
    
    if (parse_operand_full(parser, operand)) {
        node->data = operand;
        return node;
    } else {
        free(operand);
        ast_node_destroy(node);
        return NULL;
    }
}

ast_node_t *parse_expression(parser_t *parser) {
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
    
    // Simple expression parsing - numbers and symbols for now
    if (parser_match(parser, TOKEN_NUMBER)) {
        expr->type = EXPR_NUMBER;
        expr->value.number = strtoll(parser->current_token.value, NULL, 0);
        parser_advance(parser);
    } else if (parser_match(parser, TOKEN_SYMBOL)) {
        expr->type = EXPR_SYMBOL;
        expr->value.symbol = safe_strdup(parser->current_token.value);
        parser_advance(parser);
    } else {
        free(expr);
        ast_node_destroy(node);
        parser_error(parser, "Expected number or symbol in expression");
        return NULL;
    }
    
    node->data = expr;
    return node;
}

// Operand parsing implementations
int parse_register_operand(parser_t *parser, operand_t *operand) {
    if (!parser || !operand || !parser_match(parser, TOKEN_REGISTER)) {
        return -1;
    }
    
    operand->type = OPERAND_REGISTER;
    
    // Parse register using architecture interface
    if (parser->arch && parser->arch->parse_register) {
        if (parser->arch->parse_register(parser->current_token.value, &operand->value.reg) == 0) {
            operand->size = operand->value.reg.size;
            parser_advance(parser);
            return 0;
        }
    }
    
    // Fallback: simple register parsing
    operand->value.reg.name = safe_strdup(parser->current_token.value);
    operand->value.reg.id = 0; // Will need proper register ID mapping
    
    // Determine size from register name (basic heuristic)
    const char *reg_name = parser->current_token.value;
    if (strstr(reg_name, "r") == reg_name && strlen(reg_name) >= 3) {
        operand->size = 8; // 64-bit register
    } else if (strstr(reg_name, "e") == reg_name) {
        operand->size = 4; // 32-bit register  
    } else if (strlen(reg_name) == 2 || strstr(reg_name, "w")) {
        operand->size = 2; // 16-bit register
    } else {
        operand->size = 1; // 8-bit register
    }
    
    operand->value.reg.size = operand->size;
    parser_advance(parser);
    return 0;
}

int parse_immediate_operand(parser_t *parser, operand_t *operand) {
    if (!parser || !operand || !parser_match(parser, TOKEN_IMMEDIATE)) {
        return -1;
    }
    
    operand->type = OPERAND_IMMEDIATE;
    
    // Parse the immediate value (remove $ prefix)
    const char *value_str = parser->current_token.value;
    if (value_str[0] == '$') {
        value_str++; // Skip the $ prefix
    }
    
    // Parse as number (supports hex with 0x prefix)
    char *endptr;
    operand->value.immediate = strtoll(value_str, &endptr, 0);
    
    if (*endptr != '\0') {
        parser_error(parser, "Invalid immediate value: %s", parser->current_token.value);
        return -1;
    }
    
    // Determine size based on value range
    int64_t val = operand->value.immediate;
    if (val >= -128 && val <= 255) {
        operand->size = 1;
    } else if (val >= -32768 && val <= 65535) {
        operand->size = 2;
    } else if (val >= -2147483648LL && val <= 4294967295LL) {
        operand->size = 4;
    } else {
        operand->size = 8;
    }
    
    parser_advance(parser);
    return 0;
}

int parse_memory_operand(parser_t *parser, operand_t *operand) {
    if (!parser || !operand) {
        return -1;
    }
    
    operand->type = OPERAND_MEMORY;
    addressing_mode_t *addr = &operand->value.memory;
    memset(addr, 0, sizeof(addressing_mode_t));
    
    // For now, implement basic memory operand parsing
    // Full AT&T syntax: displacement(base,index,scale)
    
    if (parser_match(parser, TOKEN_LPAREN)) {
        parser_advance(parser); // consume '('
        
        // Parse base register
        if (parser_match(parser, TOKEN_REGISTER)) {
            if (parser->arch && parser->arch->parse_register) {
                parser->arch->parse_register(parser->current_token.value, &addr->base);
            } else {
                addr->base.name = safe_strdup(parser->current_token.value);
            }
            parser_advance(parser);
        }
        
        // TODO: Parse index and scale for more complex addressing
        // For now, just parse simple (%register) form
        
        if (!parser_expect(parser, TOKEN_RPAREN)) {
            return -1;
        }
        
        addr->type = ADDR_INDIRECT;
        operand->size = 8; // Default to 64-bit addressing
        return 0;
    }
    
    // TODO: Parse displacement(base,index,scale) form
    parser_error(parser, "Complex memory operands not yet implemented");
    return -1;
}

int parse_symbol_operand(parser_t *parser, operand_t *operand) {
    if (!parser || !operand || !parser_match(parser, TOKEN_SYMBOL)) {
        return -1;
    }
    
    operand->type = OPERAND_SYMBOL;
    operand->value.symbol = safe_strdup(parser->current_token.value);
    operand->size = 8; // Default symbol size
    
    parser_advance(parser);
    return 0;
}

//=============================================================================
// AST Printing Functions
//=============================================================================

const char *ast_node_type_to_string(ast_node_type_t type) {
    switch (type) {
        case AST_INSTRUCTION: return "INSTRUCTION";
        case AST_LABEL: return "LABEL";
        case AST_DIRECTIVE: return "DIRECTIVE";
        case AST_SECTION: return "SECTION";
        case AST_EXPRESSION: return "EXPRESSION";
        case AST_OPERAND: return "OPERAND";
        default: return "UNKNOWN";
    }
}

const char *operand_type_to_string(operand_type_t type) {
    switch (type) {
        case OPERAND_REGISTER: return "REGISTER";
        case OPERAND_IMMEDIATE: return "IMMEDIATE";
        case OPERAND_MEMORY: return "MEMORY";
        case OPERAND_SYMBOL: return "SYMBOL";
        default: return "UNKNOWN";
    }
}

void print_indent(int indent) {
    for (int i = 0; i < indent; i++) {
        printf("  ");
    }
}

void ast_print_operand(const operand_t *operand, int indent) {
    if (!operand) return;
    
    print_indent(indent);
    printf("- Operand [%s, size=%zu]: ", operand_type_to_string(operand->type), operand->size);
    
    switch (operand->type) {
        case OPERAND_REGISTER:
            printf("%%%s (id=%u)\n", 
                   operand->value.reg.name ? operand->value.reg.name : "unknown",
                   operand->value.reg.id);
            break;
        case OPERAND_IMMEDIATE:
            printf("$%ld\n", operand->value.immediate);
            break;
        case OPERAND_SYMBOL:
            printf("%s\n", operand->value.symbol ? operand->value.symbol : "NULL");
            break;
        case OPERAND_MEMORY:
            printf("(memory operand)\n");
            print_indent(indent + 1);
            printf("  base: %s\n", operand->value.memory.base.name ? operand->value.memory.base.name : "none");
            break;
    }
}

void ast_print(const ast_node_t *node, int indent) {
    if (!node) {
        return;
    }
    
    print_indent(indent);
    printf("%s", ast_node_type_to_string(node->type));
    
    if (node->token.value) {
        printf(" (\"%s\", line %zu)", node->token.value, node->token.line);
    }
    printf("\n");
    
    // Print node-specific data
    switch (node->type) {
        case AST_INSTRUCTION: {
            ast_instruction_t *inst = (ast_instruction_t *)node->data;
            if (inst) {
                print_indent(indent + 1);
                printf("mnemonic: %s\n", inst->mnemonic ? inst->mnemonic : "NULL");
                print_indent(indent + 1);
                printf("operands: %zu\n", inst->operand_count);
                for (size_t i = 0; i < inst->operand_count; i++) {
                    ast_print_operand(&inst->operands[i], indent + 2);
                }
            }
            break;
        }
        case AST_LABEL: {
            ast_label_t *label = (ast_label_t *)node->data;
            if (label) {
                print_indent(indent + 1);
                printf("name: %s\n", label->name ? label->name : "NULL");
            }
            break;
        }
        case AST_DIRECTIVE: {
            ast_directive_t *directive = (ast_directive_t *)node->data;
            if (directive) {
                print_indent(indent + 1);
                printf("name: %s\n", directive->name ? directive->name : "NULL");
                print_indent(indent + 1);
                printf("args: %zu\n", directive->arg_count);
                for (size_t i = 0; i < directive->arg_count; i++) {
                    print_indent(indent + 2);
                    printf("- \"%s\"\n", directive->args[i] ? directive->args[i] : "NULL");
                }
            }
            break;
        }
        case AST_EXPRESSION: {
            ast_expression_t *expr = (ast_expression_t *)node->data;
            if (expr) {
                print_indent(indent + 1);
                switch (expr->type) {
                    case EXPR_NUMBER:
                        printf("number: %ld\n", expr->value.number);
                        break;
                    case EXPR_SYMBOL:
                        printf("symbol: %s\n", expr->value.symbol ? expr->value.symbol : "NULL");
                        break;
                    case EXPR_BINARY_OP:
                        printf("binary_op: '%c'\n", expr->value.binary.operator);
                        break;
                    case EXPR_UNARY_OP:
                        printf("unary_op: '%c'\n", expr->value.unary.operator);
                        break;
                }
            }
            break;
        }
        case AST_OPERAND: {
            operand_t *operand = (operand_t *)node->data;
            if (operand) {
                ast_print_operand(operand, indent + 1);
            }
            break;
        }
        case AST_SECTION:
            print_indent(indent + 1);
            printf("(section container)\n");
            break;
    }
    
    // Print children
    if (node->child) {
        print_indent(indent + 1);
        printf("children:\n");
        ast_print(node->child, indent + 2);
    }
    
    // Print siblings
    if (node->next) {
        ast_print(node->next, indent);
    }
}

void ast_print_tree(const ast_node_t *root) {
    if (!root) {
        printf("AST: (empty)\n");
        return;
    }
    
    printf("=== AST TREE ===\n");
    ast_print(root, 0);
    printf("=== END AST ===\n");
}

void ast_print_compact(const ast_node_t *root) {
    if (!root) {
        printf("AST: (empty)\n");
        return;
    }
    
    const ast_node_t *current = root;
    int count = 0;
    
    printf("AST Summary:\n");
    while (current) {
        printf("  %d. %s", count + 1, ast_node_type_to_string(current->type));
        
        switch (current->type) {
            case AST_INSTRUCTION: {
                ast_instruction_t *inst = (ast_instruction_t *)current->data;
                if (inst) {
                    printf(" (%s, %zu operands)", 
                           inst->mnemonic ? inst->mnemonic : "NULL",
                           inst->operand_count);
                }
                break;
            }
            case AST_LABEL: {
                ast_label_t *label = (ast_label_t *)current->data;
                if (label) {
                    printf(" (%s)", label->name ? label->name : "NULL");
                }
                break;
            }
            case AST_DIRECTIVE: {
                ast_directive_t *directive = (ast_directive_t *)current->data;
                if (directive) {
                    printf(" (%s, %zu args)", 
                           directive->name ? directive->name : "NULL",
                           directive->arg_count);
                }
                break;
            }
            default:
                break;
        }
        
        if (current->token.line > 0) {
            printf(" [line %zu]", current->token.line);
        }
        printf("\n");
        
        current = current->next;
        count++;
    }
    printf("Total nodes: %d\n", count);
}
