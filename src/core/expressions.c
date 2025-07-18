/*
 * Expression Evaluator for STAS
 * Handles arithmetic expressions, symbol resolution, and forward references
 */

#include "../core/expressions.h"
#include "symbols.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>

//=============================================================================
// Expression Evaluation Context
//=============================================================================

typedef struct expr_context {
    symbol_table_t *symbols;
    size_t current_address;
    size_t current_section;
    bool allow_forward_refs;
} expr_context_t;

//=============================================================================
// Expression Parser (Simple Implementation)
//=============================================================================

static int parse_number(const char *str, int64_t *value) {
    if (!str || !value) {
        return -1;
    }
    
    char *endptr;
    
    // Handle different number formats
    if (strncmp(str, "0x", 2) == 0 || strncmp(str, "0X", 2) == 0) {
        // Hexadecimal
        *value = strtoll(str + 2, &endptr, 16);
    } else if (str[0] == '0' && strlen(str) > 1 && isdigit(str[1])) {
        // Octal
        *value = strtoll(str + 1, &endptr, 8);
    } else {
        // Decimal
        *value = strtoll(str, &endptr, 10);
    }
    
    return (*endptr == '\0') ? 0 : -1;
}

static int evaluate_symbol(const char *symbol_name, expr_context_t *ctx, int64_t *value) {
    if (!symbol_name || !ctx || !value) {
        return -1;
    }
    
    symbol_t *symbol = symbol_table_lookup(ctx->symbols, symbol_name);
    if (!symbol) {
        if (ctx->allow_forward_refs) {
            // Forward reference - will be resolved later
            *value = 0;
            return 1; // Special return code for forward reference
        }
        return -1; // Symbol not found
    }
    
    *value = symbol->value;
    return 0;
}

//=============================================================================
// Expression Evaluation Functions
//=============================================================================

int evaluate_expression(const char *expr_str, expr_context_t *ctx, int64_t *result) {
    if (!expr_str || !ctx || !result) {
        return -1;
    }
    
    // Remove leading/trailing whitespace
    char *trimmed = malloc(strlen(expr_str) + 1);
    if (!trimmed) {
        return -1;
    }
    
    const char *start = expr_str;
    while (isspace(*start)) start++;
    
    strcpy(trimmed, start);
    char *end = trimmed + strlen(trimmed) - 1;
    while (end > trimmed && isspace(*end)) *end-- = '\0';
    
    int ret_val = -1;
    
    // Simple expression evaluation
    // Try to parse as number first
    if (parse_number(trimmed, result) == 0) {
        ret_val = 0;
        goto cleanup;
    }
    
    // Try to parse as symbol
    if (evaluate_symbol(trimmed, ctx, result) >= 0) {
        ret_val = 0;
        goto cleanup;
    }
    
    // For now, only support simple numbers and symbols
    // Real implementation would handle arithmetic operators
    
cleanup:
    free(trimmed);
    return ret_val;
}

int evaluate_expression_simple(const char *expr_str, symbol_table_t *symbols, int64_t *result) {
    expr_context_t ctx = {
        .symbols = symbols,
        .current_address = 0,
        .current_section = 0,
        .allow_forward_refs = false
    };
    
    return evaluate_expression(expr_str, &ctx, result);
}

int evaluate_expression_with_context(const char *expr_str, symbol_table_t *symbols, 
                                   size_t current_address, size_t current_section,
                                   bool allow_forward_refs, int64_t *result) {
    expr_context_t ctx = {
        .symbols = symbols,
        .current_address = current_address,
        .current_section = current_section,
        .allow_forward_refs = allow_forward_refs
    };
    
    return evaluate_expression(expr_str, &ctx, result);
}

//=============================================================================
// Expression Type Detection
//=============================================================================

expression_type_t get_expression_type(const char *expr_str) {
    if (!expr_str) {
        return EXPR_INVALID;
    }
    
    // Remove whitespace
    const char *start = expr_str;
    while (isspace(*start)) start++;
    
    if (*start == '\0') {
        return EXPR_INVALID;
    }
    
    // Check for immediate value prefix
    if (*start == '$') {
        return EXPR_IMMEDIATE;
    }
    
    // Check if it's a number
    int64_t dummy;
    if (parse_number(start, &dummy) == 0) {
        return EXPR_NUMBER;
    }
    
    // Check for arithmetic operators
    if (strchr(start, '+') || strchr(start, '-') || strchr(start, '*') || strchr(start, '/')) {
        return EXPR_ARITHMETIC;
    }
    
    // Assume it's a symbol
    return EXPR_SYMBOL;
}

bool is_forward_reference(const char *expr_str, symbol_table_t *symbols) {
    if (!expr_str || !symbols) {
        return false;
    }
    
    expression_type_t type = get_expression_type(expr_str);
    if (type != EXPR_SYMBOL) {
        return false;
    }
    
    // Remove whitespace
    const char *start = expr_str;
    while (isspace(*start)) start++;
    
    symbol_t *symbol = symbol_table_lookup(symbols, start);
    return symbol == NULL;
}

//=============================================================================
// Expression Size Calculation
//=============================================================================

size_t get_expression_size(const char *expr_str, symbol_table_t *symbols) {
    if (!expr_str) {
        return 0;
    }
    
    int64_t value;
    if (evaluate_expression_simple(expr_str, symbols, &value) != 0) {
        return 4; // Default size for unknown expressions
    }
    
    // Determine minimum size needed to represent the value
    if (value >= -128 && value <= 255) {
        return 1; // 8-bit
    } else if (value >= -32768 && value <= 65535) {
        return 2; // 16-bit
    } else if (value >= -2147483648LL && value <= 4294967295LL) {
        return 4; // 32-bit
    } else {
        return 8; // 64-bit
    }
}

//=============================================================================
// Expression String Utilities
//=============================================================================

char *normalize_expression(const char *expr_str) {
    if (!expr_str) {
        return NULL;
    }
    
    size_t len = strlen(expr_str);
    char *normalized = malloc(len + 1);
    if (!normalized) {
        return NULL;
    }
    
    size_t write_pos = 0;
    bool last_was_space = true; // Start as true to skip leading spaces
    
    for (size_t i = 0; i < len; i++) {
        char c = expr_str[i];
        
        if (isspace(c)) {
            if (!last_was_space) {
                normalized[write_pos++] = ' ';
                last_was_space = true;
            }
        } else {
            normalized[write_pos++] = c;
            last_was_space = false;
        }
    }
    
    // Remove trailing space
    if (write_pos > 0 && normalized[write_pos - 1] == ' ') {
        write_pos--;
    }
    
    normalized[write_pos] = '\0';
    return normalized;
}

bool expressions_equal(const char *expr1, const char *expr2) {
    if (!expr1 && !expr2) {
        return true;
    }
    if (!expr1 || !expr2) {
        return false;
    }
    
    char *norm1 = normalize_expression(expr1);
    char *norm2 = normalize_expression(expr2);
    
    bool equal = false;
    if (norm1 && norm2) {
        equal = strcmp(norm1, norm2) == 0;
    }
    
    free(norm1);
    free(norm2);
    return equal;
}
