#ifndef EXPRESSIONS_H
#define EXPRESSIONS_H

#include <stdint.h>
#include <stdbool.h>
#include <stddef.h>
#include "symbols.h"

// Expression types
typedef enum {
    EXPR_INVALID,
    EXPR_NUMBER,
    EXPR_SYMBOL,
    EXPR_IMMEDIATE,
    EXPR_ARITHMETIC
} expression_type_t;

// Expression evaluation functions
int evaluate_expression_simple(const char *expr_str, symbol_table_t *symbols, int64_t *result);
int evaluate_expression_with_context(const char *expr_str, symbol_table_t *symbols, 
                                   size_t current_address, size_t current_section,
                                   bool allow_forward_refs, int64_t *result);

// Expression analysis
expression_type_t get_expression_type(const char *expr_str);
bool is_forward_reference(const char *expr_str, symbol_table_t *symbols);
size_t get_expression_size(const char *expr_str, symbol_table_t *symbols);

// Expression utilities
char *normalize_expression(const char *expr_str);
bool expressions_equal(const char *expr1, const char *expr2);

#endif // EXPRESSIONS_H
