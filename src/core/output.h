#ifndef OUTPUT_H
#define OUTPUT_H

#include "parser.h"
#include "symbols.h"

// Output formats
typedef enum {
    OUTPUT_ELF,
    OUTPUT_BINARY,
    OUTPUT_LISTING
} output_format_t;

// Output generation functions
int generate_output(const char *filename, output_format_t format, 
                   ast_node_t *ast, symbol_table_t *symbols);
int generate_elf_object(const char *filename, ast_node_t *ast, symbol_table_t *symbols);
int generate_binary_output(const char *filename, ast_node_t *ast, symbol_table_t *symbols);
int generate_listing_file(const char *filename, ast_node_t *ast);

#endif // OUTPUT_H
