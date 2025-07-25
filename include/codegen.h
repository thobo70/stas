#ifndef CODEGEN_H
#define CODEGEN_H

#include "arch_interface.h"
#include "parser.h"
#include "output_format.h"
#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>

// Code generation context
typedef struct {
    arch_ops_t *arch;               // Architecture operations
    output_context_t *output;       // Output context
    
    uint8_t *code_buffer;           // Generated machine code
    size_t code_size;               // Current size of generated code
    size_t code_capacity;           // Capacity of code buffer
    size_t total_code_size;         // Total bytes generated across all sections
    
    uint32_t current_address;       // Current address for code generation
    const char *current_section;    // Current section name
    
    bool verbose;                   // Verbose output
} codegen_ctx_t;

// Code generation functions
codegen_ctx_t *codegen_create(arch_ops_t *arch, output_context_t *output);
void codegen_destroy(codegen_ctx_t *ctx);
int codegen_generate(codegen_ctx_t *ctx, ast_node_t *ast);

#endif // CODEGEN_H
