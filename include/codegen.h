#ifndef CODEGEN_H
#define CODEGEN_H

#include "arch_interface.h"
#include "parser.h"
#include "output_format.h"
#include "symbols.h"
#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>

// Relocation entry for symbol resolution
typedef struct relocation {
    const char *symbol_name;        // Target symbol name
    uint32_t offset;                // Offset in code buffer to patch
    uint32_t instruction_address;   // Address of instruction containing relocation
    uint32_t reloc_type;            // Type of relocation (e.g., REL8, REL32)
    int64_t addend;                 // Additional offset to add
    struct relocation *next;        // Next relocation in list
} relocation_t;

// Relocation types for jump instructions
#define RELOC_REL8     1  // 8-bit relative displacement
#define RELOC_REL32    2  // 32-bit relative displacement

// Code generation context
typedef struct {
    arch_ops_t *arch;               // Architecture operations
    output_context_t *output;       // Output context
    symbol_table_t *symbols;        // Symbol table
    
    uint8_t *code_buffer;           // Generated machine code
    size_t code_size;               // Current size of generated code
    size_t code_capacity;           // Capacity of code buffer
    size_t total_code_size;         // Total bytes generated across all sections
    
    uint32_t current_address;       // Current address for code generation
    const char *current_section;    // Current section name
    
    relocation_t *relocations;      // List of pending relocations
    
    bool verbose;                   // Verbose output
} codegen_ctx_t;

// Code generation functions
codegen_ctx_t *codegen_create(arch_ops_t *arch, output_context_t *output, symbol_table_t *symbols);
void codegen_destroy(codegen_ctx_t *ctx);
int codegen_generate(codegen_ctx_t *ctx, ast_node_t *ast);

// Relocation functions
int codegen_add_relocation(codegen_ctx_t *ctx, const char *symbol_name, 
                          uint32_t offset, uint32_t reloc_type, int64_t addend);
int codegen_resolve_relocations(codegen_ctx_t *ctx);

#endif // CODEGEN_H
