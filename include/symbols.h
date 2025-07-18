#ifndef SYMBOLS_H
#define SYMBOLS_H

#include <stdint.h>
#include <stdbool.h>
#include <stddef.h>

// Symbol types
typedef enum {
    SYMBOL_LABEL,         // Code label
    SYMBOL_VARIABLE,      // Data variable
    SYMBOL_CONSTANT,      // Constant value
    SYMBOL_EXTERNAL,      // External symbol
    SYMBOL_SECTION,       // Section name
    SYMBOL_UNDEFINED      // Forward reference
} symbol_type_t;

// Symbol visibility
typedef enum {
    VISIBILITY_LOCAL,     // Local to file
    VISIBILITY_GLOBAL,    // Global visibility
    VISIBILITY_WEAK,      // Weak symbol
    VISIBILITY_HIDDEN     // Hidden from other modules
} symbol_visibility_t;

// Symbol structure
typedef struct symbol {
    char *name;                    // Symbol name
    symbol_type_t type;            // Symbol type
    symbol_visibility_t visibility; // Symbol visibility
    uint64_t value;                // Symbol value/address
    uint32_t section;              // Section ID
    uint32_t size;                 // Symbol size in bytes
    bool defined;                  // Whether symbol is defined
    
    // Relocation information
    struct {
        bool needs_relocation;     // Symbol needs relocation
        uint32_t reloc_type;       // Relocation type
        int64_t addend;            // Relocation addend
    } reloc;
    
    struct symbol *next;           // Hash table chain
} symbol_t;

// Symbol table structure
typedef struct {
    symbol_t **buckets;           // Hash table buckets
    size_t bucket_count;          // Number of buckets
    size_t symbol_count;          // Total symbols
    symbol_t *symbols;            // List of all symbols
} symbol_table_t;

// Symbol table functions
symbol_table_t *symbol_table_create(size_t initial_size);
void symbol_table_destroy(symbol_table_t *table);

// Symbol operations
symbol_t *symbol_create(const char *name, symbol_type_t type);
void symbol_destroy(symbol_t *symbol);
int symbol_table_add(symbol_table_t *table, symbol_t *symbol);
symbol_t *symbol_table_lookup(symbol_table_t *table, const char *name);
bool symbol_table_remove(symbol_table_t *table, const char *name);

// Symbol manipulation
void symbol_set_value(symbol_t *symbol, uint64_t value);
void symbol_set_section(symbol_t *symbol, uint32_t section);
void symbol_set_visibility(symbol_t *symbol, symbol_visibility_t visibility);
void symbol_mark_defined(symbol_t *symbol);
void symbol_add_relocation(symbol_t *symbol, uint32_t reloc_type, int64_t addend);

// Utility functions
uint32_t symbol_hash(const char *name);
const char *symbol_type_to_string(symbol_type_t type);
const char *symbol_visibility_to_string(symbol_visibility_t visibility);
void symbol_table_dump(symbol_table_t *table);

// Symbol iteration
typedef struct {
    symbol_table_t *table;
    size_t bucket_index;
    symbol_t *current;
} symbol_iterator_t;

symbol_iterator_t symbol_table_iterator(symbol_table_t *table);
symbol_t *symbol_iterator_next(symbol_iterator_t *iter);

// Forward reference resolution
typedef struct forward_ref {
    char *symbol_name;
    uint64_t location;            // Where the reference occurs
    uint32_t section;             // Section containing the reference
    uint32_t reloc_type;          // Type of relocation needed
    int64_t addend;               // Addend for relocation
    struct forward_ref *next;
} forward_ref_t;

// Forward reference management
forward_ref_t *forward_ref_create(const char *symbol_name, uint64_t location,
                                 uint32_t section, uint32_t reloc_type,
                                 int64_t addend);
void forward_ref_destroy(forward_ref_t *ref);
int resolve_forward_references(symbol_table_t *table, forward_ref_t *refs);

// Phase 2 Enhancement: Forward reference support  
int symbol_add_forward_reference(symbol_table_t *table, const char *symbol_name, 
                                uint64_t location);

#endif // SYMBOLS_H
