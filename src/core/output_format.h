#ifndef OUTPUT_FORMAT_H
#define OUTPUT_FORMAT_H

#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>

// Output format types
typedef enum {
    FORMAT_ELF32,     // ELF 32-bit object file
    FORMAT_ELF64,     // ELF 64-bit object file
    FORMAT_FLAT_BIN,  // Flat binary (no headers, direct execution)
    FORMAT_COM,       // DOS .COM format (16-bit flat binary with ORG 0x100)
    FORMAT_HEX,       // Intel HEX format
    FORMAT_SREC,      // Motorola S-record format
    FORMAT_SMOF       // STIX Minimal Object Format
} output_format_t;

// Section information for output
typedef struct {
    const char *name;
    uint8_t *data;
    size_t size;
    uint32_t virtual_address;
    uint32_t file_offset;
    uint32_t flags;
} output_section_t;

// Symbol information for output
typedef struct {
    const char *name;
    uint32_t value;
    uint32_t size;
    uint8_t type;
    uint8_t binding;
} output_symbol_t;

// Relocation information for output
typedef struct {
    uint32_t offset;           // Offset within section
    const char *symbol_name;   // Symbol to reference  
    uint8_t type;              // Relocation type
    uint8_t section_index;     // Section containing the location to patch
} output_relocation_t;

// Output context
typedef struct {
    output_format_t format;
    const char *filename;
    output_section_t *sections;
    size_t section_count;
    output_symbol_t *symbols;
    size_t symbol_count;
    output_relocation_t *relocations;
    size_t relocation_count;
    uint32_t entry_point;
    uint32_t base_address;
    bool verbose;
} output_context_t;

// Output format operations
typedef struct {
    const char *name;
    const char *extension;
    int (*write_file)(output_context_t *ctx);
    int (*add_section)(output_context_t *ctx, const char *name, 
                      uint8_t *data, size_t size, uint32_t address);
    int (*add_symbol)(output_context_t *ctx, const char *name, uint32_t value,
                     uint32_t size, uint8_t type, uint8_t binding);
    int (*add_relocation)(output_context_t *ctx, uint32_t offset, 
                         const char *symbol_name, uint8_t type, uint8_t section_index);
    void (*cleanup)(output_context_t *ctx);
} output_format_ops_t;

// Function declarations
int output_init(void);
void output_cleanup(void);
output_format_ops_t *get_output_format(output_format_t format);
int write_output_file(output_context_t *ctx);

// Specific format implementations
output_format_ops_t *get_flat_binary_format(void);
output_format_ops_t *get_com_format(void);
output_format_ops_t *get_elf32_format(void);
output_format_ops_t *get_elf64_format(void);
output_format_ops_t *get_intel_hex_format(void);
output_format_ops_t *get_motorola_srec_format(void);
output_format_ops_t *get_smof_format(void);

#endif // OUTPUT_FORMAT_H
