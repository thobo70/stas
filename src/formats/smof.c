/*
 * SMOF (STIX Minimal Object Format) Implementation
 * Based on specification: https://github.com/thobo70/stld/blob/568419bdb44e14760335c018abae457fd835e7d3/stix_minimal_object_format.md
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <unistd.h>
#include <stdint.h>
#include <stddef.h>
#include "formats/smof.h"
#include "../core/output_format.h"

// STAS Original SMOF implementation - no checksums
static size_t get_string_table_size(smof_context_t *ctx) {
    if (!ctx->string_table) {
        return 1; // Just null terminator
    }
    
    // Calculate actual string table size by scanning for the end
    size_t current_size = 1; // Start with null string at offset 0
    
    // Find actual current size by scanning the string table
    for (size_t i = 1; i < ctx->string_table_capacity; i++) {
        if (ctx->string_table[i] == '\0') {
            current_size = i + 1;
            // Check if this is the end (double null or end of capacity)
            if (i + 1 >= ctx->string_table_capacity || ctx->string_table[i + 1] == '\0') {
                break; // Found the end
            }
        }
    }
    
    return current_size;
}

// Forward declarations for format operations
static int smof_write_file_impl(output_context_t *ctx);
static int smof_add_section_impl(output_context_t *ctx, const char *name, 
                                uint8_t *data, size_t size, uint32_t address);
static int smof_add_symbol_impl(output_context_t *ctx, const char *name, uint32_t value,
                               uint32_t size, uint8_t type, uint8_t binding);
static void smof_cleanup_impl(output_context_t *ctx);

// Format operation structure
static output_format_ops_t smof_ops = {
    .name = "smof",
    .extension = ".smof",
    .write_file = smof_write_file_impl,
    .add_section = smof_add_section_impl,
    .add_symbol = smof_add_symbol_impl,
    .cleanup = smof_cleanup_impl
};

// Export format getter
output_format_ops_t *get_smof_format(void) {
    return &smof_ops;
}

//=============================================================================
// String Table Management
//=============================================================================

uint32_t smof_add_string(smof_context_t *ctx, const char *str) {
    if (!str || !*str) {
        return 0; // Empty string is at offset 0
    }
    
    // Calculate current string table size
    size_t current_size = 1; // Start with null string at offset 0
    if (ctx->string_table) {
        const char *current = ctx->string_table + 1; // Skip null string at offset 0
        uint32_t offset = 1;
        
        while (offset < current_size && ctx->string_table[offset] != '\0') {
            size_t len = strlen(current);
            if (strcmp(current, str) == 0) {
                return offset; // String already exists
            }
            len++; // Include null terminator
            current += len;
            offset += len;
            current_size = offset;
        }
        
        // Find actual current size by scanning the string table
        current_size = 1;
        for (size_t i = 1; i < ctx->string_table_capacity; i++) {
            if (ctx->string_table[i] == '\0') {
                current_size = i + 1;
                // Check if this is the end or if there's another string
                if (i + 1 < ctx->string_table_capacity && ctx->string_table[i + 1] == '\0') {
                    break; // Found the end
                }
            }
        }
    }
    
    // Add new string
    size_t len = strlen(str) + 1; // Include null terminator
    size_t needed = current_size + len;
    
    if (needed > ctx->string_table_capacity) {
        size_t new_capacity = ctx->string_table_capacity == 0 ? 256 : ctx->string_table_capacity * 2;
        while (new_capacity < needed) {
            new_capacity *= 2;
        }
        
        char *new_table = realloc(ctx->string_table, new_capacity);
        if (!new_table) {
            return 0;
        }
        
        ctx->string_table = new_table;
        ctx->string_table_capacity = new_capacity;
    }
    
    uint32_t offset = current_size;
    strcpy(ctx->string_table + offset, str);
    
    return offset;
}

//=============================================================================
// Context Management
//=============================================================================

int smof_init_context(smof_context_t *ctx) {
    memset(ctx, 0, sizeof(smof_context_t));
    
    // Detect endianness
    uint16_t endian_test = 0x0001;
    bool is_little_endian = (*(uint8_t*)&endian_test) == 0x01;
    
    // Initialize header with STLD-compatible values
    ctx->header.magic = SMOF_MAGIC;
    ctx->header.version = SMOF_VERSION_CURRENT;
    ctx->header.flags = SMOF_FLAG_EXECUTABLE;
    
    // Add endianness flag for STLD compatibility
    if (is_little_endian) {
        ctx->header.flags |= SMOF_FLAG_LITTLE_ENDIAN;
    } else {
        ctx->header.flags |= SMOF_FLAG_BIG_ENDIAN;
    }
    
    ctx->header.entry_point = 0;
    ctx->header.section_count = 0;
    ctx->header.symbol_count = 0;
    ctx->header.section_table_offset = 0;
    ctx->header.string_table_offset = 0;
    ctx->header.string_table_size = 0;
    ctx->header.reloc_table_offset = 0;
    ctx->header.reloc_count = 0;
    ctx->header.import_count = 0;
    
    // Initialize string table with null string at offset 0
    ctx->string_table_capacity = 256;
    ctx->string_table = malloc(ctx->string_table_capacity);
    if (!ctx->string_table) {
        return -1;
    }
    ctx->string_table[0] = '\0';
    
    return 0;
}

void smof_cleanup_context(smof_context_t *ctx) {
    if (!ctx) return;
    
    free(ctx->sections);
    free(ctx->symbols);
    free(ctx->relocations);
    free(ctx->imports);
    free(ctx->string_table);
    
    memset(ctx, 0, sizeof(smof_context_t));
}

//=============================================================================
// Section Management
//=============================================================================

int smof_add_section(smof_context_t *ctx, const char *name, uint32_t virtual_addr,
                     uint32_t size, uint32_t file_offset, uint16_t flags, uint8_t alignment) {
    if (!ctx || !name) return -1;
    
    // Expand sections array if needed
    if (ctx->header.section_count >= ctx->sections_capacity) {
        size_t new_capacity = ctx->sections_capacity == 0 ? 8 : ctx->sections_capacity * 2;
        smof_section_t *new_sections = realloc(ctx->sections, 
                                              new_capacity * sizeof(smof_section_t));
        if (!new_sections) {
            return -1;
        }
        ctx->sections = new_sections;
        ctx->sections_capacity = new_capacity;
    }
    
    smof_section_t *section = &ctx->sections[ctx->header.section_count];
    
    section->name_offset = smof_add_string(ctx, name);
    if (section->name_offset == 0 && *name != '\0') {
        return -1; // Failed to add string
    }
    
    section->virtual_addr = virtual_addr;
    section->size = size;
    section->file_offset = file_offset;
    section->flags = flags | SMOF_SECT_READABLE; // Always readable
    section->alignment = alignment;
    section->reserved = 0;
    
    ctx->header.section_count++;
    return ctx->header.section_count - 1; // Return section index
}

//=============================================================================
// Symbol Management
//=============================================================================

int smof_add_symbol(smof_context_t *ctx, const char *name, uint32_t value,
                    uint32_t size, uint16_t section_index, uint8_t type, uint8_t binding) {
    if (!ctx || !name) return -1;
    
    // Expand symbols array if needed
    if (ctx->header.symbol_count >= ctx->symbols_capacity) {
        size_t new_capacity = ctx->symbols_capacity == 0 ? 16 : ctx->symbols_capacity * 2;
        smof_symbol_t *new_symbols = realloc(ctx->symbols, 
                                            new_capacity * sizeof(smof_symbol_t));
        if (!new_symbols) {
            return -1;
        }
        ctx->symbols = new_symbols;
        ctx->symbols_capacity = new_capacity;
    }
    
    smof_symbol_t *symbol = &ctx->symbols[ctx->header.symbol_count];
    
    symbol->name_offset = smof_add_string(ctx, name);
    if (symbol->name_offset == 0 && *name != '\0') {
        return -1; // Failed to add string
    }
    
    symbol->value = value;
    symbol->size = size;
    symbol->section_index = section_index;
    symbol->type = type;
    symbol->binding = binding;
    
    ctx->header.symbol_count++;
    return ctx->header.symbol_count - 1; // Return symbol index
}

//=============================================================================
// File Writing
//=============================================================================

int smof_write_file(smof_context_t *ctx, const char *filename, bool verbose) {
    return smof_write_file_with_data(ctx, filename, verbose, NULL, 0);
}

int smof_write_file_with_data(smof_context_t *ctx, const char *filename, bool verbose,
                             output_section_t *sections, size_t section_count) {
    if (!ctx || !filename) return -1;
    
    FILE *file = fopen(filename, "wb");
    if (!file) {
        if (verbose) {
            fprintf(stderr, "Error: Cannot create SMOF file '%s': %s\n", 
                   filename, strerror(errno));
        }
        return -1;
    }
    
    // Calculate offsets
    uint32_t current_offset = sizeof(smof_header_t);
    
    // Section table offset
    ctx->header.section_table_offset = current_offset;
    current_offset += ctx->header.section_count * sizeof(smof_section_t);
    
    // Symbol table comes right after sections (no separate offset field)
    if (ctx->header.symbol_count > 0) {
        current_offset += ctx->header.symbol_count * sizeof(smof_symbol_t);
    }
    
    // String table offset
    ctx->header.string_table_offset = current_offset;
    ctx->header.string_table_size = get_string_table_size(ctx);
    current_offset += ctx->header.string_table_size;
    
    // Relocation table offset (if any)
    if (ctx->header.reloc_count > 0) {
        ctx->header.reloc_table_offset = current_offset;
        current_offset += ctx->header.reloc_count * sizeof(smof_relocation_t);
    }
    
    // Calculate section data offsets and update section headers
    if (sections && section_count > 0) {
        uint32_t section_data_offset = current_offset;
        for (size_t i = 0; i < section_count && i < ctx->header.section_count; i++) {
            if (sections[i].size > 0) {
                ctx->sections[i].file_offset = section_data_offset;
                section_data_offset += sections[i].size;
            }
        }
    }
    
    // Write header (no checksum calculation for STAS format)
    if (fwrite(&ctx->header, sizeof(smof_header_t), 1, file) != 1) {
        if (verbose) {
            fprintf(stderr, "Error: Failed to write SMOF header\n");
        }
        fclose(file);
        return -1;
    }
    
    // Write section table
    if (ctx->header.section_count > 0) {
        if (fwrite(ctx->sections, sizeof(smof_section_t), 
                  ctx->header.section_count, file) != ctx->header.section_count) {
            if (verbose) {
                fprintf(stderr, "Error: Failed to write SMOF section table\n");
            }
            fclose(file);
            return -1;
        }
    }
    
    // Write symbol table
    if (ctx->header.symbol_count > 0 && ctx->symbols) {
        if (fwrite(ctx->symbols, sizeof(smof_symbol_t),
                  ctx->header.symbol_count, file) != ctx->header.symbol_count) {
            if (verbose) {
                fprintf(stderr, "Error: Failed to write SMOF symbol table\n");
            }
            fclose(file);
            return -1;
        }
    }
    
    // Write string table
    if (ctx->header.string_table_size > 0) {
        if (fwrite(ctx->string_table, 1, ctx->header.string_table_size, file) != 
           ctx->header.string_table_size) {
            if (verbose) {
                fprintf(stderr, "Error: Failed to write SMOF string table\n");
            }
            fclose(file);
            return -1;
        }
    }
    
    // Write relocation table (if any)
    if (ctx->header.reloc_count > 0 && ctx->relocations) {
        if (fwrite(ctx->relocations, sizeof(smof_relocation_t),
                  ctx->header.reloc_count, file) != ctx->header.reloc_count) {
            if (verbose) {
                fprintf(stderr, "Error: Failed to write SMOF relocation table\n");
            }
            fclose(file);
            return -1;
        }
    }
    
    // Write section data
    if (sections && section_count > 0) {
        for (size_t i = 0; i < section_count && i < ctx->header.section_count; i++) {
            if (sections[i].size > 0 && sections[i].data) {
                if (fwrite(sections[i].data, 1, sections[i].size, file) != sections[i].size) {
                    if (verbose) {
                        fprintf(stderr, "Error: Failed to write section data for %s\n", 
                               sections[i].name);
                    }
                    fclose(file);
                    return -1;
                }
                
                if (verbose) {
                    printf("Wrote section '%s' data: %zu bytes at offset 0x%08X\n",
                           sections[i].name, sections[i].size, ctx->sections[i].file_offset);
                }
            }
        }
    }
    
    if (verbose) {
        printf("SMOF file written: %s\n", filename);
        printf("  Header size: %zu bytes\n", sizeof(smof_header_t));
        printf("  Sections: %u\n", ctx->header.section_count);
        printf("  Symbols: %u\n", ctx->header.symbol_count);
        printf("  String table size: %u bytes\n", ctx->header.string_table_size);
        printf("  Total file size: %ld bytes\n", ftell(file));
    }
    
    fclose(file);
    return 0;
}

//=============================================================================
// Format Interface Implementation
//=============================================================================

static int smof_write_file_impl(output_context_t *ctx) {
    if (!ctx || !ctx->filename) return -1;
    
    smof_context_t smof_ctx;
    if (smof_init_context(&smof_ctx) != 0) {
        return -1;
    }
    
    // Set entry point
    smof_ctx.header.entry_point = ctx->entry_point;
    
    // Add sections
    for (size_t i = 0; i < ctx->section_count; i++) {
        output_section_t *section = &ctx->sections[i];
        
        // Determine section flags
        uint16_t flags = SMOF_SECT_LOADABLE;
        
        if (section->flags & 0x1) flags |= SMOF_SECT_EXECUTABLE; // Executable
        if (section->flags & 0x2) flags |= SMOF_SECT_WRITABLE;   // Writable
        
        // Special handling for .bss section (zero-filled)
        if (strcmp(section->name, ".bss") == 0) {
            flags |= SMOF_SECT_ZERO_FILL;
            
            // Add .bss section with no file data
            if (smof_add_section(&smof_ctx, section->name, section->virtual_address,
                                section->size, 0, flags, 4) < 0) {
                smof_cleanup_context(&smof_ctx);
                return -1;
            }
        } else {
            // Regular section with data
            uint32_t file_offset = 0; // Will be calculated during file writing
            
            if (smof_add_section(&smof_ctx, section->name, section->virtual_address,
                                section->size, file_offset, flags, 4) < 0) {
                smof_cleanup_context(&smof_ctx);
                return -1;
            }
        }
    }
    
    // Add symbols
    for (size_t i = 0; i < ctx->symbol_count; i++) {
        output_symbol_t *symbol = &ctx->symbols[i];
        
        // Map to SMOF section index (0 = no section for now)
        uint16_t section_index = 0;
        
        if (smof_add_symbol(&smof_ctx, symbol->name, symbol->value,
                           symbol->size, section_index, symbol->type, symbol->binding) < 0) {
            smof_cleanup_context(&smof_ctx);
            return -1;
        }
    }
    
    // Calculate section data offsets before writing
    uint32_t section_data_offset = sizeof(smof_header_t) + 
                                   smof_ctx.header.section_count * sizeof(smof_section_t) +
                                   smof_ctx.header.symbol_count * sizeof(smof_symbol_t) +
                                   smof_ctx.header.string_table_size +
                                   smof_ctx.header.reloc_count * sizeof(smof_relocation_t);
    
    for (size_t i = 0; i < ctx->section_count; i++) {
        if (ctx->sections[i].size > 0) {
            smof_ctx.sections[i].file_offset = section_data_offset;
            section_data_offset += ctx->sections[i].size;
        }
    }
    
    // Write the file with section data
    int result = smof_write_file_with_data(&smof_ctx, ctx->filename, ctx->verbose, 
                                          ctx->sections, ctx->section_count);
    
    smof_cleanup_context(&smof_ctx);
    return result;
}

static int smof_add_section_impl(output_context_t *ctx, const char *name, 
                                uint8_t *data, size_t size, uint32_t address) {
    if (!ctx || !name || !data) {
        return -1;
    }
    
    // Expand sections array if needed
    size_t new_count = ctx->section_count + 1;
    output_section_t *new_sections = realloc(ctx->sections, new_count * sizeof(output_section_t));
    if (!new_sections) {
        return -1;
    }
    
    ctx->sections = new_sections;
    
    // Allocate memory for section name (will be freed in cleanup)
    char *section_name = malloc(strlen(name) + 1);
    if (!section_name) {
        return -1;
    }
    strcpy(section_name, name);
    
    // Allocate memory for section data (will be freed in cleanup)
    uint8_t *section_data = malloc(size);
    if (!section_data) {
        free(section_name);
        return -1;
    }
    memcpy(section_data, data, size);
    
    // Store section
    output_section_t *section = &ctx->sections[ctx->section_count];
    section->name = section_name;
    section->data = section_data;
    section->size = size;
    section->virtual_address = address;
    section->file_offset = 0; // Will be calculated during writing
    section->flags = 0; // Will be set based on section type
    
    ctx->section_count++;
    return 0;
}

static int smof_add_symbol_impl(output_context_t *ctx, const char *name, uint32_t value,
                               uint32_t size, uint8_t type, uint8_t binding) {
    if (!ctx || !name) {
        return -1;
    }
    
    // Expand symbols array if needed
    size_t new_count = ctx->symbol_count + 1;
    output_symbol_t *new_symbols = realloc(ctx->symbols, new_count * sizeof(output_symbol_t));
    if (!new_symbols) {
        return -1;
    }
    
    ctx->symbols = new_symbols;
    
    // Allocate memory for symbol name (will be freed in cleanup)
    char *symbol_name = malloc(strlen(name) + 1);
    if (!symbol_name) {
        return -1;
    }
    strcpy(symbol_name, name);
    
    // Store symbol
    output_symbol_t *symbol = &ctx->symbols[ctx->symbol_count];
    symbol->name = symbol_name;
    symbol->value = value;
    symbol->size = size;
    symbol->type = type;
    symbol->binding = binding;
    
    ctx->symbol_count++;
    return 0;
}

static void smof_cleanup_impl(output_context_t *ctx) {
    if (!ctx) return;
    
    // Free section names and data that were allocated
    for (size_t i = 0; i < ctx->section_count; i++) {
        if (ctx->sections[i].name) {
            free((void*)ctx->sections[i].name);
        }
        if (ctx->sections[i].data) {
            free(ctx->sections[i].data);
        }
    }
    
    // Free sections array
    if (ctx->sections) {
        free(ctx->sections);
        ctx->sections = NULL;
        ctx->section_count = 0;
    }
    
    // Free symbol names that were allocated
    for (size_t i = 0; i < ctx->symbol_count; i++) {
        if (ctx->symbols[i].name) {
            free((void*)ctx->symbols[i].name);
        }
    }
    
    // Free symbols array
    if (ctx->symbols) {
        free(ctx->symbols);
        ctx->symbols = NULL;
        ctx->symbol_count = 0;
    }
}

//=============================================================================
// Validation Functions
//=============================================================================

int smof_validate_header(const smof_header_t *header) {
    if (!header) return 0;
    
    // Magic number check
    if (header->magic != SMOF_MAGIC) return 0;
    
    // Version check
    if (header->version > SMOF_VERSION_CURRENT) return 0;
    
    // Sanity checks
    if (header->section_count > 256) return 0; // Reasonable limit
    if (header->symbol_count > 32767) return 0; // uint16_t reasonable limit
    // Remove obsolete field validation
    // if (header->string_table_size > 1048576) return 0; // 1MB limit
    
    // Offset validation
    if (header->section_table_offset < sizeof(smof_header_t)) return 0;
    if (header->string_table_offset < sizeof(smof_header_t)) return 0;
    
    return 1; // Valid
}

int smof_validate_section(const smof_section_t *section) {
    if (!section) return 0;
    
    // Basic sanity checks
    if (section->size > 0x10000000) return 0; // 256MB limit
    if (section->alignment > 64) return 0; // Reasonable alignment limit
    
    // Flag validation
    if (!(section->flags & SMOF_SECT_READABLE)) return 0; // Must be readable
    
    return 1; // Valid
}
