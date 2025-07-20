/*
 * DOS .COM Output Format for STAS
 * Generates DOS .COM executable files for 16-bit x86 programs
 */

#include "formats/com_format.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>

// Safe string duplication (C99 compatible)
static char *safe_strdup(const char *s) {
    if (!s) return NULL;
    size_t len = strlen(s) + 1;
    char *copy = malloc(len);
    if (copy) {
        memcpy(copy, s, len);
    }
    return copy;
}

// Forward declarations
static int com_write_file(output_context_t *ctx);
static int com_add_section(output_context_t *ctx, const char *name, 
                          uint8_t *data, size_t size, uint32_t address);
static void com_cleanup(output_context_t *ctx);

// DOS .COM format operations
static output_format_ops_t com_format_ops = {
    .name = "dos-com",
    .extension = "com",
    .write_file = com_write_file,
    .add_section = com_add_section,
    .cleanup = com_cleanup
};

output_format_ops_t *get_com_format(void) {
    return &com_format_ops;
}

//=============================================================================
// DOS .COM Format Implementation
//=============================================================================

static int com_write_file(output_context_t *ctx) {
    if (!ctx || !ctx->filename) {
        return -1;
    }
    
    FILE *output_file = fopen(ctx->filename, "wb");
    if (!output_file) {
        fprintf(stderr, "Error: Cannot create .COM file '%s': %s\n", 
                ctx->filename, strerror(errno));
        return -1;
    }
    
    // Force base address for .COM format
    uint32_t com_base = 0x100;
    size_t total_size = 0;
    uint32_t max_addr = com_base;
    
    // Calculate total size for .COM format
    for (size_t i = 0; i < ctx->section_count; i++) {
        output_section_t *section = &ctx->sections[i];
        uint32_t end_addr = section->virtual_address + section->size;
        if (end_addr > max_addr) {
            max_addr = end_addr;
        }
    }
    
    total_size = max_addr - com_base;
    
    // .COM files are limited to 65536 - 256 = 65280 bytes
    if (total_size > 65280) {
        fprintf(stderr, "Error: .COM file too large (%zu bytes, max 65280)\n", total_size);
        fclose(output_file);
        return -1;
    }
    
    if (ctx->verbose) {
        printf("DOS .COM Output:\n");
        printf("  Base address: 0x%04x\n", com_base);
        printf("  Total size: %zu bytes\n", total_size);
        printf("  Max .COM size: 65280 bytes\n");
    }
    
    // Create output buffer
    uint8_t *output_buffer = calloc(total_size, 1);
    if (!output_buffer && total_size > 0) {
        fprintf(stderr, "Error: Cannot allocate .COM output buffer\n");
        fclose(output_file);
        return -1;
    }
    
    // Copy sections to buffer (offset by COM base address)
    for (size_t i = 0; i < ctx->section_count; i++) {
        output_section_t *section = &ctx->sections[i];
        
        // Calculate offset from COM base
        if (section->virtual_address < com_base) {
            fprintf(stderr, "Error: Section '%s' address 0x%x below .COM base 0x%x\n",
                   section->name, section->virtual_address, com_base);
            free(output_buffer);
            fclose(output_file);
            return -1;
        }
        
        uint32_t offset = section->virtual_address - com_base;
        
        if (ctx->verbose) {
            printf("  Section '%s': %zu bytes at offset 0x%04x\n", 
                   section->name, section->size, offset);
        }
        
        if (section->data && section->size > 0) {
            memcpy(output_buffer + offset, section->data, section->size);
        }
    }
    
    // Write .COM binary data
    if (total_size > 0) {
        size_t written = fwrite(output_buffer, 1, total_size, output_file);
        if (written != total_size) {
            fprintf(stderr, "Error: Failed to write complete .COM data\n");
            free(output_buffer);
            fclose(output_file);
            return -1;
        }
    }
    
    free(output_buffer);
    fclose(output_file);
    
    if (ctx->verbose) {
        printf("DOS .COM file written successfully to '%s'\n", ctx->filename);
    }
    
    return 0;
}

static int com_add_section(output_context_t *ctx, const char *name, 
                          uint8_t *data, size_t size, uint32_t address) {
    if (!ctx || !name) {
        return -1;
    }
    
    // Reallocate sections array
    ctx->sections = realloc(ctx->sections, 
                           (ctx->section_count + 1) * sizeof(output_section_t));
    if (!ctx->sections) {
        return -1;
    }
    
    // Add new section
    output_section_t *section = &ctx->sections[ctx->section_count];
    section->name = safe_strdup(name);
    
    // Make a copy of the data instead of just storing the pointer
    if (data && size > 0) {
        section->data = malloc(size);
        if (!section->data) {
            free((char*)section->name);
            return -1;
        }
        memcpy(section->data, data, size);
    } else {
        section->data = NULL;
    }
    
    section->size = size;
    section->virtual_address = address;
    section->file_offset = 0; // Not used in .COM format
    section->flags = 0;
    
    ctx->section_count++;
    return 0;
}

static void com_cleanup(output_context_t *ctx) {
    if (!ctx) return;
    
    // Free section names and data
    for (size_t i = 0; i < ctx->section_count; i++) {
        free((char*)ctx->sections[i].name);
        free(ctx->sections[i].data);  // Free the copied data
    }
    
    // Free sections array
    free(ctx->sections);
    ctx->sections = NULL;
    ctx->section_count = 0;
}
