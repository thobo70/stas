/*
 * Flat Binary Output Format for STAS
 * Generates raw binary files without headers, suitable for bootloaders,
 * embedded systems, and direct execution scenarios.
 */

#include "formats/flat_binary.h"
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
static int flat_binary_write_file(output_context_t *ctx);
static int flat_binary_add_section(output_context_t *ctx, const char *name, 
                                  uint8_t *data, size_t size, uint32_t address);
static void flat_binary_cleanup(output_context_t *ctx);

// Flat binary format operations
static output_format_ops_t flat_binary_ops = {
    .name = "flat-binary",
    .extension = "bin",
    .write_file = flat_binary_write_file,
    .add_section = flat_binary_add_section,
    .cleanup = flat_binary_cleanup
};

output_format_ops_t *get_flat_binary_format(void) {
    return &flat_binary_ops;
}

//=============================================================================
// Flat Binary Format Implementation
//=============================================================================

// Binary section structure for tracking data
typedef struct {
    char *name;
    uint8_t *data;
    size_t size;
    uint32_t address;
    struct binary_section *next;
} binary_section_t;

// Context for flat binary generation
typedef struct {
    binary_section_t *sections;
    uint32_t base_address;
    size_t total_size;
} flat_binary_context_t;

static int flat_binary_write_file(output_context_t *ctx) {
    if (!ctx || !ctx->filename) {
        return -1;
    }
    
    FILE *output_file = fopen(ctx->filename, "wb");
    if (!output_file) {
        fprintf(stderr, "Error: Cannot create output file '%s': %s\n", 
                ctx->filename, strerror(errno));
        return -1;
    }
    
    // Calculate total output size
    size_t total_size = 0;
    uint32_t min_addr = 0xFFFFFFFF;
    uint32_t max_addr = 0;
    
    // Find address range
    for (size_t i = 0; i < ctx->section_count; i++) {
        output_section_t *section = &ctx->sections[i];
        if (section->virtual_address < min_addr) {
            min_addr = section->virtual_address;
        }
        uint32_t end_addr = section->virtual_address + section->size;
        if (end_addr > max_addr) {
            max_addr = end_addr;
        }
    }
    
    if (ctx->section_count > 0) {
        total_size = max_addr - min_addr;
    }
    
    if (ctx->verbose) {
        printf("Flat Binary Output:\n");
        printf("  Address range: 0x%08x - 0x%08x\n", min_addr, max_addr);
        printf("  Total size: %zu bytes\n", total_size);
    }
    
    // Create output buffer
    uint8_t *output_buffer = calloc(total_size, 1);
    if (!output_buffer && total_size > 0) {
        fprintf(stderr, "Error: Cannot allocate output buffer\n");
        fclose(output_file);
        return -1;
    }
    
    // Copy sections to buffer
    for (size_t i = 0; i < ctx->section_count; i++) {
        output_section_t *section = &ctx->sections[i];
        uint32_t offset = section->virtual_address - min_addr;
        
        if (ctx->verbose) {
            printf("  Section '%s': %zu bytes at offset 0x%08x\n", 
                   section->name, section->size, offset);
        }
        
        if (section->data && section->size > 0) {
            memcpy(output_buffer + offset, section->data, section->size);
        }
    }
    
    // Write binary data
    if (total_size > 0) {
        size_t written = fwrite(output_buffer, 1, total_size, output_file);
        if (written != total_size) {
            fprintf(stderr, "Error: Failed to write complete binary data\n");
            free(output_buffer);
            fclose(output_file);
            return -1;
        }
    }
    
    free(output_buffer);
    fclose(output_file);
    
    if (ctx->verbose) {
        printf("Flat binary written successfully to '%s'\n", ctx->filename);
    }
    
    return 0;
}

static int flat_binary_add_section(output_context_t *ctx, const char *name, 
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
    section->data = data;
    section->size = size;
    section->virtual_address = address;
    section->file_offset = 0; // Not used in flat binary
    section->flags = 0;
    
    ctx->section_count++;
    return 0;
}

static void flat_binary_cleanup(output_context_t *ctx) {
    if (!ctx) return;
    
    // Free section names
    for (size_t i = 0; i < ctx->section_count; i++) {
        free((char*)ctx->sections[i].name);
    }
    
    // Free sections array
    free(ctx->sections);
    ctx->sections = NULL;
    ctx->section_count = 0;
}
