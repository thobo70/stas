/*
 * Flat Binary Output Format for STAS
 * Generates raw binary files without headers, suitable for bootloaders,
 * embedded systems, and direct execution scenarios.
 */

#include "output_format.h"
#include "formats/elf.h"
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

// COM format specific functions
static int com_write_file(output_context_t *ctx);
static int com_add_section(output_context_t *ctx, const char *name, 
                          uint8_t *data, size_t size, uint32_t address);

// Flat binary format operations
static output_format_ops_t flat_binary_ops = {
    .name = "flat-binary",
    .extension = "bin",
    .write_file = flat_binary_write_file,
    .add_section = flat_binary_add_section,
    .cleanup = flat_binary_cleanup
};

// DOS .COM format operations
static output_format_ops_t com_format_ops = {
    .name = "dos-com",
    .extension = "com",
    .write_file = com_write_file,
    .add_section = com_add_section,
    .cleanup = flat_binary_cleanup
};

output_format_ops_t *get_flat_binary_format(void) {
    return &flat_binary_ops;
}

output_format_ops_t *get_com_format(void) {
    return &com_format_ops;
}

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
    
    if (ctx->verbose) {
        printf("Writing flat binary to '%s'\n", ctx->filename);
        printf("Base address: 0x%08X\n", ctx->base_address);
        printf("Entry point: 0x%08X\n", ctx->entry_point);
    }
    
    // Calculate total output size and minimum address
    uint32_t min_address = UINT32_MAX;
    uint32_t max_address = 0;
    
    for (size_t i = 0; i < ctx->section_count; i++) {
        output_section_t *section = &ctx->sections[i];
        if (section->virtual_address < min_address) {
            min_address = section->virtual_address;
        }
        if (section->virtual_address + section->size > max_address) {
            max_address = section->virtual_address + section->size;
        }
    }
    
    if (ctx->section_count == 0) {
        fprintf(stderr, "Warning: No sections to write\n");
        fclose(output_file);
        return 0;
    }
    
    // Use base address if specified, otherwise use minimum section address
    uint32_t output_base = (ctx->base_address != 0) ? ctx->base_address : min_address;
    size_t output_size = max_address - output_base;
    
    if (ctx->verbose) {
        printf("Output size: %zu bytes (0x%08X to 0x%08X)\n", 
               output_size, output_base, max_address);
    }
    
    // Allocate output buffer and initialize to zero
    uint8_t *output_buffer = calloc(output_size, 1);
    if (!output_buffer) {
        fprintf(stderr, "Error: Cannot allocate output buffer (%zu bytes)\n", output_size);
        fclose(output_file);
        return -1;
    }
    
    // Copy section data to output buffer
    for (size_t i = 0; i < ctx->section_count; i++) {
        output_section_t *section = &ctx->sections[i];
        
        if (section->virtual_address < output_base) {
            fprintf(stderr, "Error: Section '%s' address 0x%08X is below base address 0x%08X\n",
                    section->name, section->virtual_address, output_base);
            free(output_buffer);
            fclose(output_file);
            return -1;
        }
        
        size_t offset = section->virtual_address - output_base;
        
        if (offset + section->size > output_size) {
            fprintf(stderr, "Error: Section '%s' extends beyond output buffer\n", section->name);
            free(output_buffer);
            fclose(output_file);
            return -1;
        }
        
        if (ctx->verbose) {
            printf("Section '%s': 0x%08X + %zu bytes -> offset 0x%08zX\n",
                   section->name, section->virtual_address, section->size, offset);
        }
        
        memcpy(output_buffer + offset, section->data, section->size);
    }
    
    // Write output buffer to file
    size_t written = fwrite(output_buffer, 1, output_size, output_file);
    if (written != output_size) {
        fprintf(stderr, "Error: Failed to write complete output (%zu of %zu bytes)\n",
                written, output_size);
        free(output_buffer);
        fclose(output_file);
        return -1;
    }
    
    free(output_buffer);
    fclose(output_file);
    
    if (ctx->verbose) {
        printf("Successfully wrote %zu bytes to '%s'\n", output_size, ctx->filename);
    }
    
    return 0;
}

static int flat_binary_add_section(output_context_t *ctx, const char *name, 
                                  uint8_t *data, size_t size, uint32_t address) {
    if (!ctx || !name || !data) {
        return -1;
    }
    
    // Reallocate sections array
    output_section_t *new_sections = realloc(ctx->sections, 
                                            (ctx->section_count + 1) * sizeof(output_section_t));
    if (!new_sections) {
        return -1;
    }
    
    ctx->sections = new_sections;
    
    // Add new section
    output_section_t *section = &ctx->sections[ctx->section_count];
    section->name = safe_strdup(name);
    section->data = malloc(size);
    if (!section->data) {
        free((void*)section->name);
        return -1;
    }
    
    memcpy(section->data, data, size);
    section->size = size;
    section->virtual_address = address;
    section->file_offset = 0; // Not used in flat binary
    section->flags = 0;       // Not used in flat binary
    
    ctx->section_count++;
    
    if (ctx->verbose) {
        printf("Added section '%s': %zu bytes at 0x%08X\n", name, size, address);
    }
    
    return 0;
}

static void flat_binary_cleanup(output_context_t *ctx) {
    if (!ctx) return;
    
    for (size_t i = 0; i < ctx->section_count; i++) {
        free((void*)ctx->sections[i].name);
        free(ctx->sections[i].data);
    }
    free(ctx->sections);
    ctx->sections = NULL;
    ctx->section_count = 0;
}

// DOS .COM format implementation
static int com_write_file(output_context_t *ctx) {
    if (!ctx || !ctx->filename) {
        return -1;
    }
    
    // .COM files have specific constraints:
    // - Maximum size: 65280 bytes (64KB - 256 bytes for PSP)
    // - Load address: 0x0100 (after PSP)
    // - No relocations allowed
    // - Single segment
    
    const uint32_t COM_LOAD_ADDRESS = 0x0100;
    const size_t COM_MAX_SIZE = 65280;
    
    // Force base address for .COM format
    ctx->base_address = COM_LOAD_ADDRESS;
    
    if (ctx->verbose) {
        printf("Writing DOS .COM file to '%s'\n", ctx->filename);
        printf("Load address: 0x%04X\n", COM_LOAD_ADDRESS);
    }
    
    // Calculate total size
    uint32_t max_address = COM_LOAD_ADDRESS;
    for (size_t i = 0; i < ctx->section_count; i++) {
        output_section_t *section = &ctx->sections[i];
        uint32_t section_end = section->virtual_address + section->size;
        if (section_end > max_address) {
            max_address = section_end;
        }
    }
    
    size_t total_size = max_address - COM_LOAD_ADDRESS;
    
    if (total_size > COM_MAX_SIZE) {
        fprintf(stderr, "Error: .COM file too large (%zu bytes, maximum %zu)\n",
                total_size, COM_MAX_SIZE);
        return -1;
    }
    
    // Validate that all sections are within .COM constraints
    for (size_t i = 0; i < ctx->section_count; i++) {
        output_section_t *section = &ctx->sections[i];
        if (section->virtual_address < COM_LOAD_ADDRESS) {
            fprintf(stderr, "Error: Section '%s' address 0x%04X is below .COM load address 0x%04X\n",
                    section->name, section->virtual_address, COM_LOAD_ADDRESS);
            return -1;
        }
    }
    
    // Use flat binary writer with .COM constraints
    return flat_binary_write_file(ctx);
}

static int com_add_section(output_context_t *ctx, const char *name, 
                          uint8_t *data, size_t size, uint32_t address) {
    const uint32_t COM_LOAD_ADDRESS = 0x0100;
    const uint32_t COM_MAX_ADDRESS = 0x10000; // 64KB segment limit
    
    // Validate .COM constraints
    if (address < COM_LOAD_ADDRESS) {
        fprintf(stderr, "Error: Section '%s' address 0x%04X is below .COM load address 0x%04X\n",
                name, address, COM_LOAD_ADDRESS);
        return -1;
    }
    
    if (address + size > COM_MAX_ADDRESS) {
        fprintf(stderr, "Error: Section '%s' extends beyond 64KB segment limit\n", name);
        return -1;
    }
    
    return flat_binary_add_section(ctx, name, data, size, address);
}

// General output format interface implementation
int output_init(void) {
    return 0;
}

void output_cleanup(void) {
    // Global cleanup if needed
}

output_format_ops_t *get_output_format(output_format_t format) {
    switch (format) {
        case FORMAT_FLAT_BIN:
            return get_flat_binary_format();
        case FORMAT_COM:
            return get_com_format();
        case FORMAT_ELF32:
            return get_elf32_format();
        case FORMAT_ELF64:
            return get_elf64_format();
        case FORMAT_HEX:
        case FORMAT_SREC:
        default:
            return NULL; // Not implemented yet
    }
}

int write_output_file(output_context_t *ctx) {
    if (!ctx) return -1;
    
    output_format_ops_t *ops = get_output_format(ctx->format);
    if (!ops || !ops->write_file) {
        return -1;
    }
    
    return ops->write_file(ctx);
}
