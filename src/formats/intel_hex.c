/*
 * Intel HEX Output Format for STAS
 * Generates Intel HEX format files for embedded programming and ROM programming
 */

#include "formats/intel_hex.h"
#include "utils.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>

// Intel HEX record types
#define INTEL_HEX_TYPE_DATA         0x00
#define INTEL_HEX_TYPE_EOF          0x01
#define INTEL_HEX_TYPE_EXT_SEG_ADDR 0x02
#define INTEL_HEX_TYPE_START_SEG    0x03
#define INTEL_HEX_TYPE_EXT_LIN_ADDR 0x04
#define INTEL_HEX_TYPE_START_LIN    0x05

// Maximum data bytes per record (typically 16)
#define INTEL_HEX_MAX_DATA_BYTES    16

// Forward declarations
static int intel_hex_write_file(output_context_t *ctx);
static int intel_hex_add_section(output_context_t *ctx, const char *name, 
                                uint8_t *data, size_t size, uint32_t address);
static void intel_hex_cleanup(output_context_t *ctx);
static uint8_t intel_hex_checksum(const uint8_t *data, size_t length);
static int intel_hex_write_record(FILE *file, uint8_t type, uint16_t address, 
                                 const uint8_t *data, uint8_t data_length);

// Intel HEX format operations
static output_format_ops_t intel_hex_ops = {
    .name = "intel-hex",
    .extension = "hex",
    .write_file = intel_hex_write_file,
    .add_section = intel_hex_add_section,
    .cleanup = intel_hex_cleanup
};

output_format_ops_t *get_intel_hex_format(void) {
    return &intel_hex_ops;
}

//=============================================================================
// Intel HEX Format Implementation
//=============================================================================

static uint8_t intel_hex_checksum(const uint8_t *data, size_t length) {
    uint8_t sum = 0;
    for (size_t i = 0; i < length; i++) {
        sum += data[i];
    }
    return (uint8_t)(0x100 - sum);
}

static int intel_hex_write_record(FILE *file, uint8_t type, uint16_t address, 
                                 const uint8_t *data, uint8_t data_length) {
    if (!file) return -1;
    
    // Write record start marker
    fprintf(file, ":");
    
    // Write byte count
    fprintf(file, "%02X", data_length);
    
    // Write address
    fprintf(file, "%04X", address);
    
    // Write record type
    fprintf(file, "%02X", type);
    
    // Write data bytes
    for (uint8_t i = 0; i < data_length; i++) {
        fprintf(file, "%02X", data[i]);
    }
    
    // Calculate and write checksum
    uint8_t checksum_data[4 + data_length];
    checksum_data[0] = data_length;
    checksum_data[1] = (address >> 8) & 0xFF;
    checksum_data[2] = address & 0xFF;
    checksum_data[3] = type;
    for (uint8_t i = 0; i < data_length; i++) {
        checksum_data[4 + i] = data[i];
    }
    
    uint8_t checksum = intel_hex_checksum(checksum_data, 4 + data_length);
    fprintf(file, "%02X", checksum);
    
    // Write line terminator
    fprintf(file, "\n");
    
    return 0;
}

static int intel_hex_write_file(output_context_t *ctx) {
    if (!ctx || !ctx->filename) {
        return -1;
    }
    
    FILE *output_file = fopen(ctx->filename, "w");
    if (!output_file) {
        fprintf(stderr, "Error: Cannot create output file '%s': %s\n", 
                ctx->filename, strerror(errno));
        return -1;
    }
    
    if (ctx->verbose) {
        printf("Intel HEX Output:\n");
        printf("  File: %s\n", ctx->filename);
        printf("  Sections: %zu\n", ctx->section_count);
    }
    
    // Write all sections as data records
    for (size_t i = 0; i < ctx->section_count; i++) {
        output_section_t *section = &ctx->sections[i];
        uint32_t address = section->virtual_address;
        uint8_t *data = section->data;
        size_t remaining = section->size;
        
        if (ctx->verbose) {
            printf("  Section '%s': 0x%08x, %zu bytes\n", 
                   section->name, address, section->size);
        }
        
        // Handle extended address if needed (> 16-bit address space)
        if (address > 0xFFFF) {
            uint16_t ext_addr = (address >> 16) & 0xFFFF;
            uint8_t ext_data[2] = {(ext_addr >> 8) & 0xFF, ext_addr & 0xFF};
            intel_hex_write_record(output_file, INTEL_HEX_TYPE_EXT_LIN_ADDR, 0, ext_data, 2);
        }
        
        // Write data in chunks
        while (remaining > 0) {
            uint8_t chunk_size = (remaining > INTEL_HEX_MAX_DATA_BYTES) ? 
                                INTEL_HEX_MAX_DATA_BYTES : (uint8_t)remaining;
            
            intel_hex_write_record(output_file, INTEL_HEX_TYPE_DATA, 
                                 (uint16_t)(address & 0xFFFF), data, chunk_size);
            
            data += chunk_size;
            address += chunk_size;
            remaining -= chunk_size;
        }
    }
    
    // Write end-of-file record
    intel_hex_write_record(output_file, INTEL_HEX_TYPE_EOF, 0, NULL, 0);
    
    fclose(output_file);
    
    if (ctx->verbose) {
        printf("Intel HEX file written successfully\n");
    }
    
    return 0;
}

static int intel_hex_add_section(output_context_t *ctx, const char *name, 
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
    section->file_offset = 0; // Not used in Intel HEX
    section->flags = 0;
    
    ctx->section_count++;
    return 0;
}

static void intel_hex_cleanup(output_context_t *ctx) {
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
