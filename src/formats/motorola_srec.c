/*
 * Motorola S-Record Output Format for STAS
 * Generates Motorola S-Record format files for embedded programming
 */

#include "formats/motorola_srec.h"
#include "utils.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>

// Motorola S-Record types
#define SREC_TYPE_HEADER        0   // S0 - Header record
#define SREC_TYPE_DATA_16       1   // S1 - Data record with 16-bit address
#define SREC_TYPE_DATA_24       2   // S2 - Data record with 24-bit address  
#define SREC_TYPE_DATA_32       3   // S3 - Data record with 32-bit address
#define SREC_TYPE_COUNT_16      5   // S5 - Record count with 16-bit count
#define SREC_TYPE_COUNT_24      6   // S6 - Record count with 24-bit count
#define SREC_TYPE_START_32      7   // S7 - Start address with 32-bit address
#define SREC_TYPE_START_24      8   // S8 - Start address with 24-bit address
#define SREC_TYPE_START_16      9   // S9 - Start address with 16-bit address

// Maximum data bytes per record
#define SREC_MAX_DATA_BYTES     32

// Forward declarations
static int srec_write_file(output_context_t *ctx);
static int srec_add_section(output_context_t *ctx, const char *name, 
                           uint8_t *data, size_t size, uint32_t address);
static void srec_cleanup(output_context_t *ctx);
static uint8_t srec_checksum(const uint8_t *data, size_t length);
static int srec_write_record(FILE *file, uint8_t type, uint32_t address, 
                            const uint8_t *data, uint8_t data_length);
static uint8_t srec_get_data_type(uint32_t address);
static uint8_t srec_get_start_type(uint32_t address);

// Motorola S-Record format operations
static output_format_ops_t srec_ops = {
    .name = "motorola-srec",
    .extension = "s19",
    .write_file = srec_write_file,
    .add_section = srec_add_section,
    .cleanup = srec_cleanup
};

output_format_ops_t *get_motorola_srec_format(void) {
    return &srec_ops;
}

//=============================================================================
// Motorola S-Record Format Implementation
//=============================================================================

static uint8_t srec_checksum(const uint8_t *data, size_t length) {
    uint8_t sum = 0;
    for (size_t i = 0; i < length; i++) {
        sum += data[i];
    }
    return (uint8_t)(0xFF - sum);
}

static uint8_t srec_get_data_type(uint32_t address) {
    if (address <= 0xFFFF) {
        return SREC_TYPE_DATA_16;
    } else if (address <= 0xFFFFFF) {
        return SREC_TYPE_DATA_24;
    } else {
        return SREC_TYPE_DATA_32;
    }
}

static uint8_t srec_get_start_type(uint32_t address) {
    if (address <= 0xFFFF) {
        return SREC_TYPE_START_16;
    } else if (address <= 0xFFFFFF) {
        return SREC_TYPE_START_24;
    } else {
        return SREC_TYPE_START_32;
    }
}

static int srec_write_record(FILE *file, uint8_t type, uint32_t address, 
                            const uint8_t *data, uint8_t data_length) {
    if (!file) return -1;
    
    // Determine address byte count based on record type
    uint8_t addr_bytes;
    switch (type) {
        case SREC_TYPE_DATA_16:
        case SREC_TYPE_START_16:
            addr_bytes = 2;
            break;
        case SREC_TYPE_DATA_24:
        case SREC_TYPE_START_24:
            addr_bytes = 3;
            break;
        case SREC_TYPE_DATA_32:
        case SREC_TYPE_START_32:
            addr_bytes = 4;
            break;
        case SREC_TYPE_HEADER:
            addr_bytes = 2; // Header uses 16-bit address
            break;
        default:
            return -1;
    }
    
    // Record length = address bytes + data bytes + checksum byte
    uint8_t record_length = addr_bytes + data_length + 1;
    
    // Write record start and type
    fprintf(file, "S%u", type);
    
    // Write record length
    fprintf(file, "%02X", record_length);
    
    // Write address (big-endian)
    for (int i = addr_bytes - 1; i >= 0; i--) {
        fprintf(file, "%02X", (address >> (i * 8)) & 0xFF);
    }
    
    // Write data bytes
    for (uint8_t i = 0; i < data_length; i++) {
        fprintf(file, "%02X", data[i]);
    }
    
    // Calculate and write checksum
    uint8_t checksum_data[1 + addr_bytes + data_length];
    checksum_data[0] = record_length;
    for (int i = 0; i < addr_bytes; i++) {
        checksum_data[1 + i] = (address >> ((addr_bytes - 1 - i) * 8)) & 0xFF;
    }
    for (uint8_t i = 0; i < data_length; i++) {
        checksum_data[1 + addr_bytes + i] = data[i];
    }
    
    uint8_t checksum = srec_checksum(checksum_data, 1 + addr_bytes + data_length);
    fprintf(file, "%02X", checksum);
    
    // Write line terminator
    fprintf(file, "\n");
    
    return 0;
}

static int srec_write_file(output_context_t *ctx) {
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
        printf("Motorola S-Record Output:\n");
        printf("  File: %s\n", ctx->filename);
        printf("  Sections: %zu\n", ctx->section_count);
    }
    
    // Write header record (S0)
    const char *header_msg = "STAS";
    srec_write_record(output_file, SREC_TYPE_HEADER, 0, 
                     (const uint8_t*)header_msg, strlen(header_msg));
    
    uint32_t record_count = 1; // Header record counts as 1
    
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
        
        // Write data in chunks
        while (remaining > 0) {
            uint8_t chunk_size = (remaining > SREC_MAX_DATA_BYTES) ? 
                                SREC_MAX_DATA_BYTES : (uint8_t)remaining;
            
            uint8_t record_type = srec_get_data_type(address);
            srec_write_record(output_file, record_type, address, data, chunk_size);
            record_count++;
            
            data += chunk_size;
            address += chunk_size;
            remaining -= chunk_size;
        }
    }
    
    // Write record count (S5 for 16-bit count)
    if (record_count <= 0xFFFF) {
        uint8_t count_data[2] = {(record_count >> 8) & 0xFF, record_count & 0xFF};
        srec_write_record(output_file, SREC_TYPE_COUNT_16, record_count, count_data, 0);
    }
    
    // Write start address record if entry point is set
    if (ctx->entry_point != 0) {
        uint8_t start_type = srec_get_start_type(ctx->entry_point);
        srec_write_record(output_file, start_type, ctx->entry_point, NULL, 0);
    }
    
    fclose(output_file);
    
    if (ctx->verbose) {
        printf("Motorola S-Record file written successfully\n");
        printf("  Records: %u\n", record_count);
    }
    
    return 0;
}

static int srec_add_section(output_context_t *ctx, const char *name, 
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
    section->file_offset = 0; // Not used in Motorola S-Record
    section->flags = 0;
    
    ctx->section_count++;
    return 0;
}

static void srec_cleanup(output_context_t *ctx) {
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
