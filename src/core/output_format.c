/*
 * Output Format Manager for STAS
 * Central interface for all output format implementations
 */

#include "output_format.h"
#include "formats/elf.h"
#include "formats/flat_binary.h"
#include "formats/com_format.h"
#include "formats/intel_hex.h"
#include "formats/motorola_srec.h"
#include <stdio.h>
#include <stdlib.h>

//=============================================================================
// General Output Format Interface Implementation
//=============================================================================

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
            return get_intel_hex_format();
        case FORMAT_SREC:
            return get_motorola_srec_format();
        default:
            return NULL; // Unknown format
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
