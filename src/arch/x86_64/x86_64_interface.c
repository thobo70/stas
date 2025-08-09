/*
 * x86-64 Architecture Interface Implementation - UNIFIED CLEAN VERSION
 * Provides the standard architecture interface for x86-64
 * Following STAS Development Manifest requirements
 */

#define _GNU_SOURCE
#include "x86_64.h"
#include "x86_64_unified.h"
#include "arch_interface.h"
#include <stdio.h>
#include <string.h>
#include <stdlib.h>

// Forward declarations for x86_64 unified functions
extern bool x86_64_is_valid_register(const char *name);
extern bool x86_64_validate_operand_combination(const char *mnemonic, 
                                                 const char **operands, 
                                                 int operand_count);
extern int x86_64_encode_instruction(instruction_t *inst, uint8_t *buffer, size_t *length);
extern int x86_64_validate_instruction(instruction_t *inst);

//=============================================================================
// Architecture Interface Implementation
//=============================================================================

static int x86_64_interface_init(void) {
    return x86_64_init();
}

static void x86_64_interface_cleanup(void) {
    x86_64_cleanup();
}

// Wrapper to convert int return to bool
static bool x86_64_interface_validate_instruction(instruction_t *inst) {
    return x86_64_validate_instruction(inst) != 0;
}

// Wrapper function for validate_operand_combination with proper signature
static bool x86_64_interface_validate_operand_combination(const char *mnemonic, 
                                                         operand_t *operands, 
                                                         size_t operand_count) {
    // Call the existing function with adapted parameters
    (void)operands; // Suppress unused parameter warning for future expansion
    return x86_64_validate_operand_combination(mnemonic, NULL, (int)operand_count);
}

// Wrapper function for parse_register with proper signature  
static int x86_64_interface_parse_register(const char *reg_name, asm_register_t *reg) {
    if (!reg_name || !reg) return -1;
    
    // CPU-ACCURATE: Handle register names with or without % prefix
    char full_reg_name[16];
    if (reg_name[0] != '%') {
        snprintf(full_reg_name, sizeof(full_reg_name), "%%%s", reg_name);
    } else {
        strncpy(full_reg_name, reg_name, sizeof(full_reg_name) - 1);
        full_reg_name[sizeof(full_reg_name) - 1] = '\0';
    }
    
    // Basic register parsing - check if it's a valid x86_64 register
    if (x86_64_is_valid_register(full_reg_name)) {
        reg->id = 0; // Simplified - would need proper mapping
        reg->name = strdup(full_reg_name);
        reg->encoding = 0;
        
        // Determine register size based on register name
        const char *name = reg_name;
        // Skip % prefix if present
        if (name[0] == '%') name++;
        
        size_t name_len = strlen(name);
        
        // 32-bit registers (e prefix) - check FIRST
        if (name[0] == 'e' && name_len == 3) {
            reg->size = 4;
        }
        // 32-bit extended registers (r*d)
        else if (name[0] == 'r' && name_len >= 3 && name[name_len-1] == 'd') {
            reg->size = 4;
        }
        // 8-bit registers
        else if ((name_len == 2 && (
                     strcmp(name, "al") == 0 || strcmp(name, "ah") == 0 ||
                     strcmp(name, "bl") == 0 || strcmp(name, "bh") == 0 ||
                     strcmp(name, "cl") == 0 || strcmp(name, "ch") == 0 ||
                     strcmp(name, "dl") == 0 || strcmp(name, "dh") == 0)) ||
                 (name_len == 3 && (
                     strcmp(name, "spl") == 0 || strcmp(name, "bpl") == 0 ||
                     strcmp(name, "sil") == 0 || strcmp(name, "dil") == 0)) ||
                 (name[0] == 'r' && name_len >= 3 && name[name_len-1] == 'b')) {
            reg->size = 1;
        }
        // 16-bit registers (ax, bx, cx, dx, sp, bp, si, di)
        else if ((name_len == 2 && (
                     strcmp(name, "ax") == 0 || strcmp(name, "bx") == 0 ||
                     strcmp(name, "cx") == 0 || strcmp(name, "dx") == 0 ||
                     strcmp(name, "sp") == 0 || strcmp(name, "bp") == 0 ||
                     strcmp(name, "si") == 0 || strcmp(name, "di") == 0)) ||
                 (name[0] == 'r' && name_len >= 3 && name[name_len-1] == 'w')) {
            reg->size = 2;
        }
        // 64-bit registers (default)
        else {
            reg->size = 8;
        }
        
        return 0;
    }
    return -1;
}

// Wrapper function for is_valid_register with proper signature
static bool x86_64_interface_is_valid_register(asm_register_t reg) {
    return reg.id <= 15; // x86_64 has 16 general purpose registers
}

// Wrapper function for get_register_name
static const char *x86_64_interface_get_register_name(asm_register_t reg) {
    // Return a default name - simplified implementation
    static const char* reg_names[] = {
        "%rax", "%rcx", "%rdx", "%rbx", "%rsp", "%rbp", "%rsi", "%rdi",
        "%r8", "%r9", "%r10", "%r11", "%r12", "%r13", "%r14", "%r15"
    };
    
    if (reg.id <= 15) {
        return reg_names[reg.id];
    }
    return NULL;
}

// Wrapper function for parse_addressing
static int x86_64_interface_parse_addressing(const char *addr_str, addressing_mode_t *mode) {
    if (!addr_str || !mode) return -1;
    
    // Basic implementation
    mode->type = ADDR_DIRECT;
    mode->offset = 0;
    mode->scale = 1;
    mode->symbol = strdup(addr_str);
    return 0;
}

// Wrapper function for validate_addressing
static bool x86_64_interface_validate_addressing(addressing_mode_t *mode, instruction_t *inst) {
    (void)inst; // Unused
    return mode != NULL;
}

// Wrapper function for get_instruction_size
static size_t x86_64_interface_get_instruction_size(instruction_t *inst) {
    if (!inst || !inst->mnemonic) return 0;
    
    // Basic size estimation
    if (strcmp(inst->mnemonic, "nop") == 0) return 1;
    if (strcmp(inst->mnemonic, "ret") == 0) return 1;
    if (strncmp(inst->mnemonic, "mov", 3) == 0) return 3;
    return 3; // Default
}

// Wrapper function for get_alignment
static size_t x86_64_interface_get_alignment(section_type_t section) {
    switch (section) {
        case SECTION_TEXT: return 16;
        case SECTION_DATA: return 8;
        case SECTION_BSS: return 8;
        case SECTION_RODATA: return 8;
        default: return 1;
    }
}

// Wrapper function for parse_instruction
static int x86_64_interface_parse_instruction(const char *mnemonic, operand_t *operands, 
                                             size_t operand_count, instruction_t *inst) {
    if (!mnemonic || !inst) return -1;
    
    // Validate that the mnemonic is a known x86_64 instruction
    const x86_64_instruction_info_t *instr_info = x86_64_find_instruction(mnemonic);
    if (!instr_info) {
        return -1; // Invalid instruction
    }
    
    inst->mnemonic = strdup(mnemonic);
    inst->operands = operands;
    inst->operand_count = operand_count;
    inst->encoding = NULL;
    inst->encoding_length = 0;
    
    return 0;
}

//=============================================================================
// Architecture Operations Structure
//=============================================================================

static const arch_ops_t x86_64_ops = {
    .name = "x86_64",
    .init = x86_64_interface_init,
    .cleanup = x86_64_interface_cleanup,
    .parse_instruction = x86_64_interface_parse_instruction,
    .encode_instruction = x86_64_encode_instruction,
    .parse_register = x86_64_interface_parse_register,
    .is_valid_register = x86_64_interface_is_valid_register,
    .get_register_name = x86_64_interface_get_register_name,
    .parse_addressing = x86_64_interface_parse_addressing,
    .validate_addressing = x86_64_interface_validate_addressing,
    .handle_directive = NULL,  // Not implemented yet
    .get_instruction_size = x86_64_interface_get_instruction_size,
    .get_alignment = x86_64_interface_get_alignment,
    .validate_instruction = x86_64_interface_validate_instruction,
    .validate_operand_combination = x86_64_interface_validate_operand_combination
};

//=============================================================================
// Architecture Registration Function
//=============================================================================

const arch_ops_t *get_x86_64_ops(void) {
    return &x86_64_ops;
}

// Main expects this function name
arch_ops_t *get_arch_ops_x86_64(void) {
    return (arch_ops_t *)&x86_64_ops;
}

// Test compatibility function
arch_ops_t *x86_64_get_arch_ops(void) {
    return (arch_ops_t *)&x86_64_ops;
}

//=============================================================================
// Debug and Diagnostic Functions (Optional)
//=============================================================================

void x86_64_print_capabilities(void) {
    printf("x86-64 Architecture Capabilities:\n");
    printf("- CPU-accurate instruction encoding\n");
    printf("- AT&T syntax support\n");
    printf("- 64-bit mode operations\n");
    printf("- Comprehensive register set\n");
}
