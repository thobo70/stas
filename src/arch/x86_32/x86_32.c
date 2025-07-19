/*
 * x86-32 Architecture Module for STAS
 * Intel IA-32 (80386+) instruction set implementation
 */

#include "x86_32.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>

// Safe string duplication
static char *x86_32_safe_strdup(const char *s) {
    if (!s) return NULL;
    size_t len = strlen(s) + 1;
    char *dup = malloc(len);
    if (dup) {
        memcpy(dup, s, len);
    }
    return dup;
}

// Convert string to lowercase
static char *x86_32_strlower(const char *str) {
    if (!str) return NULL;
    
    char *lower = x86_32_safe_strdup(str);
    if (!lower) return NULL;
    
    for (size_t i = 0; lower[i]; i++) {
        lower[i] = (char)tolower((unsigned char)lower[i]);
    }
    
    return lower;
}

// x86-32 register table
static const struct {
    const char *name;
    uint8_t encoding;
    uint8_t size;
} x86_32_registers[] = {
    // 32-bit registers
    {"eax", 0, 4}, {"ecx", 1, 4}, {"edx", 2, 4}, {"ebx", 3, 4},
    {"esp", 4, 4}, {"ebp", 5, 4}, {"esi", 6, 4}, {"edi", 7, 4},
    
    // 16-bit registers  
    {"ax", 0, 2}, {"cx", 1, 2}, {"dx", 2, 2}, {"bx", 3, 2},
    {"sp", 4, 2}, {"bp", 5, 2}, {"si", 6, 2}, {"di", 7, 2},
    
    // 8-bit registers (low)
    {"al", 0, 1}, {"cl", 1, 1}, {"dl", 2, 1}, {"bl", 3, 1},
    
    // 8-bit registers (high)
    {"ah", 4, 1}, {"ch", 5, 1}, {"dh", 6, 1}, {"bh", 7, 1},
};

static int x86_32_find_register(const char *name, uint8_t *encoding, uint8_t *size) {
    if (!name || !encoding || !size) return -1;
    
    size_t count = sizeof(x86_32_registers) / sizeof(x86_32_registers[0]);
    for (size_t i = 0; i < count; i++) {
        if (strcmp(name, x86_32_registers[i].name) == 0) {
            *encoding = x86_32_registers[i].encoding;
            *size = x86_32_registers[i].size;
            return 0;
        }
    }
    return -1;
}

int x86_32_init(void) {
    return 0;
}

void x86_32_cleanup(void) {
    // Cleanup implementation
}

int x86_32_parse_instruction(const char *mnemonic, operand_t *operands, 
                           size_t operand_count, instruction_t *inst) {
    if (!mnemonic || !inst) {
        return -1;
    }
    
    // Basic instruction setup
    inst->mnemonic = x86_32_safe_strdup(mnemonic);
    inst->operands = operands;
    inst->operand_count = operand_count;
    inst->encoding = NULL;
    inst->encoding_length = 0;
    
    return 0;
}

int x86_32_encode_instruction(instruction_t *inst, uint8_t *buffer, size_t *length) {
    if (!inst || !buffer || !length) {
        return -1;
    }
    
    // Assume maximum reasonable buffer size of 16 bytes for now
    const size_t MAX_BUFFER_SIZE = 16;

    char *lower_mnemonic = x86_32_strlower(inst->mnemonic);
    if (!lower_mnemonic) {
        return -1;
    }

    size_t pos = 0;

    // Handle specific instructions
    if (strcmp(lower_mnemonic, "ret") == 0) {
        // RET instruction: 0xC3
        if (pos >= MAX_BUFFER_SIZE) { free(lower_mnemonic); return -1; }
        buffer[pos++] = 0xC3;
        *length = pos;
        free(lower_mnemonic);
        return 0;
    }

    if (strcmp(lower_mnemonic, "nop") == 0) {
        // NOP instruction: 0x90
        if (pos >= MAX_BUFFER_SIZE) { free(lower_mnemonic); return -1; }
        buffer[pos++] = 0x90;
        *length = pos;
        free(lower_mnemonic);
        return 0;
    }
    
    // Handle MOV instructions
    if (strcmp(lower_mnemonic, "movl") == 0) {
        if (inst->operand_count == 2) {
            // MOV immediate to register: B8+r id (AT&T syntax: movl $imm, %reg)
            if (inst->operands[0].type == OPERAND_IMMEDIATE && 
                inst->operands[1].type == OPERAND_REGISTER) {
                
                uint8_t reg_encoding, reg_size;
                if (x86_32_find_register(inst->operands[1].value.reg.name, &reg_encoding, &reg_size) == 0) {
                    if (reg_size == 4 && reg_encoding == 0) { // EAX
                        if (pos + 5 > MAX_BUFFER_SIZE) { free(lower_mnemonic); return -1; }
                        buffer[pos++] = 0xB8; // MOV EAX, imm32
                        
                        // Add immediate value (little-endian)
                        uint32_t imm = (uint32_t)inst->operands[0].value.immediate;
                        buffer[pos++] = (uint8_t)(imm & 0xFF);
                        buffer[pos++] = (uint8_t)((imm >> 8) & 0xFF);
                        buffer[pos++] = (uint8_t)((imm >> 16) & 0xFF);
                        buffer[pos++] = (uint8_t)((imm >> 24) & 0xFF);
                        
                        *length = pos;
                        free(lower_mnemonic);
                        return 0;
                    }
                    else if (reg_size == 4) { // Other 32-bit registers
                        if (pos + 5 > MAX_BUFFER_SIZE) { free(lower_mnemonic); return -1; }
                        buffer[pos++] = 0xB8 + reg_encoding; // MOV r32, imm32
                        
                        // Add immediate value (little-endian)
                        uint32_t imm = (uint32_t)inst->operands[0].value.immediate;
                        buffer[pos++] = (uint8_t)(imm & 0xFF);
                        buffer[pos++] = (uint8_t)((imm >> 8) & 0xFF);
                        buffer[pos++] = (uint8_t)((imm >> 16) & 0xFF);
                        buffer[pos++] = (uint8_t)((imm >> 24) & 0xFF);
                        
                        *length = pos;
                        free(lower_mnemonic);
                        return 0;
                    }
                }
            }
            
            // MOV register to register (AT&T syntax: movl %src, %dst)
            if (inst->operands[0].type == OPERAND_REGISTER && 
                inst->operands[1].type == OPERAND_REGISTER) {
                
                uint8_t src_encoding, src_size, dst_encoding, dst_size;
                if (x86_32_find_register(inst->operands[0].value.reg.name, &src_encoding, &src_size) == 0 &&
                    x86_32_find_register(inst->operands[1].value.reg.name, &dst_encoding, &dst_size) == 0) {
                    
                    if (src_size == 4 && dst_size == 4) { // 32-bit register to register
                        if (pos + 2 > MAX_BUFFER_SIZE) { free(lower_mnemonic); return -1; }
                        buffer[pos++] = 0x89; // MOV r/m32, r32
                        buffer[pos++] = 0xC0 | (src_encoding << 3) | dst_encoding; // ModR/M byte
                        
                        *length = pos;
                        free(lower_mnemonic);
                        return 0;
                    }
                }
            }
        }
    }
    
    free(lower_mnemonic);
    return -1; // Unsupported instruction
}

int x86_32_parse_register(const char *reg_name, asm_register_t *reg) {
    if (!reg_name || !reg) {
        return -1;
    }
    
    uint8_t encoding, size;
    if (x86_32_find_register(reg_name, &encoding, &size) == 0) {
        reg->name = x86_32_safe_strdup(reg_name);
        reg->id = encoding;
        reg->size = size;
        reg->encoding = encoding;
        return 0;
    }
    
    return -1;
}

bool x86_32_is_valid_register(asm_register_t reg) {
    // Check if register encoding is valid for x86-32
    return (reg.encoding <= 7 && reg.size > 0);
}

const char *x86_32_get_register_name(asm_register_t reg) {
    // Placeholder - would return x86-32 register names
    (void)reg;      // Suppress unused parameter warning
    return NULL;
}

// Architecture operations structure
static arch_ops_t x86_32_ops = {
    .name = "x86_32",
    .init = x86_32_init,
    .cleanup = x86_32_cleanup,
    .parse_instruction = x86_32_parse_instruction,
    .encode_instruction = x86_32_encode_instruction,
    .parse_register = x86_32_parse_register,
    .is_valid_register = x86_32_is_valid_register,
    .get_register_name = x86_32_get_register_name,
    .parse_addressing = NULL, // Placeholder
    .validate_addressing = NULL, // Placeholder
    .handle_directive = NULL, // Placeholder
    .get_instruction_size = NULL, // Placeholder
    .get_alignment = NULL, // Placeholder
    .validate_instruction = NULL, // Placeholder
    .validate_operand_combination = NULL // Placeholder
};

arch_ops_t *x86_32_get_arch_ops(void) {
    return &x86_32_ops;
}

// Plugin entry point for x86_32
arch_ops_t *get_arch_ops_x86_32(void) {
    return x86_32_get_arch_ops();
}
