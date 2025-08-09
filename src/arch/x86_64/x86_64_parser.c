/*
 * x86-64 Instruction Parsing and Encoding - UNIFIED CLEAN VERSION
 * AT&T syntax parsing with CPU-accurate encoding
 * Following STAS Development Manifest requirements
 */

#include "x86_64_unified.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>

#define MAX_OPERANDS 4

//=============================================================================
// Helper Functions
//=============================================================================

static char *skip_whitespace(char *str) {
    while (*str && isspace(*str)) str++;
    return str;
}

static int parse_immediate(const char *str, int64_t *value) {
    if (!str || str[0] != '$') return -1;
    
    char *endptr;
    *value = strtoll(str + 1, &endptr, 0);
    
    return (*endptr == '\0' || isspace(*endptr)) ? 0 : -1;
}

static int parse_register(const char *str, asm_register_t *reg) {
    if (!str || str[0] != '%') return -1;
    
    // Simple register parsing - just copy the name without the %
    reg->name = malloc(strlen(str));
    strcpy(reg->name, str + 1);
    reg->id = 0;  // Will be filled by register lookup
    reg->encoding = 0;
    
    // Determine register size based on register name
    const char *reg_name = str + 1; // Skip the %
    size_t name_len = strlen(reg_name);
    
    // 32-bit registers (e prefix) - check FIRST before 16-bit
    if (reg_name[0] == 'e' && name_len == 3) {
        reg->size = 4;
    }
    // 32-bit extended registers (r*d)
    else if (reg_name[0] == 'r' && name_len >= 3 && reg_name[name_len-1] == 'd') {
        reg->size = 4;
    }
    // 8-bit registers
    else if ((name_len == 2 && (
                 strcmp(reg_name, "al") == 0 || strcmp(reg_name, "ah") == 0 ||
                 strcmp(reg_name, "bl") == 0 || strcmp(reg_name, "bh") == 0 ||
                 strcmp(reg_name, "cl") == 0 || strcmp(reg_name, "ch") == 0 ||
                 strcmp(reg_name, "dl") == 0 || strcmp(reg_name, "dh") == 0)) ||
             (name_len == 3 && (
                 strcmp(reg_name, "spl") == 0 || strcmp(reg_name, "bpl") == 0 ||
                 strcmp(reg_name, "sil") == 0 || strcmp(reg_name, "dil") == 0)) ||
             (reg_name[0] == 'r' && name_len >= 3 && reg_name[name_len-1] == 'b')) {
        reg->size = 1;
    }
    // 16-bit registers (ax, bx, cx, dx, sp, bp, si, di)
    else if ((name_len == 2 && (
                 strcmp(reg_name, "ax") == 0 || strcmp(reg_name, "bx") == 0 ||
                 strcmp(reg_name, "cx") == 0 || strcmp(reg_name, "dx") == 0 ||
                 strcmp(reg_name, "sp") == 0 || strcmp(reg_name, "bp") == 0 ||
                 strcmp(reg_name, "si") == 0 || strcmp(reg_name, "di") == 0)) ||
             (reg_name[0] == 'r' && name_len >= 3 && reg_name[name_len-1] == 'w')) {
        reg->size = 2;
    }
    // 64-bit registers (default)
    else {
        reg->size = 8;
    }
    
    return 0;
}

static int parse_memory_operand(const char *str, operand_t *operand) {
    if (!str || !operand) return -1;
    
    operand->type = OPERAND_MEMORY;
    operand->value.memory.type = ADDR_DIRECT;
    operand->value.memory.offset = 0;
    operand->value.memory.base.name = NULL;
    operand->value.memory.index.name = NULL;
    operand->value.memory.scale = 1;
    operand->value.memory.symbol = NULL;
    
    // For now, simplified memory parsing
    if (strchr(str, '(')) {
        operand->value.memory.type = ADDR_INDIRECT;
        // More complex parsing would go here
    }
    
    return 0;
}

//=============================================================================
// Instruction Parsing
//=============================================================================

int x86_64_parse_instruction(const char *line, instruction_t *inst) {
    if (!line || !inst) return -1;
    
    // Clear instruction structure
    memset(inst, 0, sizeof(instruction_t));
    
    // Create working copy of the line
    char *work_line = malloc(strlen(line) + 1);
    strcpy(work_line, line);
    
    // Skip whitespace
    char *ptr = skip_whitespace(work_line);
    
    // Extract mnemonic
    char *space = strchr(ptr, ' ');
    char *tab = strchr(ptr, '\t');
    char *end = space;
    if (tab && (!space || tab < space)) end = tab;
    
    if (end) {
        *end = '\0';
        inst->mnemonic = malloc(strlen(ptr) + 1);
        strcpy(inst->mnemonic, ptr);
        ptr = skip_whitespace(end + 1);
    } else {
        // No operands
        inst->mnemonic = malloc(strlen(ptr) + 1);
        strcpy(inst->mnemonic, ptr);
        inst->operand_count = 0;
        free(work_line);
        return 0;
    }
    
    // Parse operands
    inst->operands = malloc(MAX_OPERANDS * sizeof(operand_t));
    inst->operand_count = 0;
    
    // Split operands by commas
    char *operand_str = strtok(ptr, ",");
    while (operand_str && inst->operand_count < MAX_OPERANDS) {
        operand_str = skip_whitespace(operand_str);
        
        // Remove trailing whitespace
        char *end_op = operand_str + strlen(operand_str) - 1;
        while (end_op > operand_str && isspace(*end_op)) {
            *end_op = '\0';
            end_op--;
        }
        
        operand_t *op = &inst->operands[inst->operand_count];
        
        if (operand_str[0] == '$') {
            // Immediate operand
            op->type = OPERAND_IMMEDIATE;
            if (parse_immediate(operand_str, &op->value.immediate) != 0) {
                free(work_line);
                return -1;
            }
        } else if (operand_str[0] == '%') {
            // Register operand
            op->type = OPERAND_REGISTER;
            if (parse_register(operand_str, &op->value.reg) != 0) {
                free(work_line);
                return -1;
            }
        } else if (strchr(operand_str, '(') || strchr(operand_str, ')')) {
            // Memory operand
            if (parse_memory_operand(operand_str, op) != 0) {
                free(work_line);
                return -1;
            }
        } else {
            // Symbol operand
            op->type = OPERAND_SYMBOL;
            op->value.symbol = malloc(strlen(operand_str) + 1);
            strcpy(op->value.symbol, operand_str);
        }
        
        inst->operand_count++;
        operand_str = strtok(NULL, ",");
    }
    
    free(work_line);
    return 0;
}

//=============================================================================
// Instruction Encoding (Simplified)
//=============================================================================

// Helper function to get register encoding per Intel SDM - COMPREHENSIVE VERSION
static uint8_t get_register_encoding(const char *reg_name) {
    if (!reg_name) return 0xFF;
    
    // CPU-ACCURATE: Handle register names with or without % prefix
    const char *name = (reg_name[0] == '%') ? reg_name + 1 : reg_name;
    
    // 64-bit registers
    if (strcmp(name, "rax") == 0) return 0;
    if (strcmp(name, "rcx") == 0) return 1;
    if (strcmp(name, "rdx") == 0) return 2;
    if (strcmp(name, "rbx") == 0) return 3;
    if (strcmp(name, "rsp") == 0) return 4;
    if (strcmp(name, "rbp") == 0) return 5;
    if (strcmp(name, "rsi") == 0) return 6;
    if (strcmp(name, "rdi") == 0) return 7;
    
    // 32-bit registers (same encoding as 64-bit counterparts)
    if (strcmp(name, "eax") == 0) return 0;
    if (strcmp(name, "ecx") == 0) return 1;
    if (strcmp(name, "edx") == 0) return 2;
    if (strcmp(name, "ebx") == 0) return 3;
    if (strcmp(name, "esp") == 0) return 4;
    if (strcmp(name, "ebp") == 0) return 5;
    if (strcmp(name, "esi") == 0) return 6;
    if (strcmp(name, "edi") == 0) return 7;
    
    // 16-bit registers (same encoding)
    if (strcmp(name, "ax") == 0) return 0;
    if (strcmp(name, "cx") == 0) return 1;
    if (strcmp(name, "dx") == 0) return 2;
    if (strcmp(name, "bx") == 0) return 3;
    if (strcmp(name, "sp") == 0) return 4;
    if (strcmp(name, "bp") == 0) return 5;
    if (strcmp(name, "si") == 0) return 6;
    if (strcmp(name, "di") == 0) return 7;
    
    // 8-bit registers
    if (strcmp(name, "al") == 0) return 0;
    if (strcmp(name, "cl") == 0) return 1;
    if (strcmp(name, "dl") == 0) return 2;
    if (strcmp(name, "bl") == 0) return 3;
    if (strcmp(name, "ah") == 0) return 4;
    if (strcmp(name, "ch") == 0) return 5;
    if (strcmp(name, "dh") == 0) return 6;
    if (strcmp(name, "bh") == 0) return 7;
    
    return 0xFF; // Invalid
}

int x86_64_encode_instruction(instruction_t *inst, uint8_t *buffer, size_t *length) {
    if (!inst || !buffer || !length || !inst->mnemonic) return -1;
    
    // Find instruction in CPU-accurate database
    const x86_64_instruction_info_t *instr_info = x86_64_find_instruction(inst->mnemonic);
    if (!instr_info) {
        printf("x86_64: Instruction '%s' not found in CPU-accurate database\n", inst->mnemonic);
        return -1;
    }
    
    size_t pos = 0;
    
    // CPU-ACCURATE ENCODING following Intel SDM specifications
    // Handle instructions based on their database encoding information
    
    // 1. HANDLE NO-OPERAND INSTRUCTIONS (RET, NOP, etc.)
    if (inst->operand_count == 0) {
        // Add prefixes if needed
        if (instr_info->prefix_byte != 0) {
            buffer[pos++] = instr_info->prefix_byte;
        }
        
        // Add REX prefix if needed for 64-bit operation
        if (instr_info->rex_w) {
            buffer[pos++] = 0x48;  // REX.W
        }
        
        // Add opcode bytes
        for (int i = 0; i < instr_info->opcode_length; i++) {
            buffer[pos++] = instr_info->opcode[i];
        }
        
        *length = pos;
        return 0;
    }
    
    // 2. HANDLE MOV IMMEDIATE TO REGISTER (Special encoding)
    if (strcmp(inst->mnemonic, "movq") == 0 && inst->operand_count == 2 &&
        inst->operands && inst->operands[0].type == OPERAND_IMMEDIATE &&
        inst->operands[1].type == OPERAND_REGISTER) {
        
        const char *reg_name = inst->operands[1].value.reg.name;
        if (!reg_name) return -1;
        
        // Remove % prefix if present for comparison
        if (reg_name[0] == '%') reg_name++;
        
        // Intel SDM: MOV imm64, r64 = REX.W + [B8+rd] io
        uint8_t reg_encoding = 0xFF;
        
        if (strcmp(reg_name, "rax") == 0) reg_encoding = 0;
        else if (strcmp(reg_name, "rcx") == 0) reg_encoding = 1;
        else if (strcmp(reg_name, "rdx") == 0) reg_encoding = 2;
        else if (strcmp(reg_name, "rbx") == 0) reg_encoding = 3;
        else if (strcmp(reg_name, "rsp") == 0) reg_encoding = 4;
        else if (strcmp(reg_name, "rbp") == 0) reg_encoding = 5;
        else if (strcmp(reg_name, "rsi") == 0) reg_encoding = 6;
        else if (strcmp(reg_name, "rdi") == 0) reg_encoding = 7;
        else return -1;
        
        // REX.W prefix for 64-bit operation
        buffer[pos++] = 0x48;
        
        // Opcode: B8+rd
        buffer[pos++] = 0xB8 + reg_encoding;
        
        // 8-byte immediate in little-endian
        int64_t imm = inst->operands[0].value.immediate;
        for (int i = 0; i < 8; i++) {
            buffer[pos++] = (uint8_t)((imm >> (i * 8)) & 0xFF);
        }
        
        *length = pos;
        return 0;
    }
    
    // 3. HANDLE REGISTER-TO-REGISTER OPERATIONS
    if (inst->operand_count == 2 && 
        inst->operands && 
        inst->operands[0].type == OPERAND_REGISTER &&
        inst->operands[1].type == OPERAND_REGISTER) {
        
        const char *src_reg = inst->operands[0].value.reg.name;
        const char *dst_reg = inst->operands[1].value.reg.name;
        
        if (!src_reg || !dst_reg) return -1;
        
        // Remove % prefix
        if (src_reg[0] == '%') src_reg++;
        if (dst_reg[0] == '%') dst_reg++;
        
        // Get register encodings
        uint8_t src_encoding = get_register_encoding(src_reg);
        uint8_t dst_encoding = get_register_encoding(dst_reg);
        
        if (src_encoding == 0xFF || dst_encoding == 0xFF) return -1;
        
        // Add REX prefix if needed for 64-bit operation
        if (instr_info->rex_w) {
            buffer[pos++] = 0x48;  // REX.W
        }
        
        // Add operand size prefix if needed
        if (instr_info->prefix_byte != 0) {
            buffer[pos++] = instr_info->prefix_byte;
        }
        
        // Add opcode bytes
        for (int i = 0; i < instr_info->opcode_length; i++) {
            buffer[pos++] = instr_info->opcode[i];
        }
        
        // ModR/M byte: mod=11 (register), reg=src, r/m=dst
        uint8_t modrm = 0xC0 | (src_encoding << 3) | dst_encoding;
        buffer[pos++] = modrm;
        
        *length = pos;
        return 0;
    }
    
    // Default: Instruction encoding not yet implemented
    printf("x86_64: Instruction '%s' encoding not yet implemented in CPU-accurate mode\n", inst->mnemonic);
    return -1;
}

//=============================================================================
// Register Functions - Declarations only (implemented in x86_64_unified.c)
//=============================================================================

// extern declarations - these are implemented in x86_64_unified.c
// int x86_64_parse_register(const char *reg_str, asm_register_t *reg);
// bool x86_64_is_valid_register(const char *reg_str);
// int x86_64_validate_operands(const char *mnemonic, operand_t *operands, size_t count);
// bool x86_64_is_valid_operand_combination(const char *mnemonic, operand_t *operands, size_t count);
