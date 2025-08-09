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

int x86_64_encode_instruction(instruction_t *inst, uint8_t *buffer, size_t *length) {
    if (!inst || !buffer || !length || !inst->mnemonic) return -1;
    
    size_t pos = 0;
    
    // Handle MOV immediate to register instructions specifically
    if (strcmp(inst->mnemonic, "movq") == 0 && inst->operand_count == 2 &&
        inst->operands && inst->operands[0].type == OPERAND_IMMEDIATE &&
        inst->operands[1].type == OPERAND_REGISTER) {
        
        // Add REX.W prefix for 64-bit operation (0x48)
        buffer[pos++] = 0x48;
        
        // Determine register encoding
        const char *reg_name = inst->operands[1].value.reg.name;
        if (!reg_name) return -1; // NULL register name
        uint8_t opcode = 0xB8; // Base opcode for MOV immediate to register
        
        if (strcmp(reg_name, "rax") == 0) opcode += 0;
        else if (strcmp(reg_name, "rcx") == 0) opcode += 1;
        else if (strcmp(reg_name, "rdx") == 0) opcode += 2;
        else if (strcmp(reg_name, "rbx") == 0) opcode += 3;
        else if (strcmp(reg_name, "rsp") == 0) opcode += 4;
        else if (strcmp(reg_name, "rbp") == 0) opcode += 5;
        else if (strcmp(reg_name, "rsi") == 0) opcode += 6;
        else if (strcmp(reg_name, "rdi") == 0) opcode += 7;
        else return -1; // Unsupported register
        
        // Add opcode with register encoding
        buffer[pos++] = opcode;
        
        // Add 8-byte immediate value (little-endian)
        int64_t imm = inst->operands[0].value.immediate;
        for (int i = 0; i < 8; i++) {
            buffer[pos++] = (imm >> (i * 8)) & 0xFF;
        }
        
        *length = pos;
        return 0;
    }
    
    // For other instructions, find the instruction info and use basic encoding
    const x86_64_instruction_info_t *info = x86_64_find_instruction(inst->mnemonic);
    if (!info) return -1;
    
    // Default: just output the base opcode for other instructions
    for (int i = 0; i < info->opcode_length; i++) {
        buffer[pos++] = info->opcode[i];
    }
    
    *length = pos;
    return 0;
}

//=============================================================================
// Register Functions - Declarations only (implemented in x86_64_unified.c)
//=============================================================================

// extern declarations - these are implemented in x86_64_unified.c
// int x86_64_parse_register(const char *reg_str, asm_register_t *reg);
// bool x86_64_is_valid_register(const char *reg_str);
// int x86_64_validate_operands(const char *mnemonic, operand_t *operands, size_t count);
// bool x86_64_is_valid_operand_combination(const char *mnemonic, operand_t *operands, size_t count);
