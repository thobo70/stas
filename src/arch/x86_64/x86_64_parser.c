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
    reg->size = 8; // Default to 64-bit
    reg->encoding = 0;
    
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
    if (!inst || !buffer || !length) return -1;
    
    // Find instruction info
    const x86_64_instruction_info_t *info = x86_64_find_instruction(inst->mnemonic);
    if (!info) return -1;
    
    size_t pos = 0;
    
    // For now, just output the base opcode
    // Real implementation would handle all the complex encoding
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
