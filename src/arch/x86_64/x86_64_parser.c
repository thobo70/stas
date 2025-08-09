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

// Helper function to get register encoding per Intel SDM
static uint8_t get_register_encoding(const char *reg_name) {
    if (!reg_name) return 0xFF;
    
    // CPU-ACCURATE: Handle register names with or without % prefix
    const char *name = (reg_name[0] == '%') ? reg_name + 1 : reg_name;
    
    if (strcmp(name, "rax") == 0) return 0;
    if (strcmp(name, "rcx") == 0) return 1;
    if (strcmp(name, "rdx") == 0) return 2;
    if (strcmp(name, "rbx") == 0) return 3;
    if (strcmp(name, "rsp") == 0) return 4;
    if (strcmp(name, "rbp") == 0) return 5;
    if (strcmp(name, "rsi") == 0) return 6;
    if (strcmp(name, "rdi") == 0) return 7;
    return 0xFF; // Invalid
}

int x86_64_encode_instruction(instruction_t *inst, uint8_t *buffer, size_t *length) {
    if (!inst || !buffer || !length || !inst->mnemonic) return -1;
    
    size_t pos = 0;
    
    // CPU-ACCURATE ENCODING: Handle MOV immediate to register per Intel SDM
    if (strcmp(inst->mnemonic, "movq") == 0 && inst->operand_count == 2 &&
        inst->operands && inst->operands[0].type == OPERAND_IMMEDIATE &&
        inst->operands[1].type == OPERAND_REGISTER) {
        
        const char *reg_name = inst->operands[1].value.reg.name;
        if (!reg_name) return -1; // NULL register name
        
        // Intel SDM: MOV imm64, r64 = REX.W + [B8+rd] io
        uint8_t reg_encoding = 0xFF; // Invalid default
        
        if (strcmp(reg_name, "rax") == 0) reg_encoding = 0;
        else if (strcmp(reg_name, "rcx") == 0) reg_encoding = 1;
        else if (strcmp(reg_name, "rdx") == 0) reg_encoding = 2;
        else if (strcmp(reg_name, "rbx") == 0) reg_encoding = 3;
        else if (strcmp(reg_name, "rsp") == 0) reg_encoding = 4;
        else if (strcmp(reg_name, "rbp") == 0) reg_encoding = 5;
        else if (strcmp(reg_name, "rsi") == 0) reg_encoding = 6;
        else if (strcmp(reg_name, "rdi") == 0) reg_encoding = 7;
        else return -1; // Unsupported register for this encoding
        
        // REX.W prefix: 0100W000 (Intel SDM Section 2.2.1)
        buffer[pos++] = 0x48; // REX.W = 1, others = 0
        
        // Opcode: B8+rd where rd is register encoding (Intel SDM Volume 2A)
        buffer[pos++] = 0xB8 + reg_encoding;
        
        // 8-byte immediate value in little-endian format (Intel SDM)
        int64_t imm = inst->operands[0].value.immediate;
        for (int i = 0; i < 8; i++) {
            buffer[pos++] = (uint8_t)((imm >> (i * 8)) & 0xFF);
        }
        
        *length = pos;
        return 0;
    }
    
    // CPU-ACCURATE: Handle simple NOP instruction (Intel SDM)
    if (strcmp(inst->mnemonic, "nop") == 0 && inst->operand_count == 0) {
        buffer[pos++] = 0x90; // NOP opcode per Intel SDM
        *length = pos;
        return 0;
    }
    
    // CPU-ACCURATE: Handle RET instruction (Intel SDM)
    if ((strcmp(inst->mnemonic, "ret") == 0 || strcmp(inst->mnemonic, "retq") == 0) && 
        inst->operand_count == 0) {
        buffer[pos++] = 0xC3; // RET near opcode per Intel SDM
        *length = pos;
        return 0;
    }
    
    // CPU-ACCURATE: Handle SYSCALL instruction (Intel SDM Volume 2B)
    if (strcmp(inst->mnemonic, "syscall") == 0 && inst->operand_count == 0) {
        buffer[pos++] = 0x0F; // Two-byte opcode prefix
        buffer[pos++] = 0x05; // SYSCALL opcode per Intel SDM
        *length = pos;
        return 0;
    }
    // CPU-ACCURATE: Handle MOV register-to-register (Intel SDM: MOV r64, r/m64 = REX.W + 8B /r)
    if (strcmp(inst->mnemonic, "movq") == 0 && inst->operand_count == 2 &&
        inst->operands && inst->operands[0].type == OPERAND_REGISTER &&
        inst->operands[1].type == OPERAND_REGISTER) {
        
        uint8_t src_reg = get_register_encoding(inst->operands[0].value.reg.name);
        uint8_t dst_reg = get_register_encoding(inst->operands[1].value.reg.name);
        if (src_reg == 0xFF || dst_reg == 0xFF) return -1;
        
        buffer[pos++] = 0x48; // REX.W prefix
        buffer[pos++] = 0x89; // MOV r64 to r/m64 opcode
        buffer[pos++] = 0xC0 | (src_reg << 3) | dst_reg; // ModR/M: 11 reg r/m
        *length = pos;
        return 0;
    }
    
    // CPU-ACCURATE: Handle MOV immediate to memory (Intel SDM: MOV imm32, r/m64 = REX.W + C7 /0)
    if (strcmp(inst->mnemonic, "movq") == 0 && inst->operand_count == 2 &&
        inst->operands && inst->operands[0].type == OPERAND_IMMEDIATE &&
        inst->operands[1].type == OPERAND_MEMORY) {
        
        // For simple (%rdi) addressing mode
        addressing_mode_t *addr = &inst->operands[1].value.memory;
        uint8_t base_reg = get_register_encoding(addr->base.name);
        if (base_reg == 0xFF) return -1;
        
        buffer[pos++] = 0x48; // REX.W prefix
        buffer[pos++] = 0xC7; // MOV imm32 to r/m64 opcode
        
        // ModR/M byte: mod=00 (register indirect), reg=000, r/m=base_reg
        if (addr->offset == 0) {
            buffer[pos++] = base_reg; // [rdi] = mod=00, r/m=base_reg
        } else if (addr->offset >= -128 && addr->offset <= 127) {
            buffer[pos++] = 0x40 | base_reg; // [rdi+disp8] = mod=01, r/m=base_reg
            buffer[pos++] = (uint8_t)addr->offset; // 8-bit displacement
        } else {
            buffer[pos++] = 0x80 | base_reg; // [rdi+disp32] = mod=10, r/m=base_reg
            // 32-bit displacement in little-endian
            for (int i = 0; i < 4; i++) {
                buffer[pos++] = (uint8_t)((addr->offset >> (i * 8)) & 0xFF);
            }
        }
        
        // 32-bit immediate value (sign-extended to 64-bit)
        int32_t imm = (int32_t)inst->operands[0].value.immediate;
        for (int i = 0; i < 4; i++) {
            buffer[pos++] = (uint8_t)((imm >> (i * 8)) & 0xFF);
        }
        
        *length = pos;
        return 0;
    }
    
    // CPU-ACCURATE: Handle MOV register to memory (Intel SDM: MOV r64, r/m64 = REX.W + 89 /r)
    if (strcmp(inst->mnemonic, "movq") == 0 && inst->operand_count == 2 &&
        inst->operands && inst->operands[0].type == OPERAND_REGISTER &&
        inst->operands[1].type == OPERAND_MEMORY) {
        
        uint8_t src_reg = get_register_encoding(inst->operands[0].value.reg.name);
        addressing_mode_t *addr = &inst->operands[1].value.memory;
        uint8_t base_reg = get_register_encoding(addr->base.name);
        if (src_reg == 0xFF || base_reg == 0xFF) return -1;
        
        buffer[pos++] = 0x48; // REX.W prefix
        buffer[pos++] = 0x89; // MOV r64 to r/m64 opcode
        
        // ModR/M byte: mod depends on displacement, reg=src_reg, r/m=base_reg
        if (addr->offset == 0) {
            buffer[pos++] = (src_reg << 3) | base_reg; // [base] = mod=00
        } else if (addr->offset >= -128 && addr->offset <= 127) {
            buffer[pos++] = 0x40 | (src_reg << 3) | base_reg; // [base+disp8] = mod=01
            buffer[pos++] = (uint8_t)addr->offset; // 8-bit displacement
        } else {
            buffer[pos++] = 0x80 | (src_reg << 3) | base_reg; // [base+disp32] = mod=10
            // 32-bit displacement in little-endian
            for (int i = 0; i < 4; i++) {
                buffer[pos++] = (uint8_t)((addr->offset >> (i * 8)) & 0xFF);
            }
        }
        
        *length = pos;
        return 0;
    }
    
    // CPU-ACCURATE: Handle ADD register-to-register (Intel SDM: ADD r/m64, r64 = REX.W + 01 /r)
    if (strcmp(inst->mnemonic, "addq") == 0 && inst->operand_count == 2 &&
        inst->operands && inst->operands[0].type == OPERAND_REGISTER &&
        inst->operands[1].type == OPERAND_REGISTER) {
        
        uint8_t src_reg = get_register_encoding(inst->operands[0].value.reg.name);
        uint8_t dst_reg = get_register_encoding(inst->operands[1].value.reg.name);
        if (src_reg == 0xFF || dst_reg == 0xFF) return -1;
        
        buffer[pos++] = 0x48; // REX.W prefix
        buffer[pos++] = 0x01; // ADD r64 to r/m64 opcode
        buffer[pos++] = 0xC0 | (src_reg << 3) | dst_reg; // ModR/M: 11 reg r/m
        *length = pos;
        return 0;
    }
    
    // CPU-ACCURATE: Handle SUB register-to-register (Intel SDM: SUB r/m64, r64 = REX.W + 29 /r)
    if (strcmp(inst->mnemonic, "subq") == 0 && inst->operand_count == 2 &&
        inst->operands && inst->operands[0].type == OPERAND_REGISTER &&
        inst->operands[1].type == OPERAND_REGISTER) {
        
        uint8_t src_reg = get_register_encoding(inst->operands[0].value.reg.name);
        uint8_t dst_reg = get_register_encoding(inst->operands[1].value.reg.name);
        if (src_reg == 0xFF || dst_reg == 0xFF) return -1;
        
        buffer[pos++] = 0x48; // REX.W prefix
        buffer[pos++] = 0x29; // SUB r64 from r/m64 opcode
        buffer[pos++] = 0xC0 | (src_reg << 3) | dst_reg; // ModR/M: 11 reg r/m
        *length = pos;
        return 0;
    }
    
    // CPU-ACCURATE: Handle INC register (Intel SDM: INC r/m64 = REX.W + FF /0)
    if (strcmp(inst->mnemonic, "incq") == 0 && inst->operand_count == 1 &&
        inst->operands && inst->operands[0].type == OPERAND_REGISTER) {
        
        uint8_t reg = get_register_encoding(inst->operands[0].value.reg.name);
        if (reg == 0xFF) return -1;
        
        buffer[pos++] = 0x48; // REX.W prefix
        buffer[pos++] = 0xFF; // INC/DEC opcode
        buffer[pos++] = 0xC0 | reg; // ModR/M: 11 000 r/m (reg field = 0 for INC)
        *length = pos;
        return 0;
    }
    
    // CPU-ACCURATE: Handle DEC register (Intel SDM: DEC r/m64 = REX.W + FF /1)
    if (strcmp(inst->mnemonic, "decq") == 0 && inst->operand_count == 1 &&
        inst->operands && inst->operands[0].type == OPERAND_REGISTER) {
        
        uint8_t reg = get_register_encoding(inst->operands[0].value.reg.name);
        if (reg == 0xFF) return -1;
        
        buffer[pos++] = 0x48; // REX.W prefix
        buffer[pos++] = 0xFF; // INC/DEC opcode
        buffer[pos++] = 0xC8 | reg; // ModR/M: 11 001 r/m (reg field = 1 for DEC)
        *length = pos;
        return 0;
    }
    
    // CPU-ACCURATE: Handle JNE (conditional jump) with 8-bit relative displacement (Intel SDM)
    if (strcmp(inst->mnemonic, "jne") == 0 && inst->operand_count == 1 &&
        inst->operands && (inst->operands[0].type == OPERAND_SYMBOL || 
                          inst->operands[0].type == OPERAND_IMMEDIATE)) {
        
        // For now, use a placeholder displacement (will be resolved by linker)
        buffer[pos++] = 0x75; // JNE rel8 opcode per Intel SDM
        buffer[pos++] = 0x00; // Placeholder 8-bit displacement
        *length = pos;
        return 0;
    }
    
    // CPU-ACCURATE: Handle JMP (unconditional jump) with 8-bit relative displacement (Intel SDM)
    if (strcmp(inst->mnemonic, "jmp") == 0 && inst->operand_count == 1 &&
        inst->operands && (inst->operands[0].type == OPERAND_SYMBOL || 
                          inst->operands[0].type == OPERAND_IMMEDIATE)) {
        
        // For now, use a placeholder displacement (will be resolved by linker)
        buffer[pos++] = 0xEB; // JMP rel8 opcode per Intel SDM
        buffer[pos++] = 0x00; // Placeholder 8-bit displacement
        *length = pos;
        return 0;
    }
    
    // CPU-ACCURATE: Handle CLI (clear interrupt flag) (Intel SDM)
    if (strcmp(inst->mnemonic, "cli") == 0 && inst->operand_count == 0) {
        buffer[pos++] = 0xFA; // CLI opcode per Intel SDM
        *length = pos;
        return 0;
    }
    
    // CPU-ACCURATE: Handle HLT (halt) (Intel SDM)
    if (strcmp(inst->mnemonic, "hlt") == 0 && inst->operand_count == 0) {
        buffer[pos++] = 0xF4; // HLT opcode per Intel SDM
        *length = pos;
        return 0;
    }
    
    // CPU-ACCURATE: Handle AND register-to-register (Intel SDM: AND r/m64, r64 = REX.W + 21 /r)
    if (strcmp(inst->mnemonic, "andq") == 0 && inst->operand_count == 2 &&
        inst->operands && inst->operands[0].type == OPERAND_REGISTER &&
        inst->operands[1].type == OPERAND_REGISTER) {
        
        uint8_t src_reg = get_register_encoding(inst->operands[0].value.reg.name);
        uint8_t dst_reg = get_register_encoding(inst->operands[1].value.reg.name);
        if (src_reg == 0xFF || dst_reg == 0xFF) return -1;
        
        buffer[pos++] = 0x48; // REX.W prefix
        buffer[pos++] = 0x21; // AND r64 with r/m64 opcode
        buffer[pos++] = 0xC0 | (src_reg << 3) | dst_reg; // ModR/M: 11 reg r/m
        *length = pos;
        return 0;
    }
    
    // CPU-ACCURATE: Handle OR register-to-register (Intel SDM: OR r/m64, r64 = REX.W + 09 /r)
    if (strcmp(inst->mnemonic, "orq") == 0 && inst->operand_count == 2 &&
        inst->operands && inst->operands[0].type == OPERAND_REGISTER &&
        inst->operands[1].type == OPERAND_REGISTER) {
        
        uint8_t src_reg = get_register_encoding(inst->operands[0].value.reg.name);
        uint8_t dst_reg = get_register_encoding(inst->operands[1].value.reg.name);
        if (src_reg == 0xFF || dst_reg == 0xFF) return -1;
        
        buffer[pos++] = 0x48; // REX.W prefix
        buffer[pos++] = 0x09; // OR r64 with r/m64 opcode
        buffer[pos++] = 0xC0 | (src_reg << 3) | dst_reg; // ModR/M: 11 reg r/m
        *length = pos;
        return 0;
    }
    
    // CPU-ACCURATE: Handle CMP register-to-register (Intel SDM: CMP r/m64, r64 = REX.W + 39 /r)
    if (strcmp(inst->mnemonic, "cmpq") == 0 && inst->operand_count == 2 &&
        inst->operands && inst->operands[0].type == OPERAND_REGISTER &&
        inst->operands[1].type == OPERAND_REGISTER) {
        
        uint8_t src_reg = get_register_encoding(inst->operands[0].value.reg.name);
        uint8_t dst_reg = get_register_encoding(inst->operands[1].value.reg.name);
        if (src_reg == 0xFF || dst_reg == 0xFF) return -1;
        
        buffer[pos++] = 0x48; // REX.W prefix
        buffer[pos++] = 0x39; // CMP r64 with r/m64 opcode
        buffer[pos++] = 0xC0 | (src_reg << 3) | dst_reg; // ModR/M: 11 reg r/m
        *length = pos;
        return 0;
    }
    
    // For other instructions that we haven't implemented yet, return error
    // This prevents generating invalid machine code that violates CPU specifications
    fprintf(stderr, "x86_64: Instruction '%s' encoding not yet implemented in CPU-accurate mode\n", 
            inst->mnemonic);
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
