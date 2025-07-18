/*
 * x86-64 Instruction Encoding Implementation
 * Handles instruction encoding, ModR/M, SIB, and displacement calculation
 */

#include "x86_64.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

//=============================================================================
// Instruction Encoding Tables
//=============================================================================

// Extended instruction table with encoding details
typedef struct {
    const char *mnemonic;
    uint8_t opcode[3];
    uint8_t opcode_length;
    bool needs_modrm;
    bool needs_rex_w;      // Requires REX.W for 64-bit operation
    uint8_t operand_order; // 0=reg,r/m  1=r/m,reg  2=special
} x86_64_instruction_encoding_t;

static const x86_64_instruction_encoding_t instruction_encodings[] = {
    // Data movement instructions
    {"mov",    {0x89, 0x00, 0x00}, 1, true,  false, 0}, // MOV r/m32, r32
    {"movq",   {0x89, 0x00, 0x00}, 1, true,  true,  0}, // MOV r/m64, r64
    {"movl",   {0x89, 0x00, 0x00}, 1, true,  false, 0}, // MOV r/m32, r32
    {"movw",   {0x66, 0x89, 0x00}, 2, true,  false, 0}, // MOV r/m16, r16
    {"movb",   {0x88, 0x00, 0x00}, 1, true,  false, 0}, // MOV r/m8, r8
    
    // Immediate to register moves
    {"movq",   {0xB8, 0x00, 0x00}, 1, false, true,  2}, // MOV r64, imm64
    
    // Arithmetic instructions
    {"add",    {0x01, 0x00, 0x00}, 1, true,  false, 0}, // ADD r/m32, r32
    {"addq",   {0x01, 0x00, 0x00}, 1, true,  true,  0}, // ADD r/m64, r64
    {"sub",    {0x29, 0x00, 0x00}, 1, true,  false, 0}, // SUB r/m32, r32
    {"subq",   {0x29, 0x00, 0x00}, 1, true,  true,  0}, // SUB r/m64, r64
    
    // Stack operations
    {"push",   {0x50, 0x00, 0x00}, 1, false, false, 2}, // PUSH r64
    {"pushq",  {0x50, 0x00, 0x00}, 1, false, false, 2}, // PUSH r64
    {"pop",    {0x58, 0x00, 0x00}, 1, false, false, 2}, // POP r64
    {"popq",   {0x58, 0x00, 0x00}, 1, false, false, 2}, // POP r64
    
    // Control flow
    {"call",   {0xE8, 0x00, 0x00}, 1, false, false, 2}, // CALL rel32
    {"ret",    {0xC3, 0x00, 0x00}, 1, false, false, 2}, // RET
    {"jmp",    {0xE9, 0x00, 0x00}, 1, false, false, 2}, // JMP rel32
    
    // System instructions
    {"syscall", {0x0F, 0x05, 0x00}, 2, false, false, 2}, // SYSCALL
    {"nop",     {0x90, 0x00, 0x00}, 1, false, false, 2}, // NOP
    
    {NULL, {0}, 0, false, false, 0} // Sentinel
};

//=============================================================================
// Encoding Helper Functions
//=============================================================================

static uint8_t encode_rex_prefix(bool w, bool r, bool x, bool b) {
    uint8_t rex = 0x40; // REX prefix base
    if (w) rex |= 0x08; // REX.W
    if (r) rex |= 0x04; // REX.R
    if (x) rex |= 0x02; // REX.X
    if (b) rex |= 0x01; // REX.B
    return rex;
}

static uint8_t encode_modrm(uint8_t mod, uint8_t reg, uint8_t rm) {
    return (mod << 6) | (reg << 3) | rm;
}

static uint8_t encode_sib(uint8_t scale, uint8_t index, uint8_t base) __attribute__((unused));
static uint8_t encode_sib(uint8_t scale, uint8_t index, uint8_t base) {
    return (scale << 6) | (index << 3) | base;
}

static int get_register_encoding(asm_register_t reg, bool *needs_rex) {
    *needs_rex = false;
    
    // Extract the base encoding
    int encoding = reg.encoding & 0x07;
    
    // Check if we need REX prefix for extended registers
    if (reg.id >= R8B && reg.id <= R15B) { // 8-bit extended
        *needs_rex = true;
        return encoding;
    }
    if (reg.id >= R8W && reg.id <= R15W) { // 16-bit extended
        *needs_rex = true;
        return encoding;
    }
    if (reg.id >= R8D && reg.id <= R15D) { // 32-bit extended
        *needs_rex = true;
        return encoding;
    }
    if (reg.id >= R8 && reg.id <= R15) { // 64-bit extended
        *needs_rex = true;
        return encoding;
    }
    
    return encoding;
}

//=============================================================================
// Instruction Encoding Functions
//=============================================================================

int encode_mov_instruction(instruction_t *inst, uint8_t *buffer, size_t *length) {
    if (!inst || !buffer || !length || inst->operand_count != 2) {
        return -1;
    }
    
    operand_t *dst = &inst->operands[0];
    operand_t *src = &inst->operands[1];
    
    size_t pos = 0;
    bool needs_rex = false;
    bool rex_w = false, rex_r = false, rex_x = false, rex_b = false;
    
    // Determine REX prefix requirements
    if (strstr(inst->mnemonic, "movq") != NULL) {
        rex_w = true; // 64-bit operation
        needs_rex = true;
    }
    
    // Handle MOV r64, imm64 (special case)
    if (dst->type == OPERAND_REGISTER && src->type == OPERAND_IMMEDIATE) {
        bool reg_needs_rex;
        int reg_encoding = get_register_encoding(dst->value.reg, &reg_needs_rex);
        
        if (reg_needs_rex) {
            rex_b = true;
            needs_rex = true;
        }
        
        // Add REX prefix if needed
        if (needs_rex) {
            buffer[pos++] = encode_rex_prefix(rex_w, rex_r, rex_x, rex_b);
        }
        
        // MOV r64, imm64: 0xB8 + register
        buffer[pos++] = 0xB8 + reg_encoding;
        
        // Add immediate value (8 bytes for 64-bit)
        int64_t imm = src->value.immediate;
        for (int i = 0; i < 8; i++) {
            buffer[pos++] = (imm >> (i * 8)) & 0xFF;
        }
        
        *length = pos;
        return 0;
    }
    
    // Handle MOV r/m, r (general case)
    if (dst->type == OPERAND_REGISTER && src->type == OPERAND_REGISTER) {
        bool dst_needs_rex, src_needs_rex;
        int dst_encoding = get_register_encoding(dst->value.reg, &dst_needs_rex);
        int src_encoding = get_register_encoding(src->value.reg, &src_needs_rex);
        
        if (dst_needs_rex) rex_b = true;
        if (src_needs_rex) rex_r = true;
        if (dst_needs_rex || src_needs_rex) needs_rex = true;
        
        // Add REX prefix if needed
        if (needs_rex) {
            buffer[pos++] = encode_rex_prefix(rex_w, rex_r, rex_x, rex_b);
        }
        
        // MOV r/m, r: 0x89
        buffer[pos++] = 0x89;
        
        // ModR/M byte: mod=11 (register-register), reg=source, r/m=destination
        buffer[pos++] = encode_modrm(3, src_encoding, dst_encoding);
        
        *length = pos;
        return 0;
    }
    
    return -1; // Unsupported operand combination
}

int encode_arithmetic_instruction(instruction_t *inst, uint8_t *buffer, size_t *length) {
    if (!inst || !buffer || !length || inst->operand_count != 2) {
        return -1;
    }
    
    // Find instruction in encoding table
    for (int i = 0; instruction_encodings[i].mnemonic != NULL; i++) {
        if (strcmp(inst->mnemonic, instruction_encodings[i].mnemonic) == 0) {
            const x86_64_instruction_encoding_t *enc = &instruction_encodings[i];
            
            operand_t *dst = &inst->operands[0];
            operand_t *src = &inst->operands[1];
            
            if (dst->type == OPERAND_REGISTER && src->type == OPERAND_REGISTER) {
                size_t pos = 0;
                bool needs_rex = false;
                bool rex_w = enc->needs_rex_w;
                bool rex_r = false, rex_x = false, rex_b = false;
                
                bool dst_needs_rex, src_needs_rex;
                int dst_encoding = get_register_encoding(dst->value.reg, &dst_needs_rex);
                int src_encoding = get_register_encoding(src->value.reg, &src_needs_rex);
                
                if (dst_needs_rex) rex_b = true;
                if (src_needs_rex) rex_r = true;
                if (dst_needs_rex || src_needs_rex || rex_w) needs_rex = true;
                
                // Add REX prefix if needed
                if (needs_rex) {
                    buffer[pos++] = encode_rex_prefix(rex_w, rex_r, rex_x, rex_b);
                }
                
                // Add opcode
                for (int j = 0; j < enc->opcode_length; j++) {
                    buffer[pos++] = enc->opcode[j];
                }
                
                // Add ModR/M byte if needed
                if (enc->needs_modrm) {
                    buffer[pos++] = encode_modrm(3, src_encoding, dst_encoding);
                }
                
                *length = pos;
                return 0;
            }
        }
    }
    
    return -1;
}

int encode_simple_instruction(instruction_t *inst, uint8_t *buffer, size_t *length) {
    if (!inst || !buffer || !length) {
        return -1;
    }
    
    // Handle simple instructions with no operands
    for (int i = 0; instruction_encodings[i].mnemonic != NULL; i++) {
        if (strcmp(inst->mnemonic, instruction_encodings[i].mnemonic) == 0) {
            const x86_64_instruction_encoding_t *enc = &instruction_encodings[i];
            
            if (enc->operand_order == 2) { // Special encoding
                size_t pos = 0;
                
                // Add opcode bytes
                for (int j = 0; j < enc->opcode_length; j++) {
                    buffer[pos++] = enc->opcode[j];
                }
                
                *length = pos;
                return 0;
            }
        }
    }
    
    return -1;
}

//=============================================================================
// Main Instruction Encoding Function
//=============================================================================

int x86_64_encode_instruction_full(instruction_t *inst, uint8_t *buffer, size_t *length) {
    if (!inst || !buffer || !length) {
        return -1;
    }
    
    // Route to appropriate encoding function based on instruction type
    if (strstr(inst->mnemonic, "mov") != NULL) {
        return encode_mov_instruction(inst, buffer, length);
    }
    
    if (strcmp(inst->mnemonic, "add") == 0 || 
        strcmp(inst->mnemonic, "addq") == 0 ||
        strcmp(inst->mnemonic, "sub") == 0 || 
        strcmp(inst->mnemonic, "subq") == 0) {
        return encode_arithmetic_instruction(inst, buffer, length);
    }
    
    if (strcmp(inst->mnemonic, "syscall") == 0 ||
        strcmp(inst->mnemonic, "nop") == 0 ||
        strcmp(inst->mnemonic, "ret") == 0) {
        return encode_simple_instruction(inst, buffer, length);
    }
    
    return -1; // Instruction not supported
}
