/*
 * x86-64 Advanced Instruction Implementation
 * Phase 6.1: SSE, AVX, and Advanced Control Flow Instructions
 */

#include "x86_64_advanced.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>

//=============================================================================
// SSE Instruction Table
//=============================================================================

const sse_instruction_t sse_instructions[] = {
    // Single-precision floating-point (scalar)
    {"movss",   {0x0F, 0x10, 0x00, 0x00}, 2, 0xF3, true,  true,  "Move scalar single-precision"},
    {"movss",   {0x0F, 0x11, 0x00, 0x00}, 2, 0xF3, true,  true,  "Move scalar single-precision (store)"},
    {"addss",   {0x0F, 0x58, 0x00, 0x00}, 2, 0xF3, true,  true,  "Add scalar single-precision"},
    {"subss",   {0x0F, 0x5C, 0x00, 0x00}, 2, 0xF3, true,  true,  "Subtract scalar single-precision"},
    {"mulss",   {0x0F, 0x59, 0x00, 0x00}, 2, 0xF3, true,  true,  "Multiply scalar single-precision"},
    {"divss",   {0x0F, 0x5E, 0x00, 0x00}, 2, 0xF3, true,  true,  "Divide scalar single-precision"},
    
    // Double-precision floating-point (scalar)
    {"movsd",   {0x0F, 0x10, 0x00, 0x00}, 2, 0xF2, true,  true,  "Move scalar double-precision"},
    {"movsd",   {0x0F, 0x11, 0x00, 0x00}, 2, 0xF2, true,  true,  "Move scalar double-precision (store)"},
    {"addsd",   {0x0F, 0x58, 0x00, 0x00}, 2, 0xF2, true,  true,  "Add scalar double-precision"},
    {"subsd",   {0x0F, 0x5C, 0x00, 0x00}, 2, 0xF2, true,  true,  "Subtract scalar double-precision"},
    {"mulsd",   {0x0F, 0x59, 0x00, 0x00}, 2, 0xF2, true,  true,  "Multiply scalar double-precision"},
    {"divsd",   {0x0F, 0x5E, 0x00, 0x00}, 2, 0xF2, true,  true,  "Divide scalar double-precision"},
    
    // Packed single-precision floating-point
    {"movaps",  {0x0F, 0x28, 0x00, 0x00}, 2, 0x00, true,  true,  "Move aligned packed single-precision"},
    {"movaps",  {0x0F, 0x29, 0x00, 0x00}, 2, 0x00, true,  true,  "Move aligned packed single-precision (store)"},
    {"addps",   {0x0F, 0x58, 0x00, 0x00}, 2, 0x00, true,  true,  "Add packed single-precision"},
    {"subps",   {0x0F, 0x5C, 0x00, 0x00}, 2, 0x00, true,  true,  "Subtract packed single-precision"},
    {"mulps",   {0x0F, 0x59, 0x00, 0x00}, 2, 0x00, true,  true,  "Multiply packed single-precision"},
    {"divps",   {0x0F, 0x5E, 0x00, 0x00}, 2, 0x00, true,  true,  "Divide packed single-precision"},
    
    // Packed double-precision floating-point
    {"movapd",  {0x0F, 0x28, 0x00, 0x00}, 2, 0x66, true,  true,  "Move aligned packed double-precision"},
    {"movapd",  {0x0F, 0x29, 0x00, 0x00}, 2, 0x66, true,  true,  "Move aligned packed double-precision (store)"},
    {"addpd",   {0x0F, 0x58, 0x00, 0x00}, 2, 0x66, true,  true,  "Add packed double-precision"},
    {"subpd",   {0x0F, 0x5C, 0x00, 0x00}, 2, 0x66, true,  true,  "Subtract packed double-precision"},
    {"mulpd",   {0x0F, 0x59, 0x00, 0x00}, 2, 0x66, true,  true,  "Multiply packed double-precision"},
    {"divpd",   {0x0F, 0x5E, 0x00, 0x00}, 2, 0x66, true,  true,  "Divide packed double-precision"},
    
    // Integer SIMD operations
    {"paddd",   {0x0F, 0xFE, 0x00, 0x00}, 2, 0x66, true,  true,  "Add packed doublewords"},
    {"psubd",   {0x0F, 0xFA, 0x00, 0x00}, 2, 0x66, true,  true,  "Subtract packed doublewords"},
    {"pmulld",  {0x0F, 0x38, 0x40, 0x00}, 3, 0x66, true,  true,  "Multiply packed doublewords"},
    
    {NULL, {0}, 0, 0, false, false, NULL} // Sentinel
};

//=============================================================================
// AVX Instruction Table  
//=============================================================================

const avx_instruction_t avx_instructions[] = {
    // AVX floating-point operations (VEX-encoded)
    {"vmovaps",  {0xC5, 0xF8, 0x28}, 0x28, true,  false, "Vector move aligned packed single"},
    {"vmovapd",  {0xC5, 0xF9, 0x28}, 0x28, true,  false, "Vector move aligned packed double"},
    {"vaddps",   {0xC5, 0xF8, 0x58}, 0x58, true,  true,  "Vector add packed single"},
    {"vaddpd",   {0xC5, 0xF9, 0x58}, 0x58, true,  true,  "Vector add packed double"},
    {"vsubps",   {0xC5, 0xF8, 0x5C}, 0x5C, true,  true,  "Vector subtract packed single"},
    {"vsubpd",   {0xC5, 0xF9, 0x5C}, 0x5C, true,  true,  "Vector subtract packed double"},
    {"vmulps",   {0xC5, 0xF8, 0x59}, 0x59, true,  true,  "Vector multiply packed single"},
    {"vmulpd",   {0xC5, 0xF9, 0x59}, 0x59, true,  true,  "Vector multiply packed double"},
    
    {NULL, {0}, 0, false, false, NULL} // Sentinel
};

//=============================================================================
// Advanced Control Flow Instructions
//=============================================================================

const advanced_control_instruction_t advanced_control_instructions[] = {
    // Conditional moves (CMOVcc)
    {"cmove",   {0x0F, 0x44}, 2, 0x4, true,  "Conditional move if equal"},
    {"cmovne",  {0x0F, 0x45}, 2, 0x5, true,  "Conditional move if not equal"},
    {"cmovl",   {0x0F, 0x4C}, 2, 0xC, true,  "Conditional move if less"},
    {"cmovge",  {0x0F, 0x4D}, 2, 0xD, true,  "Conditional move if greater or equal"},
    {"cmovle",  {0x0F, 0x4E}, 2, 0xE, true,  "Conditional move if less or equal"},
    {"cmovg",   {0x0F, 0x4F}, 2, 0xF, true,  "Conditional move if greater"},
    
    // Set byte on condition (SETcc)
    {"sete",    {0x0F, 0x94}, 2, 0x4, true,  "Set byte if equal"},
    {"setne",   {0x0F, 0x95}, 2, 0x5, true,  "Set byte if not equal"},
    {"setl",    {0x0F, 0x9C}, 2, 0xC, true,  "Set byte if less"},
    {"setge",   {0x0F, 0x9D}, 2, 0xD, true,  "Set byte if greater or equal"},
    {"setle",   {0x0F, 0x9E}, 2, 0xE, true,  "Set byte if less or equal"},
    {"setg",    {0x0F, 0x9F}, 2, 0xF, true,  "Set byte if greater"},
    
    // Loop instructions
    {"loop",    {0xE2, 0x00}, 1, 0x0, false, "Loop with RCX counter"},
    {"loope",   {0xE1, 0x00}, 1, 0x1, false, "Loop while equal"},
    {"loopne",  {0xE0, 0x00}, 1, 0x0, false, "Loop while not equal"},
    
    {NULL, {0}, 0, 0, false, NULL} // Sentinel
};

//=============================================================================
// XMM/YMM Register Parsing
//=============================================================================

int parse_xmm_register(const char *reg_name, xmm_register_t *reg) {
    if (!reg_name || !reg) return -1;
    
    // Convert to lowercase for comparison
    char lower_name[16];
    snprintf(lower_name, sizeof(lower_name), "%s", reg_name);
    for (char *p = lower_name; *p; p++) *p = tolower(*p);
    
    // Parse XMM registers
    if (strncmp(lower_name, "xmm", 3) == 0) {
        int reg_num = atoi(lower_name + 3);
        if (reg_num >= 0 && reg_num <= 15) {
            *reg = (xmm_register_t)reg_num;
            return 0;
        }
    }
    
    return -1; // Invalid register
}

int parse_ymm_register(const char *reg_name, ymm_register_t *reg) {
    if (!reg_name || !reg) return -1;
    
    // Convert to lowercase for comparison
    char lower_name[16];
    snprintf(lower_name, sizeof(lower_name), "%s", reg_name);
    for (char *p = lower_name; *p; p++) *p = tolower(*p);
    
    // Parse YMM registers
    if (strncmp(lower_name, "ymm", 3) == 0) {
        int reg_num = atoi(lower_name + 3);
        if (reg_num >= 0 && reg_num <= 15) {
            *reg = (ymm_register_t)reg_num;
            return 0;
        }
    }
    
    return -1; // Invalid register
}

bool is_xmm_register(const char *reg_name) {
    xmm_register_t dummy;
    return parse_xmm_register(reg_name, &dummy) == 0;
}

bool is_ymm_register(const char *reg_name) {
    ymm_register_t dummy;
    return parse_ymm_register(reg_name, &dummy) == 0;
}

//=============================================================================
// VEX Prefix Encoding
//=============================================================================

uint8_t encode_vex_prefix_2byte(uint8_t r, uint8_t vvvv, uint8_t l, uint8_t pp) {
    // 2-byte VEX prefix: C5 [R.vvvv.L.pp]
    uint8_t byte1 = 0xC5;
    uint8_t byte2 = ((~r & 1) << 7) | ((~vvvv & 0xF) << 3) | ((l & 1) << 2) | (pp & 3);
    return (byte1 << 8) | byte2; // Return as 16-bit value for convenience
}

uint32_t encode_vex_prefix_3byte(uint8_t r, uint8_t x, uint8_t b, uint8_t m, 
                                uint8_t w, uint8_t vvvv, uint8_t l, uint8_t pp) {
    // 3-byte VEX prefix: C4 [R.X.B.mmmmm] [W.vvvv.L.pp]
    uint8_t byte1 = 0xC4;
    uint8_t byte2 = ((~r & 1) << 7) | ((~x & 1) << 6) | ((~b & 1) << 5) | (m & 0x1F);
    uint8_t byte3 = ((w & 1) << 7) | ((~vvvv & 0xF) << 3) | ((l & 1) << 2) | (pp & 3);
    return (byte1 << 16) | (byte2 << 8) | byte3;
}

//=============================================================================
// SSE Instruction Encoding
//=============================================================================

int encode_sse_instruction(instruction_t *inst, uint8_t *buffer, size_t *length) {
    if (!inst || !buffer || !length) return -1;
    
    // Find instruction in SSE table
    const sse_instruction_t *sse_inst = NULL;
    for (int i = 0; sse_instructions[i].mnemonic != NULL; i++) {
        if (strcmp(inst->mnemonic, sse_instructions[i].mnemonic) == 0) {
            sse_inst = &sse_instructions[i];
            break;
        }
    }
    
    if (!sse_inst) return -1; // Instruction not found
    
    size_t pos = 0;
    
    // Add prefix if required
    if (sse_inst->prefix != 0x00) {
        buffer[pos++] = sse_inst->prefix;
    }
    
    // Add opcode bytes
    for (int i = 0; i < sse_inst->opcode_length; i++) {
        buffer[pos++] = sse_inst->opcode[i];
    }
    
    // Add ModR/M byte if required
    if (sse_inst->needs_modrm && inst->operand_count == 2) {
        if (inst->operands[0].type == OPERAND_REGISTER && 
            inst->operands[1].type == OPERAND_REGISTER) {
            
            // For simplicity, assume XMM register encoding
            // This would need enhancement for full operand support
            uint8_t dst_reg = 0; // Placeholder - would parse XMM register
            uint8_t src_reg = 1; // Placeholder - would parse XMM register
            
            buffer[pos++] = 0xC0 | (src_reg << 3) | dst_reg; // Register-register ModR/M
        }
    }
    
    *length = pos;
    return 0;
}

//=============================================================================
// AVX Instruction Encoding
//=============================================================================

int encode_avx_instruction(instruction_t *inst, uint8_t *buffer, size_t *length) {
    if (!inst || !buffer || !length) return -1;
    
    // Find instruction in AVX table
    const avx_instruction_t *avx_inst = NULL;
    for (int i = 0; avx_instructions[i].mnemonic != NULL; i++) {
        if (strcmp(inst->mnemonic, avx_instructions[i].mnemonic) == 0) {
            avx_inst = &avx_instructions[i];
            break;
        }
    }
    
    if (!avx_inst) return -1; // Instruction not found
    
    size_t pos = 0;
    
    // Add VEX prefix (simplified 2-byte form)
    buffer[pos++] = avx_inst->vex_prefix[0]; // 0xC5
    buffer[pos++] = avx_inst->vex_prefix[1]; // VEX byte 2
    
    // Add opcode
    buffer[pos++] = avx_inst->opcode;
    
    // Add ModR/M byte if required
    if (avx_inst->needs_modrm && inst->operand_count >= 2) {
        // Simplified ModR/M for demonstration
        buffer[pos++] = 0xC0; // Register-register
    }
    
    *length = pos;
    return 0;
}

//=============================================================================
// Advanced Control Flow Encoding
//=============================================================================

int encode_advanced_control_instruction(instruction_t *inst, uint8_t *buffer, size_t *length) {
    if (!inst || !buffer || !length) return -1;
    
    // Find instruction in advanced control table
    const advanced_control_instruction_t *ctrl_inst = NULL;
    for (int i = 0; advanced_control_instructions[i].mnemonic != NULL; i++) {
        if (strcmp(inst->mnemonic, advanced_control_instructions[i].mnemonic) == 0) {
            ctrl_inst = &advanced_control_instructions[i];
            break;
        }
    }
    
    if (!ctrl_inst) return -1; // Instruction not found
    
    size_t pos = 0;
    
    // Add opcode bytes
    for (int i = 0; i < ctrl_inst->opcode_length; i++) {
        buffer[pos++] = ctrl_inst->opcode[i];
    }
    
    // Add ModR/M byte if required
    if (ctrl_inst->needs_modrm && inst->operand_count >= 1) {
        // For conditional moves: reg, r/m
        if (inst->operands[0].type == OPERAND_REGISTER && 
            inst->operands[1].type == OPERAND_REGISTER) {
            uint8_t dst_reg = 0; // Would parse actual register
            uint8_t src_reg = 1; // Would parse actual register
            buffer[pos++] = 0xC0 | (dst_reg << 3) | src_reg;
        }
    }
    
    *length = pos;
    return 0;
}

//=============================================================================
// Advanced Addressing Modes
//=============================================================================

int encode_rip_relative_addressing(int32_t displacement, uint8_t *buffer, size_t *pos) {
    if (!buffer || !pos) return -1;
    
    // RIP-relative addressing uses ModR/M: mod=00, r/m=101 (RBP in 64-bit mode)
    // Displacement follows as 32-bit signed value
    
    // ModR/M byte for RIP-relative: [00][reg][101]
    // The reg field comes from the instruction
    uint8_t modrm = 0x05; // mod=00, r/m=101, reg field to be set by caller
    buffer[(*pos)++] = modrm;
    
    // Add 32-bit displacement (little-endian)
    buffer[(*pos)++] = displacement & 0xFF;
    buffer[(*pos)++] = (displacement >> 8) & 0xFF;
    buffer[(*pos)++] = (displacement >> 16) & 0xFF;
    buffer[(*pos)++] = (displacement >> 24) & 0xFF;
    
    return 0;
}

int encode_sib_addressing(uint8_t scale, uint8_t index, uint8_t base, 
                         int32_t displacement, uint8_t *buffer, size_t *pos) {
    if (!buffer || !pos) return -1;
    
    // SIB byte encoding: [scale][index][base]
    uint8_t scale_encoding = 0;
    switch (scale) {
        case 1: scale_encoding = 0; break;
        case 2: scale_encoding = 1; break;
        case 4: scale_encoding = 2; break;
        case 8: scale_encoding = 3; break;
        default: return -1; // Invalid scale
    }
    
    uint8_t sib = (scale_encoding << 6) | ((index & 7) << 3) | (base & 7);
    buffer[(*pos)++] = sib;
    
    // Add displacement if present
    if (displacement != 0) {
        // For simplicity, always use 32-bit displacement
        buffer[(*pos)++] = displacement & 0xFF;
        buffer[(*pos)++] = (displacement >> 8) & 0xFF;
        buffer[(*pos)++] = (displacement >> 16) & 0xFF;
        buffer[(*pos)++] = (displacement >> 24) & 0xFF;
    }
    
    return 0;
}

//=============================================================================
// Instruction Category Detection
//=============================================================================

bool is_sse_instruction(const char *mnemonic) {
    if (!mnemonic) return false;
    
    // Check against SSE instruction table
    for (int i = 0; sse_instructions[i].mnemonic != NULL; i++) {
        if (strcmp(mnemonic, sse_instructions[i].mnemonic) == 0) {
            return true;
        }
    }
    
    return false;
}

bool is_avx_instruction(const char *mnemonic) {
    if (!mnemonic) return false;
    
    // Check against AVX instruction table
    for (int i = 0; avx_instructions[i].mnemonic != NULL; i++) {
        if (strcmp(mnemonic, avx_instructions[i].mnemonic) == 0) {
            return true;
        }
    }
    
    return false;
}

bool is_advanced_control_instruction(const char *mnemonic) {
    if (!mnemonic) return false;
    
    // Check against advanced control instruction table
    for (int i = 0; advanced_control_instructions[i].mnemonic != NULL; i++) {
        if (strcmp(mnemonic, advanced_control_instructions[i].mnemonic) == 0) {
            return true;
        }
    }
    
    return false;
}

bool is_floating_point_instruction(const char *mnemonic) {
    if (!mnemonic) return false;
    
    // SSE/AVX floating-point patterns
    return (strstr(mnemonic, "ss") != NULL ||  // Single-precision scalar
            strstr(mnemonic, "sd") != NULL ||  // Double-precision scalar  
            strstr(mnemonic, "ps") != NULL ||  // Packed single-precision
            strstr(mnemonic, "pd") != NULL);   // Packed double-precision
}

bool is_simd_instruction(const char *mnemonic) {
    if (!mnemonic) return false;
    
    // SIMD instruction patterns
    return (is_sse_instruction(mnemonic) || 
            is_avx_instruction(mnemonic) ||
            strncmp(mnemonic, "p", 1) == 0);  // Packed integer instructions start with 'p'
}

//=============================================================================
// Extended Instruction Set Support
//=============================================================================

bool is_sse_scalar_instruction(const char *mnemonic) {
    if (!mnemonic) return false;
    
    // Scalar SSE instructions (work on single elements)
    return (strstr(mnemonic, "ss") != NULL ||  // Single-precision scalar
            strstr(mnemonic, "sd") != NULL);   // Double-precision scalar
}

bool is_sse_packed_instruction(const char *mnemonic) {
    if (!mnemonic) return false;
    
    // Packed SSE instructions (work on multiple elements)
    return (strstr(mnemonic, "ps") != NULL ||  // Packed single-precision
            strstr(mnemonic, "pd") != NULL);   // Packed double-precision
}

bool is_sse2_instruction(const char *mnemonic) {
    if (!mnemonic) return false;
    
    // SSE2 introduces double-precision floating-point
    return (strstr(mnemonic, "pd") != NULL ||  // Packed double-precision
            strstr(mnemonic, "sd") != NULL ||  // Scalar double-precision
            (strncmp(mnemonic, "p", 1) == 0 && strlen(mnemonic) > 4)); // Extended packed integer
}

bool is_sse_integer_instruction(const char *mnemonic) {
    if (!mnemonic) return false;
    
    // Packed integer instructions
    return (strncmp(mnemonic, "padd", 4) == 0 ||   // Packed add
            strncmp(mnemonic, "psub", 4) == 0 ||   // Packed subtract  
            strncmp(mnemonic, "pmul", 4) == 0 ||   // Packed multiply
            strncmp(mnemonic, "pcmp", 4) == 0);    // Packed compare
}

bool is_avx_scalar_instruction(const char *mnemonic) {
    if (!mnemonic) return false;
    
    // AVX scalar instructions (prefixed with 'v')
    return (strncmp(mnemonic, "v", 1) == 0 &&
            (strstr(mnemonic, "ss") != NULL ||  // vaddss, vmulss, etc.
             strstr(mnemonic, "sd") != NULL));  // vaddsd, vmulsd, etc.
}

bool is_avx_packed_instruction(const char *mnemonic) {
    if (!mnemonic) return false;
    
    // AVX packed instructions (prefixed with 'v')
    return (strncmp(mnemonic, "v", 1) == 0 &&
            (strstr(mnemonic, "ps") != NULL ||  // vaddps, vmulps, etc.
             strstr(mnemonic, "pd") != NULL));  // vaddpd, vmulpd, etc.
}

bool is_avx2_instruction(const char *mnemonic) {
    if (!mnemonic) return false;
    
    // AVX2 enhanced instructions (placeholder for future expansion)
    return (strncmp(mnemonic, "v", 1) == 0 && strlen(mnemonic) > 6);
}

bool is_conditional_move_instruction(const char *mnemonic) {
    if (!mnemonic) return false;
    
    // CMOVcc instructions
    return (strncmp(mnemonic, "cmov", 4) == 0);
}

bool is_set_byte_instruction(const char *mnemonic) {
    if (!mnemonic) return false;
    
    // SETcc instructions
    return (strncmp(mnemonic, "set", 3) == 0);
}

bool is_loop_instruction(const char *mnemonic) {
    if (!mnemonic) return false;
    
    // LOOP family instructions
    return (strcmp(mnemonic, "loop") == 0 ||
            strcmp(mnemonic, "loope") == 0 ||
            strcmp(mnemonic, "loopne") == 0);
}
