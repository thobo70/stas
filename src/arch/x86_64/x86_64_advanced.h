/*
 * x86-64 Advanced Instruction Sets
 * Phase 6.1: Extended x86 instruction support including SSE, AVX, and advanced features
 */

#ifndef X86_64_ADVANCED_H
#define X86_64_ADVANCED_H

#include "x86_64.h"

//=============================================================================
// Advanced Instruction Categories
//=============================================================================

// SSE (Streaming SIMD Extensions) Instructions
typedef struct {
    const char *mnemonic;
    uint8_t opcode[4];
    uint8_t opcode_length;
    uint8_t prefix;         // 0x66, 0xF2, 0xF3, or 0x00 for none
    bool needs_modrm;
    bool xmm_operands;      // Uses XMM registers
    const char *description;
} sse_instruction_t;

// AVX (Advanced Vector Extensions) Instructions  
typedef struct {
    const char *mnemonic;
    uint8_t vex_prefix[3];  // VEX prefix for AVX instructions
    uint8_t opcode;
    bool needs_modrm;
    bool three_operand;     // VEX allows 3-operand form
    const char *description;
} avx_instruction_t;

// Advanced Control Flow Instructions
typedef struct {
    const char *mnemonic;
    uint8_t opcode[2];
    uint8_t opcode_length;
    uint8_t condition_code; // For conditional moves/jumps
    bool needs_modrm;
    const char *description;
} advanced_control_instruction_t;

//=============================================================================
// XMM Register Support
//=============================================================================

typedef enum {
    XMM0 = 0, XMM1, XMM2, XMM3, XMM4, XMM5, XMM6, XMM7,
    XMM8, XMM9, XMM10, XMM11, XMM12, XMM13, XMM14, XMM15
} xmm_register_t;

typedef enum {
    YMM0 = 0, YMM1, YMM2, YMM3, YMM4, YMM5, YMM6, YMM7,
    YMM8, YMM9, YMM10, YMM11, YMM12, YMM13, YMM14, YMM15
} ymm_register_t;

//=============================================================================
// Function Declarations
//=============================================================================

// Advanced instruction encoding
int encode_sse_instruction(instruction_t *inst, uint8_t *buffer, size_t *length);
int encode_avx_instruction(instruction_t *inst, uint8_t *buffer, size_t *length);
int encode_advanced_control_instruction(instruction_t *inst, uint8_t *buffer, size_t *length);

// Register parsing for SIMD
int parse_xmm_register(const char *reg_name, xmm_register_t *reg);
int parse_ymm_register(const char *reg_name, ymm_register_t *reg);
bool is_xmm_register(const char *reg_name);
bool is_ymm_register(const char *reg_name);

// VEX prefix encoding
uint8_t encode_vex_prefix_2byte(uint8_t r, uint8_t vvvv, uint8_t l, uint8_t pp);
uint32_t encode_vex_prefix_3byte(uint8_t r, uint8_t x, uint8_t b, uint8_t m, 
                                uint8_t w, uint8_t vvvv, uint8_t l, uint8_t pp);

// Advanced addressing modes
int encode_rip_relative_addressing(int32_t displacement, uint8_t *buffer, size_t *pos);
int encode_sib_addressing(uint8_t scale, uint8_t index, uint8_t base, 
                         int32_t displacement, uint8_t *buffer, size_t *pos);

//=============================================================================
// Instruction Category Detection Functions
//=============================================================================

// Check instruction categories for advanced encoding dispatch
bool is_sse_instruction(const char *mnemonic);
bool is_avx_instruction(const char *mnemonic);
bool is_advanced_control_instruction(const char *mnemonic);
bool is_floating_point_instruction(const char *mnemonic);
bool is_simd_instruction(const char *mnemonic);

//=============================================================================
// Extended Instruction Set Support
//=============================================================================

// SSE instruction families
bool is_sse_scalar_instruction(const char *mnemonic);      // movss, addss, etc.
bool is_sse_packed_instruction(const char *mnemonic);     // movaps, addps, etc.
bool is_sse2_instruction(const char *mnemonic);           // movsd, addpd, etc.
bool is_sse_integer_instruction(const char *mnemonic);    // paddd, psubd, etc.

// AVX instruction families  
bool is_avx_scalar_instruction(const char *mnemonic);     // vaddss, vmulss, etc.
bool is_avx_packed_instruction(const char *mnemonic);     // vaddps, vmulps, etc.
bool is_avx2_instruction(const char *mnemonic);           // Enhanced AVX features

// Advanced control flow
bool is_conditional_move_instruction(const char *mnemonic);   // cmovcc
bool is_set_byte_instruction(const char *mnemonic);          // setcc
bool is_loop_instruction(const char *mnemonic);              // loop, loope, loopne

//=============================================================================
// Instruction Tables
//=============================================================================

// SSE floating-point instructions
extern const sse_instruction_t sse_instructions[];

// AVX vector instructions
extern const avx_instruction_t avx_instructions[];

// Advanced control flow instructions
extern const advanced_control_instruction_t advanced_control_instructions[];

#endif // X86_64_ADVANCED_H
