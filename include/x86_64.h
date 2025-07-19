#ifndef X86_64_H
#define X86_64_H

#include "arch_interface.h"
#include <stdint.h>
#include <stdbool.h>

//=============================================================================
// x86-64 Architecture Interface
//=============================================================================

// Main architecture interface functions
extern arch_ops_t x86_64_arch;

// Core x86-64 functions
int x86_64_init(void);
void x86_64_cleanup(void);
int x86_64_validate_instruction(instruction_t *inst);
int x86_64_encode_instruction(instruction_t *inst, uint8_t *buffer, size_t *length);

//=============================================================================
// x86-64 Register Definitions
//=============================================================================

// 64-bit general purpose registers
typedef enum {
    X86_64_RAX = 0, X86_64_RCX = 1, X86_64_RDX = 2, X86_64_RBX = 3,
    X86_64_RSP = 4, X86_64_RBP = 5, X86_64_RSI = 6, X86_64_RDI = 7,
    X86_64_R8  = 8, X86_64_R9  = 9, X86_64_R10 = 10, X86_64_R11 = 11,
    X86_64_R12 = 12, X86_64_R13 = 13, X86_64_R14 = 14, X86_64_R15 = 15
} x86_64_register_t;

// 32-bit register views
typedef enum {
    X86_64_EAX = 0, X86_64_ECX = 1, X86_64_EDX = 2, X86_64_EBX = 3,
    X86_64_ESP = 4, X86_64_EBP = 5, X86_64_ESI = 6, X86_64_EDI = 7,
    X86_64_R8D = 8, X86_64_R9D = 9, X86_64_R10D = 10, X86_64_R11D = 11,
    X86_64_R12D = 12, X86_64_R13D = 13, X86_64_R14D = 14, X86_64_R15D = 15
} x86_64_register32_t;

// 16-bit register views
typedef enum {
    X86_64_AX = 0, X86_64_CX = 1, X86_64_DX = 2, X86_64_BX = 3,
    X86_64_SP = 4, X86_64_BP = 5, X86_64_SI = 6, X86_64_DI = 7,
    X86_64_R8W = 8, X86_64_R9W = 9, X86_64_R10W = 10, X86_64_R11W = 11,
    X86_64_R12W = 12, X86_64_R13W = 13, X86_64_R14W = 14, X86_64_R15W = 15
} x86_64_register16_t;

// 8-bit register views
typedef enum {
    X86_64_AL = 0, X86_64_CL = 1, X86_64_DL = 2, X86_64_BL = 3,
    X86_64_SPL = 4, X86_64_BPL = 5, X86_64_SIL = 6, X86_64_DIL = 7,
    X86_64_R8B = 8, X86_64_R9B = 9, X86_64_R10B = 10, X86_64_R11B = 11,
    X86_64_R12B = 12, X86_64_R13B = 13, X86_64_R14B = 14, X86_64_R15B = 15
} x86_64_register8_t;

//=============================================================================
// x86-64 Core Functions (from existing implementation)
//=============================================================================

// Register parsing and validation
int parse_x86_64_register(const char *reg_name, uint8_t *reg_num, uint8_t *size);
bool is_x86_64_register(const char *reg_name);
const char* get_x86_64_register_name(uint8_t reg_num, uint8_t size);

// Instruction encoding
int encode_x86_64_mov_instruction(instruction_t *inst, uint8_t *buffer, size_t *length);
int encode_x86_64_arithmetic_instruction(instruction_t *inst, uint8_t *buffer, size_t *length);
int encode_x86_64_control_flow_instruction(instruction_t *inst, uint8_t *buffer, size_t *length);

// REX prefix handling
uint8_t calculate_rex_prefix(bool w, bool r, bool x, bool b);
bool needs_rex_prefix(instruction_t *inst);

// ModR/M and SIB encoding
uint8_t encode_modrm(uint8_t mod, uint8_t reg, uint8_t rm);
uint8_t encode_sib(uint8_t scale, uint8_t index, uint8_t base);

//=============================================================================
// Advanced x86-64 Instruction Support (Phase 6.1)
//=============================================================================

// XMM/YMM register types (redefine here for main interface)
typedef enum {
    XMM0 = 0, XMM1 = 1, XMM2 = 2, XMM3 = 3, XMM4 = 4, XMM5 = 5, XMM6 = 6, XMM7 = 7,
    XMM8 = 8, XMM9 = 9, XMM10 = 10, XMM11 = 11, XMM12 = 12, XMM13 = 13, XMM14 = 14, XMM15 = 15
} xmm_register_t;

typedef enum {
    YMM0 = 0, YMM1 = 1, YMM2 = 2, YMM3 = 3, YMM4 = 4, YMM5 = 5, YMM6 = 6, YMM7 = 7,
    YMM8 = 8, YMM9 = 9, YMM10 = 10, YMM11 = 11, YMM12 = 12, YMM13 = 13, YMM14 = 14, YMM15 = 15
} ymm_register_t;

// Advanced instruction encoding functions
int encode_sse_instruction(instruction_t *inst, uint8_t *buffer, size_t *length);
int encode_avx_instruction(instruction_t *inst, uint8_t *buffer, size_t *length);
int encode_advanced_control_instruction(instruction_t *inst, uint8_t *buffer, size_t *length);

// Register parsing for advanced instructions
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
// Instruction Categories
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

#endif // X86_64_H
