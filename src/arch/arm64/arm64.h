#ifndef ARM64_H
#define ARM64_H

#include "arch_interface.h"
#include <stdint.h>
#include <stdbool.h>

//=============================================================================
// ARM64 (AArch64) Architecture Interface
//=============================================================================

// Main architecture interface functions
extern arch_ops_t arm64_arch;

// Core ARM64 functions
int arm64_init(void);
void arm64_cleanup(void);
bool arm64_validate_instruction(instruction_t *inst);
int arm64_encode_instruction(instruction_t *inst, uint8_t *buffer, size_t *length);

//=============================================================================
// ARM64 Register Definitions
//=============================================================================

// 64-bit general purpose registers (X registers)
typedef enum {
    ARM64_X0 = 0,   ARM64_X1 = 1,   ARM64_X2 = 2,   ARM64_X3 = 3,
    ARM64_X4 = 4,   ARM64_X5 = 5,   ARM64_X6 = 6,   ARM64_X7 = 7,
    ARM64_X8 = 8,   ARM64_X9 = 9,   ARM64_X10 = 10, ARM64_X11 = 11,
    ARM64_X12 = 12, ARM64_X13 = 13, ARM64_X14 = 14, ARM64_X15 = 15,
    ARM64_X16 = 16, ARM64_X17 = 17, ARM64_X18 = 18, ARM64_X19 = 19,
    ARM64_X20 = 20, ARM64_X21 = 21, ARM64_X22 = 22, ARM64_X23 = 23,
    ARM64_X24 = 24, ARM64_X25 = 25, ARM64_X26 = 26, ARM64_X27 = 27,
    ARM64_X28 = 28, ARM64_X29 = 29, ARM64_X30 = 30, ARM64_XZR = 31
} arm64_x_register_t;

// 32-bit general purpose registers (W registers)
typedef enum {
    ARM64_W0 = 0,   ARM64_W1 = 1,   ARM64_W2 = 2,   ARM64_W3 = 3,
    ARM64_W4 = 4,   ARM64_W5 = 5,   ARM64_W6 = 6,   ARM64_W7 = 7,
    ARM64_W8 = 8,   ARM64_W9 = 9,   ARM64_W10 = 10, ARM64_W11 = 11,
    ARM64_W12 = 12, ARM64_W13 = 13, ARM64_W14 = 14, ARM64_W15 = 15,
    ARM64_W16 = 16, ARM64_W17 = 17, ARM64_W18 = 18, ARM64_W19 = 19,
    ARM64_W20 = 20, ARM64_W21 = 21, ARM64_W22 = 22, ARM64_W23 = 23,
    ARM64_W24 = 24, ARM64_W25 = 25, ARM64_W26 = 26, ARM64_W27 = 27,
    ARM64_W28 = 28, ARM64_W29 = 29, ARM64_W30 = 30, ARM64_WZR = 31
} arm64_w_register_t;

// Stack Pointer and special registers
typedef enum {
    ARM64_SP = 31,   // Stack Pointer
    ARM64_LR = 30,   // Link Register (X30)
    ARM64_FP = 29    // Frame Pointer (X29)
} arm64_special_register_t;

// SIMD and floating-point registers (V registers)
typedef enum {
    ARM64_V0 = 0,   ARM64_V1 = 1,   ARM64_V2 = 2,   ARM64_V3 = 3,
    ARM64_V4 = 4,   ARM64_V5 = 5,   ARM64_V6 = 6,   ARM64_V7 = 7,
    ARM64_V8 = 8,   ARM64_V9 = 9,   ARM64_V10 = 10, ARM64_V11 = 11,
    ARM64_V12 = 12, ARM64_V13 = 13, ARM64_V14 = 14, ARM64_V15 = 15,
    ARM64_V16 = 16, ARM64_V17 = 17, ARM64_V18 = 18, ARM64_V19 = 19,
    ARM64_V20 = 20, ARM64_V21 = 21, ARM64_V22 = 22, ARM64_V23 = 23,
    ARM64_V24 = 24, ARM64_V25 = 25, ARM64_V26 = 26, ARM64_V27 = 27,
    ARM64_V28 = 28, ARM64_V29 = 29, ARM64_V30 = 30, ARM64_V31 = 31
} arm64_v_register_t;

// Floating-point register views
typedef arm64_v_register_t arm64_s_register_t;  // 32-bit float (S0-S31)
typedef arm64_v_register_t arm64_d_register_t;  // 64-bit double (D0-D31)
typedef arm64_v_register_t arm64_q_register_t;  // 128-bit quad (Q0-Q31)

//=============================================================================
// ARM64 Instruction Formats
//=============================================================================

// ARM64 instruction encoding structure
typedef struct {
    uint32_t instruction;  // 32-bit ARM64 instruction word
    uint8_t format;        // Instruction format type
    uint8_t op0;          // Primary opcode field
    uint8_t op1;          // Secondary opcode field
    uint8_t op2;          // Tertiary opcode field
} arm64_instruction_encoding_t;

// ARM64 instruction formats
typedef enum {
    ARM64_FORMAT_UNKNOWN = 0,
    ARM64_FORMAT_DATA_PROCESSING_IMM,    // Data processing with immediate
    ARM64_FORMAT_DATA_PROCESSING_REG,    // Data processing with register
    ARM64_FORMAT_LOAD_STORE,             // Load/store instructions
    ARM64_FORMAT_BRANCH,                 // Branch instructions
    ARM64_FORMAT_SYSTEM,                 // System instructions
    ARM64_FORMAT_SIMD_FP                 // SIMD and floating-point
} arm64_instruction_format_t;

//=============================================================================
// ARM64 Instruction Tables
//=============================================================================

// ARM64 instruction definition
typedef struct {
    const char *mnemonic;
    uint32_t opcode_mask;     // Instruction template
    uint32_t opcode_value;    // Fixed bits
    arm64_instruction_format_t format;
    bool needs_rd;            // Requires destination register
    bool needs_rn;            // Requires first source register
    bool needs_rm;            // Requires second source register
    bool needs_imm;           // Requires immediate value
    const char *description;
} arm64_instruction_t;

//=============================================================================
// ARM64 Core Functions
//=============================================================================

// Register parsing and validation
int parse_arm64_register(const char *reg_name, uint8_t *reg_num, uint8_t *size);
bool is_arm64_register(const char *reg_name);
const char* get_arm64_register_name(uint8_t reg_num, uint8_t size);

// Instruction encoding
int encode_arm64_data_processing_instruction(instruction_t *inst, uint8_t *buffer, size_t *length);
int encode_arm64_load_store_instruction(instruction_t *inst, uint8_t *buffer, size_t *length);
int encode_arm64_branch_instruction(instruction_t *inst, uint8_t *buffer, size_t *length);
int encode_arm64_simd_fp_instruction(instruction_t *inst, uint8_t *buffer, size_t *length);

// ARM64-specific addressing
int encode_arm64_immediate(int64_t value, uint8_t *buffer, size_t pos);
int encode_arm64_offset_addressing(int32_t offset, uint8_t *buffer, size_t pos);

//=============================================================================
// ARM64 Instruction Categories
//=============================================================================

// Check instruction categories for encoding dispatch
bool is_arm64_data_processing_instruction(const char *mnemonic);
bool is_arm64_load_store_instruction(const char *mnemonic);
bool is_arm64_branch_instruction(const char *mnemonic);
bool is_arm64_simd_fp_instruction(const char *mnemonic);
bool is_arm64_system_instruction(const char *mnemonic);

//=============================================================================
// ARM64 Register Utilities
//=============================================================================

// Register type checking
bool is_arm64_x_register(const char *reg_name);     // X0-X31
bool is_arm64_w_register(const char *reg_name);     // W0-W31
bool is_arm64_v_register(const char *reg_name);     // V0-V31
bool is_arm64_s_register(const char *reg_name);     // S0-S31 (32-bit float)
bool is_arm64_d_register(const char *reg_name);     // D0-D31 (64-bit double)
bool is_arm64_q_register(const char *reg_name);     // Q0-Q31 (128-bit quad)

// Special register checking
bool is_arm64_stack_pointer(const char *reg_name);  // SP
bool is_arm64_zero_register(const char *reg_name);  // XZR, WZR

//=============================================================================
// ARM64 Addressing Modes
//=============================================================================

// ARM64 addressing mode types
typedef enum {
    ARM64_ADDR_BASE,           // [Xn]
    ARM64_ADDR_OFFSET,         // [Xn, #imm]
    ARM64_ADDR_PRE_INDEX,      // [Xn, #imm]!
    ARM64_ADDR_POST_INDEX,     // [Xn], #imm
    ARM64_ADDR_REGISTER,       // [Xn, Xm]
    ARM64_ADDR_EXTENDED        // [Xn, Xm, LSL #imm]
} arm64_addressing_mode_t;

// ARM64 addressing mode structure
typedef struct {
    arm64_addressing_mode_t mode;
    uint8_t base_reg;          // Base register (Xn)
    uint8_t offset_reg;        // Offset register (Xm) for register modes
    int32_t immediate;         // Immediate offset
    uint8_t shift_amount;      // Shift amount for extended modes
    bool writeback;            // Pre/post-index writeback
} arm64_addressing_t;

//=============================================================================
// ARM64 Instruction Families
//=============================================================================

// Data processing families
bool is_arm64_arithmetic_instruction(const char *mnemonic);    // ADD, SUB, etc.
bool is_arm64_logical_instruction(const char *mnemonic);       // AND, ORR, EOR
bool is_arm64_shift_instruction(const char *mnemonic);         // LSL, LSR, ASR
bool is_arm64_move_instruction(const char *mnemonic);          // MOV, MOVK, MOVZ

// Load/store families
bool is_arm64_load_instruction(const char *mnemonic);          // LDR, LDRB, LDRH
bool is_arm64_store_instruction(const char *mnemonic);         // STR, STRB, STRH
bool is_arm64_load_pair_instruction(const char *mnemonic);     // LDP
bool is_arm64_store_pair_instruction(const char *mnemonic);    // STP

// Branch families
bool is_arm64_unconditional_branch(const char *mnemonic);      // B, BR, BL
bool is_arm64_conditional_branch(const char *mnemonic);        // B.EQ, B.NE, etc.
bool is_arm64_compare_branch(const char *mnemonic);            // CBZ, CBNZ

#endif // ARM64_H
