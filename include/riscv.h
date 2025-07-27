#ifndef RISCV_H
#define RISCV_H

#include <stdint.h>
#include <stdbool.h>
#include "arch_interface.h"

// RISC-V register definitions
typedef enum {
    // Integer registers (x0-x31)
    RISCV_REG_X0 = 0,   // zero (always 0)
    RISCV_REG_X1,       // ra (return address)
    RISCV_REG_X2,       // sp (stack pointer)
    RISCV_REG_X3,       // gp (global pointer)
    RISCV_REG_X4,       // tp (thread pointer)
    RISCV_REG_X5,       // t0 (temporary)
    RISCV_REG_X6,       // t1
    RISCV_REG_X7,       // t2
    RISCV_REG_X8,       // s0/fp (saved/frame pointer)
    RISCV_REG_X9,       // s1 (saved)
    RISCV_REG_X10,      // a0 (argument/return value)
    RISCV_REG_X11,      // a1 (argument/return value)
    RISCV_REG_X12,      // a2 (argument)
    RISCV_REG_X13,      // a3
    RISCV_REG_X14,      // a4
    RISCV_REG_X15,      // a5
    RISCV_REG_X16,      // a6
    RISCV_REG_X17,      // a7
    RISCV_REG_X18,      // s2 (saved)
    RISCV_REG_X19,      // s3
    RISCV_REG_X20,      // s4
    RISCV_REG_X21,      // s5
    RISCV_REG_X22,      // s6
    RISCV_REG_X23,      // s7
    RISCV_REG_X24,      // s8
    RISCV_REG_X25,      // s9
    RISCV_REG_X26,      // s10
    RISCV_REG_X27,      // s11
    RISCV_REG_X28,      // t3 (temporary)
    RISCV_REG_X29,      // t4
    RISCV_REG_X30,      // t5
    RISCV_REG_X31,      // t6
    RISCV_REG_COUNT = 32
} riscv_register_t;

// RISC-V instruction formats
typedef enum {
    RISCV_FORMAT_R,     // Register format (add, sub, etc.)
    RISCV_FORMAT_I,     // Immediate format (addi, load, etc.)
    RISCV_FORMAT_S,     // Store format
    RISCV_FORMAT_B,     // Branch format
    RISCV_FORMAT_U,     // Upper immediate format
    RISCV_FORMAT_J      // Jump format
} riscv_instruction_format_t;

// RISC-V instruction opcodes (7-bit)
typedef enum {
    RISCV_OP_LOAD     = 0x03,
    RISCV_OP_IMM      = 0x13,
    RISCV_OP_AUIPC    = 0x17,
    RISCV_OP_STORE    = 0x23,
    RISCV_OP_REG      = 0x33,
    RISCV_OP_LUI      = 0x37,
    RISCV_OP_BRANCH   = 0x63,
    RISCV_OP_JALR     = 0x67,
    RISCV_OP_JAL      = 0x6F,
    RISCV_OP_SYSTEM   = 0x73
} riscv_opcode_t;

// RISC-V funct3 codes for different instruction types
typedef enum {
    // Arithmetic immediate (OP_IMM)
    RISCV_FUNCT3_ADDI   = 0x0,
    RISCV_FUNCT3_SLTI   = 0x2,
    RISCV_FUNCT3_SLTIU  = 0x3,
    RISCV_FUNCT3_XORI   = 0x4,
    RISCV_FUNCT3_ORI    = 0x6,
    RISCV_FUNCT3_ANDI   = 0x7,
    RISCV_FUNCT3_SLLI   = 0x1,
    RISCV_FUNCT3_SRLI   = 0x5,  // Also SRAI
    
    // Register operations (OP_REG)
    RISCV_FUNCT3_ADD    = 0x0,  // Also SUB
    RISCV_FUNCT3_SLL    = 0x1,
    RISCV_FUNCT3_SLT    = 0x2,
    RISCV_FUNCT3_SLTU   = 0x3,
    RISCV_FUNCT3_XOR    = 0x4,
    RISCV_FUNCT3_SRL    = 0x5,  // Also SRA
    RISCV_FUNCT3_OR     = 0x6,
    RISCV_FUNCT3_AND    = 0x7,
    
    // Load/Store
    RISCV_FUNCT3_LB     = 0x0,
    RISCV_FUNCT3_LH     = 0x1,
    RISCV_FUNCT3_LW     = 0x2,
    RISCV_FUNCT3_LD     = 0x3,
    RISCV_FUNCT3_LBU    = 0x4,
    RISCV_FUNCT3_LHU    = 0x5,
    RISCV_FUNCT3_LWU    = 0x6,
    RISCV_FUNCT3_SB     = 0x0,
    RISCV_FUNCT3_SH     = 0x1,
    RISCV_FUNCT3_SW     = 0x2,
    RISCV_FUNCT3_SD     = 0x3,
    
    // Branch
    RISCV_FUNCT3_BEQ    = 0x0,
    RISCV_FUNCT3_BNE    = 0x1,
    RISCV_FUNCT3_BLT    = 0x4,
    RISCV_FUNCT3_BGE    = 0x5,
    RISCV_FUNCT3_BLTU   = 0x6,
    RISCV_FUNCT3_BGEU   = 0x7
} riscv_funct3_t;

// RISC-V instruction structure
typedef struct {
    uint32_t opcode : 7;
    uint32_t rd : 5;
    uint32_t funct3 : 3;
    uint32_t rs1 : 5;
    uint32_t rs2 : 5;
    uint32_t funct7 : 7;
} riscv_r_instruction_t;

typedef struct {
    uint32_t opcode : 7;
    uint32_t rd : 5;
    uint32_t funct3 : 3;
    uint32_t rs1 : 5;
    int32_t imm : 12;
} riscv_i_instruction_t;

// RISC-V instruction information
typedef struct {
    const char *mnemonic;
    riscv_instruction_format_t format;
    riscv_opcode_t opcode;
    riscv_funct3_t funct3;
    uint8_t funct7;
    bool has_funct7;
} riscv_instruction_info_t;

// Function declarations
arch_ops_t *get_riscv_arch_ops(void);
bool riscv_init(void);
bool riscv_parse_register(const char *reg_str, riscv_register_t *reg);
bool riscv_encode_instruction(const char *mnemonic, operand_t *operands, int operand_count, 
                             uint8_t *buffer, size_t *size);
const riscv_instruction_info_t *riscv_find_instruction(const char *mnemonic);
uint32_t riscv_encode_r_type(riscv_opcode_t opcode, riscv_funct3_t funct3, uint8_t funct7,
                            riscv_register_t rd, riscv_register_t rs1, riscv_register_t rs2);
uint32_t riscv_encode_i_type(riscv_opcode_t opcode, riscv_funct3_t funct3,
                            riscv_register_t rd, riscv_register_t rs1, int32_t imm);
uint32_t riscv_encode_s_type(riscv_opcode_t opcode, riscv_funct3_t funct3,
                            riscv_register_t rs1, riscv_register_t rs2, int32_t imm);
uint32_t riscv_encode_b_type(riscv_opcode_t opcode, riscv_funct3_t funct3,
                            riscv_register_t rs1, riscv_register_t rs2, int32_t imm);
uint32_t riscv_encode_u_type(riscv_opcode_t opcode, riscv_register_t rd, int32_t imm);
uint32_t riscv_encode_j_type(riscv_opcode_t opcode, riscv_register_t rd, int32_t imm);

// Architecture operations
arch_ops_t *get_riscv_arch_ops(void);

#endif // RISCV_H
