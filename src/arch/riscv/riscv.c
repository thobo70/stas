#define _GNU_SOURCE  // For strdup
#include "riscv.h"
#include "arch_interface.h"
#include "parser.h"
#include "utils.h"
#include <string.h>
#include <stdlib.h>
#include <stdio.h>

// RISC-V instruction table
static const riscv_instruction_info_t riscv_instructions[] = {
    // Arithmetic immediate instructions
    {"addi",  RISCV_FORMAT_I, RISCV_OP_IMM, RISCV_FUNCT3_ADDI, 0, false},
    {"slti",  RISCV_FORMAT_I, RISCV_OP_IMM, RISCV_FUNCT3_SLTI, 0, false},
    {"sltiu", RISCV_FORMAT_I, RISCV_OP_IMM, RISCV_FUNCT3_SLTIU, 0, false},
    {"xori",  RISCV_FORMAT_I, RISCV_OP_IMM, RISCV_FUNCT3_XORI, 0, false},
    {"ori",   RISCV_FORMAT_I, RISCV_OP_IMM, RISCV_FUNCT3_ORI, 0, false},
    {"andi",  RISCV_FORMAT_I, RISCV_OP_IMM, RISCV_FUNCT3_ANDI, 0, false},
    {"slli",  RISCV_FORMAT_I, RISCV_OP_IMM, RISCV_FUNCT3_SLLI, 0x00, true},
    {"srli",  RISCV_FORMAT_I, RISCV_OP_IMM, RISCV_FUNCT3_SRLI, 0x00, true},
    {"srai",  RISCV_FORMAT_I, RISCV_OP_IMM, RISCV_FUNCT3_SRLI, 0x20, true},
    
    // Register arithmetic instructions
    {"add",   RISCV_FORMAT_R, RISCV_OP_REG, RISCV_FUNCT3_ADD, 0x00, true},
    {"sub",   RISCV_FORMAT_R, RISCV_OP_REG, RISCV_FUNCT3_ADD, 0x20, true},
    {"sll",   RISCV_FORMAT_R, RISCV_OP_REG, RISCV_FUNCT3_SLL, 0x00, true},
    {"slt",   RISCV_FORMAT_R, RISCV_OP_REG, RISCV_FUNCT3_SLT, 0x00, true},
    {"sltu",  RISCV_FORMAT_R, RISCV_OP_REG, RISCV_FUNCT3_SLTU, 0x00, true},
    {"xor",   RISCV_FORMAT_R, RISCV_OP_REG, RISCV_FUNCT3_XOR, 0x00, true},
    {"srl",   RISCV_FORMAT_R, RISCV_OP_REG, RISCV_FUNCT3_SRL, 0x00, true},
    {"sra",   RISCV_FORMAT_R, RISCV_OP_REG, RISCV_FUNCT3_SRL, 0x20, true},
    {"or",    RISCV_FORMAT_R, RISCV_OP_REG, RISCV_FUNCT3_OR, 0x00, true},
    {"and",   RISCV_FORMAT_R, RISCV_OP_REG, RISCV_FUNCT3_AND, 0x00, true},
    
    // Load instructions
    {"lb",    RISCV_FORMAT_I, RISCV_OP_LOAD, RISCV_FUNCT3_LB, 0, false},
    {"lh",    RISCV_FORMAT_I, RISCV_OP_LOAD, RISCV_FUNCT3_LH, 0, false},
    {"lw",    RISCV_FORMAT_I, RISCV_OP_LOAD, RISCV_FUNCT3_LW, 0, false},
    {"ld",    RISCV_FORMAT_I, RISCV_OP_LOAD, RISCV_FUNCT3_LD, 0, false},
    {"lbu",   RISCV_FORMAT_I, RISCV_OP_LOAD, RISCV_FUNCT3_LBU, 0, false},
    {"lhu",   RISCV_FORMAT_I, RISCV_OP_LOAD, RISCV_FUNCT3_LHU, 0, false},
    {"lwu",   RISCV_FORMAT_I, RISCV_OP_LOAD, RISCV_FUNCT3_LWU, 0, false},
    
    // Store instructions
    {"sb",    RISCV_FORMAT_S, RISCV_OP_STORE, RISCV_FUNCT3_SB, 0, false},
    {"sh",    RISCV_FORMAT_S, RISCV_OP_STORE, RISCV_FUNCT3_SH, 0, false},
    {"sw",    RISCV_FORMAT_S, RISCV_OP_STORE, RISCV_FUNCT3_SW, 0, false},
    {"sd",    RISCV_FORMAT_S, RISCV_OP_STORE, RISCV_FUNCT3_SD, 0, false},
    
    // Branch instructions
    {"beq",   RISCV_FORMAT_B, RISCV_OP_BRANCH, RISCV_FUNCT3_BEQ, 0, false},
    {"bne",   RISCV_FORMAT_B, RISCV_OP_BRANCH, RISCV_FUNCT3_BNE, 0, false},
    {"blt",   RISCV_FORMAT_B, RISCV_OP_BRANCH, RISCV_FUNCT3_BLT, 0, false},
    {"bge",   RISCV_FORMAT_B, RISCV_OP_BRANCH, RISCV_FUNCT3_BGE, 0, false},
    {"bltu",  RISCV_FORMAT_B, RISCV_OP_BRANCH, RISCV_FUNCT3_BLTU, 0, false},
    {"bgeu",  RISCV_FORMAT_B, RISCV_OP_BRANCH, RISCV_FUNCT3_BGEU, 0, false},
    
    // Jump instructions
    {"jal",   RISCV_FORMAT_J, RISCV_OP_JAL, 0, 0, false},
    {"jalr",  RISCV_FORMAT_I, RISCV_OP_JALR, 0, 0, false},
    
    // Upper immediate instructions
    {"lui",   RISCV_FORMAT_U, RISCV_OP_LUI, 0, 0, false},
    {"auipc", RISCV_FORMAT_U, RISCV_OP_AUIPC, 0, 0, false},
    
    // System instructions (basic)
    {"ecall", RISCV_FORMAT_I, RISCV_OP_SYSTEM, 0, 0, false},
    {"ebreak", RISCV_FORMAT_I, RISCV_OP_SYSTEM, 0, 0, false}
};

static const int riscv_instruction_count = sizeof(riscv_instructions) / sizeof(riscv_instructions[0]);

// Register name to register mapping
static const struct {
    const char *name;
    riscv_register_t reg;
} riscv_register_names[] = {
    // Numeric register names
    {"x0", RISCV_REG_X0}, {"x1", RISCV_REG_X1}, {"x2", RISCV_REG_X2}, {"x3", RISCV_REG_X3},
    {"x4", RISCV_REG_X4}, {"x5", RISCV_REG_X5}, {"x6", RISCV_REG_X6}, {"x7", RISCV_REG_X7},
    {"x8", RISCV_REG_X8}, {"x9", RISCV_REG_X9}, {"x10", RISCV_REG_X10}, {"x11", RISCV_REG_X11},
    {"x12", RISCV_REG_X12}, {"x13", RISCV_REG_X13}, {"x14", RISCV_REG_X14}, {"x15", RISCV_REG_X15},
    {"x16", RISCV_REG_X16}, {"x17", RISCV_REG_X17}, {"x18", RISCV_REG_X18}, {"x19", RISCV_REG_X19},
    {"x20", RISCV_REG_X20}, {"x21", RISCV_REG_X21}, {"x22", RISCV_REG_X22}, {"x23", RISCV_REG_X23},
    {"x24", RISCV_REG_X24}, {"x25", RISCV_REG_X25}, {"x26", RISCV_REG_X26}, {"x27", RISCV_REG_X27},
    {"x28", RISCV_REG_X28}, {"x29", RISCV_REG_X29}, {"x30", RISCV_REG_X30}, {"x31", RISCV_REG_X31},
    
    // ABI register names
    {"zero", RISCV_REG_X0}, {"ra", RISCV_REG_X1}, {"sp", RISCV_REG_X2}, {"gp", RISCV_REG_X3},
    {"tp", RISCV_REG_X4}, {"t0", RISCV_REG_X5}, {"t1", RISCV_REG_X6}, {"t2", RISCV_REG_X7},
    {"s0", RISCV_REG_X8}, {"fp", RISCV_REG_X8}, {"s1", RISCV_REG_X9},
    {"a0", RISCV_REG_X10}, {"a1", RISCV_REG_X11}, {"a2", RISCV_REG_X12}, {"a3", RISCV_REG_X13},
    {"a4", RISCV_REG_X14}, {"a5", RISCV_REG_X15}, {"a6", RISCV_REG_X16}, {"a7", RISCV_REG_X17},
    {"s2", RISCV_REG_X18}, {"s3", RISCV_REG_X19}, {"s4", RISCV_REG_X20}, {"s5", RISCV_REG_X21},
    {"s6", RISCV_REG_X22}, {"s7", RISCV_REG_X23}, {"s8", RISCV_REG_X24}, {"s9", RISCV_REG_X25},
    {"s10", RISCV_REG_X26}, {"s11", RISCV_REG_X27}, {"t3", RISCV_REG_X28}, {"t4", RISCV_REG_X29},
    {"t5", RISCV_REG_X30}, {"t6", RISCV_REG_X31}
};

static const int riscv_register_count = sizeof(riscv_register_names) / sizeof(riscv_register_names[0]);

// Forward declarations for interface functions
static int riscv_init_impl(void);
static int riscv_parse_instruction_impl(const char *mnemonic, operand_t *operands, 
                                       size_t operand_count, instruction_t *inst);
static int riscv_encode_instruction_impl(instruction_t *inst, uint8_t *buffer, size_t *length);
static int riscv_parse_register_impl(const char *reg_name, asm_register_t *reg);
static bool riscv_is_valid_register(asm_register_t reg);
static const char *riscv_get_register_name(asm_register_t reg);

int riscv_init_impl(void) {
    // RISC-V initialization
    return 0; // Success
}

int riscv_parse_register_impl(const char *reg_name, asm_register_t *reg) {
    if (!reg_name || !reg) {
        return -1;
    }
    
    // Remove % prefix if present
    if (reg_name[0] == '%') {
        reg_name++;
    }
    
    // Search for register name
    for (int i = 0; i < riscv_register_count; i++) {
        if (strcmp(reg_name, riscv_register_names[i].name) == 0) {
            reg->id = riscv_register_names[i].reg;
            reg->name = strdup(riscv_register_names[i].name);
            reg->size = 8; // 64-bit RISC-V
            reg->encoding = riscv_register_names[i].reg;
            return 0; // Success
        }
    }
    
    return -1; // Not found
}

const riscv_instruction_info_t *riscv_find_instruction(const char *mnemonic) {
    if (!mnemonic) {
        return NULL;
    }
    
    for (int i = 0; i < riscv_instruction_count; i++) {
        if (strcmp(mnemonic, riscv_instructions[i].mnemonic) == 0) {
            return &riscv_instructions[i];
        }
    }
    
    return NULL;
}

uint32_t riscv_encode_r_type(riscv_opcode_t opcode, riscv_funct3_t funct3, uint8_t funct7,
                            riscv_register_t rd, riscv_register_t rs1, riscv_register_t rs2) {
    uint32_t instruction = 0;
    instruction |= (opcode & 0x7F);
    instruction |= ((rd & 0x1F) << 7);
    instruction |= ((funct3 & 0x7) << 12);
    instruction |= ((rs1 & 0x1F) << 15);
    instruction |= ((rs2 & 0x1F) << 20);
    instruction |= ((funct7 & 0x7F) << 25);
    return instruction;
}

uint32_t riscv_encode_i_type(riscv_opcode_t opcode, riscv_funct3_t funct3,
                            riscv_register_t rd, riscv_register_t rs1, int32_t imm) {
    uint32_t instruction = 0;
    instruction |= (opcode & 0x7F);
    instruction |= ((rd & 0x1F) << 7);
    instruction |= ((funct3 & 0x7) << 12);
    instruction |= ((rs1 & 0x1F) << 15);
    instruction |= ((imm & 0xFFF) << 20);
    return instruction;
}

uint32_t riscv_encode_s_type(riscv_opcode_t opcode, riscv_funct3_t funct3,
                            riscv_register_t rs1, riscv_register_t rs2, int32_t imm) {
    uint32_t instruction = 0;
    instruction |= (opcode & 0x7F);
    instruction |= ((imm & 0x1F) << 7);
    instruction |= ((funct3 & 0x7) << 12);
    instruction |= ((rs1 & 0x1F) << 15);
    instruction |= ((rs2 & 0x1F) << 20);
    instruction |= (((imm >> 5) & 0x7F) << 25);
    return instruction;
}

uint32_t riscv_encode_b_type(riscv_opcode_t opcode, riscv_funct3_t funct3,
                            riscv_register_t rs1, riscv_register_t rs2, int32_t imm) {
    uint32_t instruction = 0;
    instruction |= (opcode & 0x7F);
    instruction |= (((imm >> 11) & 0x1) << 7);
    instruction |= (((imm >> 1) & 0xF) << 8);
    instruction |= ((funct3 & 0x7) << 12);
    instruction |= ((rs1 & 0x1F) << 15);
    instruction |= ((rs2 & 0x1F) << 20);
    instruction |= (((imm >> 5) & 0x3F) << 25);
    instruction |= (((imm >> 12) & 0x1) << 31);
    return instruction;
}

uint32_t riscv_encode_u_type(riscv_opcode_t opcode, riscv_register_t rd, int32_t imm) {
    uint32_t instruction = 0;
    instruction |= (opcode & 0x7F);
    instruction |= ((rd & 0x1F) << 7);
    instruction |= ((imm & 0xFFFFF000));
    return instruction;
}

uint32_t riscv_encode_j_type(riscv_opcode_t opcode, riscv_register_t rd, int32_t imm) {
    uint32_t instruction = 0;
    instruction |= (opcode & 0x7F);
    instruction |= ((rd & 0x1F) << 7);
    instruction |= (((imm >> 12) & 0xFF) << 12);
    instruction |= (((imm >> 11) & 0x1) << 20);
    instruction |= (((imm >> 1) & 0x3FF) << 21);
    instruction |= (((imm >> 20) & 0x1) << 31);
    return instruction;
}

bool riscv_is_valid_register(asm_register_t reg) {
    return reg.id < RISCV_REG_COUNT;
}

const char *riscv_get_register_name(asm_register_t reg) {
    // Search for register by ID in the names table
    for (int i = 0; i < riscv_register_count; i++) {
        if (riscv_register_names[i].reg == reg.id) {
            return riscv_register_names[i].name;
        }
    }
    return NULL;
}

int riscv_parse_instruction_impl(const char *mnemonic, operand_t *operands, 
                                size_t operand_count, instruction_t *inst) {
    if (!mnemonic || !inst) {
        return -1;
    }
    
    // Find instruction info
    const riscv_instruction_info_t *info = riscv_find_instruction(mnemonic);
    if (!info) {
        return -1;
    }
    
    // Fill instruction structure
    inst->mnemonic = strdup(mnemonic);
    inst->operands = operands;
    inst->operand_count = operand_count;
    inst->encoding = NULL;
    inst->encoding_length = 0;
    
    return 0; // Success
}

int riscv_encode_instruction_impl(instruction_t *inst, uint8_t *buffer, size_t *length) {
    if (!inst || !buffer || !length) {
        return -1;
    }

    const riscv_instruction_info_t *info = riscv_find_instruction(inst->mnemonic);
    if (!info) {
        return -1;
    }

    uint32_t instruction = 0;
    operand_t *operands = inst->operands;
    size_t operand_count = inst->operand_count;    switch (info->format) {
        case RISCV_FORMAT_R: {
            // R-type: op rd, rs1, rs2
            if (operand_count != 3) return -1;
            
            // Check that all operands are registers
            if (operands[0].type != OPERAND_REGISTER ||
                operands[1].type != OPERAND_REGISTER ||
                operands[2].type != OPERAND_REGISTER) {
                return -1;
            }
            
            asm_register_t rd = operands[0].value.reg;
            asm_register_t rs1 = operands[1].value.reg;
            asm_register_t rs2 = operands[2].value.reg;
            
            instruction = riscv_encode_r_type(info->opcode, info->funct3, info->funct7, 
                                             rd.id, rs1.id, rs2.id);
            break;
        }
        
        case RISCV_FORMAT_I: {
            // I-type: op rd, rs1, imm
            if (operand_count != 3) {
                return -1;
            }
            
            // Check operand types
            if (operands[0].type != OPERAND_REGISTER ||
                operands[1].type != OPERAND_REGISTER ||
                operands[2].type != OPERAND_IMMEDIATE) {
                return -1;
            }
            
            asm_register_t rd = operands[0].value.reg;
            asm_register_t rs1 = operands[1].value.reg;
            int32_t imm = (int32_t)operands[2].value.immediate;
            
            instruction = riscv_encode_i_type(info->opcode, info->funct3, rd.id, rs1.id, imm);
            break;
        }
        
        case RISCV_FORMAT_U: {
            // U-type: op rd, imm
            if (operand_count != 2) return -1;
            
            // Check operand types
            if (operands[0].type != OPERAND_REGISTER ||
                operands[1].type != OPERAND_IMMEDIATE) {
                return -1;
            }
            
            asm_register_t rd = operands[0].value.reg;
            int32_t imm = (int32_t)operands[1].value.immediate;
            
            instruction = riscv_encode_u_type(info->opcode, rd.id, imm);
            break;
        }
        
        default:
            return -1;
    }
    
    // Write instruction as little-endian
    buffer[0] = instruction & 0xFF;
    buffer[1] = (instruction >> 8) & 0xFF;
    buffer[2] = (instruction >> 16) & 0xFF;
    buffer[3] = (instruction >> 24) & 0xFF;
    *length = 4;
    
    return 0; // Success
}

// RISC-V cleanup function
static void riscv_cleanup(void) {
    // No cleanup needed for RISC-V
}

// RISC-V addressing mode parsing
static int riscv_parse_addressing(const char *addr_str, addressing_mode_t *mode) {
    if (!addr_str || !mode) {
        return -1;
    }
    
    // RISC-V uses simple addressing modes
    mode->type = ADDR_DIRECT;
    mode->offset = 0;
    mode->scale = 1;
    mode->symbol = NULL;
    
    return 0;
}

// RISC-V addressing mode validation
static bool riscv_validate_addressing(addressing_mode_t *mode, instruction_t *inst) {
    if (!mode || !inst) {
        return false;
    }
    
    // Basic validation - RISC-V addressing is straightforward
    return true;
}

// RISC-V directive handler
static int riscv_handle_directive(const char *directive, const char *args) {
    if (!directive) {
        return -1;
    }
    
    // Suppress unused parameter warning
    (void)args;
    
    // No special directives for basic RISC-V implementation
    return 0;
}

// RISC-V instruction size
static size_t riscv_get_instruction_size(instruction_t *inst) {
    if (!inst) {
        return 0;
    }
    
    // All RISC-V instructions are 32-bit (4 bytes)
    return 4;
}

// RISC-V alignment requirements
static size_t riscv_get_alignment(section_type_t section) {
    switch (section) {
        case SECTION_TEXT:
            return 4; // 4-byte alignment for code
        case SECTION_DATA:
        case SECTION_RODATA:
            return 8; // 8-byte alignment for data
        case SECTION_BSS:
            return 8; // 8-byte alignment for BSS
        case SECTION_DEBUG:
            return 1; // No special alignment for debug
        default:
            return 4; // Default 4-byte alignment
    }
}

// RISC-V instruction validation
static bool riscv_validate_instruction(instruction_t *inst) {
    if (!inst) {
        return false;
    }
    
    // Basic instruction validation
    return true;
}

// RISC-V operand combination validation
static bool riscv_validate_operand_combination(const char *mnemonic, 
                                             operand_t *operands, 
                                             size_t operand_count) {
    if (!mnemonic) {
        return false;
    }
    
    // Suppress unused parameter warning
    (void)operands;
    
    // Basic operand validation - RISC-V instructions have at most 3 operands
    return operand_count <= 3;
}

// RISC-V architecture operations
static arch_ops_t riscv_ops = {
    .name = "riscv",
    .init = riscv_init_impl,
    .cleanup = riscv_cleanup,
    .parse_instruction = riscv_parse_instruction_impl,
    .encode_instruction = riscv_encode_instruction_impl,
    .parse_register = riscv_parse_register_impl,
    .is_valid_register = riscv_is_valid_register,
    .get_register_name = riscv_get_register_name,
    .parse_addressing = riscv_parse_addressing,
    .validate_addressing = riscv_validate_addressing,
    .handle_directive = riscv_handle_directive,
    .get_instruction_size = riscv_get_instruction_size,
    .get_alignment = riscv_get_alignment,
    .validate_instruction = riscv_validate_instruction,
    .validate_operand_combination = riscv_validate_operand_combination
};

arch_ops_t *get_riscv_arch_ops(void) {
    return &riscv_ops;
}

// Export function for dynamic loading
arch_ops_t *get_arch_ops(void) {
    return get_riscv_arch_ops();
}
