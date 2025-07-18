#ifndef X86_16_H
#define X86_16_H

#include "../arch_interface.h"

// x86-16 specific register definitions
typedef enum {
    // 8-bit registers
    AL_16, CL_16, DL_16, BL_16, AH_16, CH_16, DH_16, BH_16,
    
    // 16-bit registers
    AX_16, CX_16, DX_16, BX_16, SP_16, BP_16, SI_16, DI_16,
    
    // Segment registers
    ES_16, CS_16, SS_16, DS_16,
    
    // Special registers
    IP_16, FLAGS_16
} x86_16_register_id_t;

// x86-16 instruction prefixes
typedef enum {
    PREFIX_16_NONE = 0x00,
    PREFIX_16_LOCK = 0xF0,
    PREFIX_16_REPNE = 0xF2,
    PREFIX_16_REP = 0xF3,
    PREFIX_16_CS = 0x2E,
    PREFIX_16_SS = 0x36,
    PREFIX_16_DS = 0x3E,
    PREFIX_16_ES = 0x26,
    PREFIX_16_SEGMENT_OVERRIDE = 0x26  // Generic segment override
} x86_16_prefix_t;

// ModR/M byte (same as x86-32/64 but different context)
typedef struct {
    uint8_t rm : 3;   // R/M field
    uint8_t reg : 3;  // Reg field
    uint8_t mod : 2;  // Mod field
} x86_16_modrm_byte_t;

// x86-16 instruction encoding structure
typedef struct {
    uint8_t prefixes[2];     // Legacy prefixes (fewer than x86-64)
    uint8_t prefix_count;
    uint8_t opcode[2];       // Opcode bytes (simpler than x86-64)
    uint8_t opcode_length;
    x86_16_modrm_byte_t modrm; // ModR/M byte
    bool has_modrm;
    int16_t displacement;    // Displacement (16-bit max)
    uint8_t disp_size;       // Displacement size (0, 1, 2)
    int16_t immediate;       // Immediate value (16-bit max)
    uint8_t imm_size;        // Immediate size (0, 1, 2)
} x86_16_encoding_t;

// x86-16 addressing modes (16-bit specific)
typedef enum {
    ADDR_16_BX_SI,    // [BX + SI]
    ADDR_16_BX_DI,    // [BX + DI]
    ADDR_16_BP_SI,    // [BP + SI]
    ADDR_16_BP_DI,    // [BP + DI]
    ADDR_16_SI,       // [SI]
    ADDR_16_DI,       // [DI]
    ADDR_16_BP,       // [BP]
    ADDR_16_BX,       // [BX]
    ADDR_16_DIRECT    // Direct 16-bit address
} x86_16_addressing_t;

// Common x86-16 instruction opcodes
typedef enum {
    OP_16_MOV_REG_REG = 0x89,     // MOV r/m16, r16
    OP_16_MOV_REG_IMM = 0xB8,     // MOV r16, imm16
    OP_16_MOV_MEM_REG = 0x89,     // MOV m16, r16
    OP_16_MOV_REG_MEM = 0x8B,     // MOV r16, m16
    OP_16_ADD_REG_REG = 0x01,     // ADD r/m16, r16
    OP_16_ADD_REG_IMM = 0x81,     // ADD r/m16, imm16
    OP_16_SUB_REG_REG = 0x29,     // SUB r/m16, r16
    OP_16_SUB_REG_IMM = 0x81,     // SUB r/m16, imm16 (with reg=5)
    OP_16_CMP_REG_REG = 0x39,     // CMP r/m16, r16
    OP_16_CMP_REG_IMM = 0x81,     // CMP r/m16, imm16 (with reg=7)
    OP_16_JMP_REL = 0xE9,         // JMP rel16
    OP_16_JMP_SHORT = 0xEB,       // JMP rel8
    OP_16_CALL_REL = 0xE8,        // CALL rel16
    OP_16_RET = 0xC3,             // RET
    OP_16_INT = 0xCD,             // INT imm8
    OP_16_HLT = 0xF4,             // HLT
    OP_16_NOP = 0x90,             // NOP
    OP_16_PUSH_REG = 0x50,        // PUSH r16 (base + reg)
    OP_16_POP_REG = 0x58,         // POP r16 (base + reg)
    OP_16_JE = 0x74,              // JE rel8
    OP_16_JNE = 0x75,             // JNE rel8
    OP_16_JL = 0x7C,              // JL rel8
    OP_16_JG = 0x7F               // JG rel8
} x86_16_opcode_t;

// Function declarations
arch_ops_t *get_arch_ops_x86_16(void);
int x86_16_init(void);
void x86_16_cleanup(void);
int x86_16_parse_instruction(const char *mnemonic, operand_t *operands, 
                           size_t operand_count, instruction_t *inst);
int x86_16_encode_instruction(instruction_t *inst, uint8_t *buffer, size_t *length);
int x86_16_parse_register(const char *reg_name, asm_register_t *reg);
bool x86_16_is_valid_register(asm_register_t reg);
const char *x86_16_get_register_name(asm_register_t reg);
int x86_16_parse_addressing(const char *addr_str, addressing_mode_t *mode);
bool x86_16_validate_addressing(addressing_mode_t *mode, instruction_t *inst);
int x86_16_handle_directive(const char *directive, const char *args);
size_t x86_16_get_instruction_size(instruction_t *inst);
size_t x86_16_get_alignment(section_type_t section);
bool x86_16_validate_instruction(instruction_t *inst);
bool x86_16_validate_operand_combination(const char *mnemonic, 
                                       operand_t *operands, 
                                       size_t operand_count);

#endif // X86_16_H
