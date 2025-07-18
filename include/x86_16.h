#ifndef X86_16_H
#define X86_16_H

#include "arch_interface.h"

// x86-16 specific register definitions
typedef enum {
    // 16-bit general purpose registers
    X86_16_REG_AX, X86_16_REG_BX, X86_16_REG_CX, X86_16_REG_DX,
    X86_16_REG_SI, X86_16_REG_DI, X86_16_REG_BP, X86_16_REG_SP,
    
    // 8-bit general purpose registers (low byte)
    X86_16_REG_AL, X86_16_REG_BL, X86_16_REG_CL, X86_16_REG_DL,
    
    // 8-bit general purpose registers (high byte)
    X86_16_REG_AH, X86_16_REG_BH, X86_16_REG_CH, X86_16_REG_DH,
    
    // Segment registers
    X86_16_REG_CS, X86_16_REG_DS, X86_16_REG_ES, X86_16_REG_SS,
    
    // Index registers (16-bit addressing)
    X86_16_REG_IP,  // Instruction pointer
    
    // 80286+ additional segment registers
    X86_16_REG_FS, X86_16_REG_GS
} x86_16_register_t;

// x86-16 addressing modes
typedef enum {
    X86_16_ADDR_REGISTER,     // %ax
    X86_16_ADDR_IMMEDIATE,    // $0x1234
    X86_16_ADDR_DIRECT,       // 0x1234
    X86_16_ADDR_INDIRECT,     // (%bx)
    X86_16_ADDR_INDEXED,      // 4(%bx,%si)
    X86_16_ADDR_SEGMENT       // %ds:0x1234
} x86_16_addressing_mode_t;

// x86-16 instruction prefixes
typedef enum {
    X86_16_PREFIX_NONE    = 0x00,
    X86_16_PREFIX_LOCK    = 0xF0,
    X86_16_PREFIX_REPNE   = 0xF2,
    X86_16_PREFIX_REP     = 0xF3,
    X86_16_PREFIX_CS      = 0x2E,
    X86_16_PREFIX_SS      = 0x36,
    X86_16_PREFIX_DS      = 0x3E,
    X86_16_PREFIX_ES      = 0x26,
    X86_16_PREFIX_FS      = 0x64,  // 80286+
    X86_16_PREFIX_GS      = 0x65   // 80286+
} x86_16_prefix_t;

// x86-16 instruction format
typedef struct {
    x86_16_prefix_t prefix;
    uint8_t opcode;
    uint8_t modrm;
    uint8_t sib;       // Not used in 16-bit mode, but kept for compatibility
    bool has_modrm;
    bool has_sib;      // Always false for 16-bit
    uint8_t displacement_size;  // 0, 1, or 2 bytes
    uint8_t immediate_size;     // 0, 1, or 2 bytes
} x86_16_instruction_format_t;

// Common x86-16 instruction encodings
typedef enum {
    X86_16_OP_MOV_REG_REG   = 0x89,
    X86_16_OP_MOV_REG_MEM   = 0x8B,
    X86_16_OP_MOV_MEM_REG   = 0x89,
    X86_16_OP_MOV_IMM_REG   = 0xB8,  // + register encoding
    X86_16_OP_ADD_REG_REG   = 0x01,
    X86_16_OP_SUB_REG_REG   = 0x29,
    X86_16_OP_CMP_REG_REG   = 0x39,
    X86_16_OP_JMP_REL16     = 0xE9,
    X86_16_OP_JMP_REL8      = 0xEB,
    X86_16_OP_CALL_REL16    = 0xE8,
    X86_16_OP_RET           = 0xC3,
    X86_16_OP_PUSH_REG      = 0x50,  // + register encoding
    X86_16_OP_POP_REG       = 0x58,  // + register encoding
    X86_16_OP_INT           = 0xCD,
    X86_16_OP_NOP           = 0x90
} x86_16_opcodes_t;

// Architecture operations for x86-16
extern arch_ops_t x86_16_arch_ops;

// Function declarations
int x86_16_init(void);
void x86_16_cleanup(void);
int x86_16_parse_instruction(const char *mnemonic, operand_t *operands, 
                           size_t operand_count, instruction_t *inst);
int x86_16_encode_instruction(instruction_t *inst, uint8_t *buffer, size_t *length);
int x86_16_parse_register(const char *reg_name, register_t *reg);
bool x86_16_is_valid_register(register_t reg);
const char *x86_16_get_register_name(register_t reg);
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
