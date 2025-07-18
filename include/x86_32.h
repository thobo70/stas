#ifndef X86_32_H
#define X86_32_H

#include "arch_interface.h"

// x86-32 specific register definitions
typedef enum {
    // 32-bit general purpose registers (IA-32)
    X86_32_REG_EAX, X86_32_REG_EBX, X86_32_REG_ECX, X86_32_REG_EDX,
    X86_32_REG_ESI, X86_32_REG_EDI, X86_32_REG_EBP, X86_32_REG_ESP,
    
    // 16-bit general purpose registers
    X86_32_REG_AX, X86_32_REG_BX, X86_32_REG_CX, X86_32_REG_DX,
    X86_32_REG_SI, X86_32_REG_DI, X86_32_REG_BP, X86_32_REG_SP,
    
    // 8-bit general purpose registers (low byte)
    X86_32_REG_AL, X86_32_REG_BL, X86_32_REG_CL, X86_32_REG_DL,
    
    // 8-bit general purpose registers (high byte)
    X86_32_REG_AH, X86_32_REG_BH, X86_32_REG_CH, X86_32_REG_DH,
    
    // Segment registers
    X86_32_REG_CS, X86_32_REG_DS, X86_32_REG_ES, X86_32_REG_SS,
    X86_32_REG_FS, X86_32_REG_GS,
    
    // Control registers
    X86_32_REG_CR0, X86_32_REG_CR1, X86_32_REG_CR2, X86_32_REG_CR3,
    X86_32_REG_CR4,
    
    // Debug registers
    X86_32_REG_DR0, X86_32_REG_DR1, X86_32_REG_DR2, X86_32_REG_DR3,
    X86_32_REG_DR6, X86_32_REG_DR7,
    
    // Test registers (386/486)
    X86_32_REG_TR6, X86_32_REG_TR7,
    
    // MMX registers (Pentium+)
    X86_32_REG_MM0, X86_32_REG_MM1, X86_32_REG_MM2, X86_32_REG_MM3,
    X86_32_REG_MM4, X86_32_REG_MM5, X86_32_REG_MM6, X86_32_REG_MM7,
    
    // SSE registers (Pentium III+)
    X86_32_REG_XMM0, X86_32_REG_XMM1, X86_32_REG_XMM2, X86_32_REG_XMM3,
    X86_32_REG_XMM4, X86_32_REG_XMM5, X86_32_REG_XMM6, X86_32_REG_XMM7,
    
    // Instruction and stack pointers
    X86_32_REG_EIP
} x86_32_register_t;

// x86-32 addressing modes
typedef enum {
    X86_32_ADDR_REGISTER,     // %eax
    X86_32_ADDR_IMMEDIATE,    // $0x12345678
    X86_32_ADDR_DIRECT,       // 0x12345678
    X86_32_ADDR_INDIRECT,     // (%eax)
    X86_32_ADDR_INDEXED,      // 8(%eax,%ebx,2)
    X86_32_ADDR_SEGMENT       // %ds:0x12345678
} x86_32_addressing_mode_t;

// x86-32 instruction prefixes
typedef enum {
    X86_32_PREFIX_NONE        = 0x00,
    X86_32_PREFIX_LOCK        = 0xF0,
    X86_32_PREFIX_REPNE       = 0xF2,
    X86_32_PREFIX_REP         = 0xF3,
    X86_32_PREFIX_CS          = 0x2E,
    X86_32_PREFIX_SS          = 0x36,
    X86_32_PREFIX_DS          = 0x3E,
    X86_32_PREFIX_ES          = 0x26,
    X86_32_PREFIX_FS          = 0x64,
    X86_32_PREFIX_GS          = 0x65,
    X86_32_PREFIX_OPERAND     = 0x66,  // Operand size override
    X86_32_PREFIX_ADDRESS     = 0x67   // Address size override
} x86_32_prefix_t;

// x86-32 instruction format with SIB support
typedef struct {
    x86_32_prefix_t prefix;
    uint8_t opcode;
    uint8_t modrm;
    uint8_t sib;
    bool has_modrm;
    bool has_sib;
    uint8_t displacement_size;  // 0, 1, or 4 bytes
    uint8_t immediate_size;     // 0, 1, 2, or 4 bytes
} x86_32_instruction_format_t;

// Common x86-32 instruction encodings
typedef enum {
    X86_32_OP_MOV_REG_REG   = 0x89,
    X86_32_OP_MOV_REG_MEM   = 0x8B,
    X86_32_OP_MOV_MEM_REG   = 0x89,
    X86_32_OP_MOV_IMM_REG   = 0xB8,  // + register encoding
    X86_32_OP_ADD_REG_REG   = 0x01,
    X86_32_OP_SUB_REG_REG   = 0x29,
    X86_32_OP_CMP_REG_REG   = 0x39,
    X86_32_OP_JMP_REL32     = 0xE9,
    X86_32_OP_JMP_REL8      = 0xEB,
    X86_32_OP_CALL_REL32    = 0xE8,
    X86_32_OP_RET           = 0xC3,
    X86_32_OP_PUSH_REG      = 0x50,  // + register encoding
    X86_32_OP_POP_REG       = 0x58,  // + register encoding
    X86_32_OP_PUSHAD        = 0x60,  // Push all 32-bit registers
    X86_32_OP_POPAD         = 0x61,  // Pop all 32-bit registers
    X86_32_OP_INT           = 0xCD,
    X86_32_OP_SYSENTER      = 0x0F34, // Fast system call (Pentium II+)
    X86_32_OP_SYSEXIT       = 0x0F35, // Fast system call return
    X86_32_OP_NOP           = 0x90
} x86_32_opcodes_t;

// x86-32 CPU feature levels
typedef enum {
    X86_32_CPU_386,          // 80386
    X86_32_CPU_486,          // 80486
    X86_32_CPU_PENTIUM,      // Pentium (P5)
    X86_32_CPU_PENTIUM_PRO,  // Pentium Pro (P6)
    X86_32_CPU_PENTIUM_MMX,  // Pentium with MMX
    X86_32_CPU_PENTIUM2,     // Pentium II
    X86_32_CPU_PENTIUM3,     // Pentium III (SSE)
    X86_32_CPU_PENTIUM4      // Pentium 4 (SSE2)
} x86_32_cpu_level_t;

// Architecture operations for x86-32
extern arch_ops_t x86_32_arch_ops;

// Function declarations
int x86_32_init(void);
void x86_32_cleanup(void);
int x86_32_parse_instruction(const char *mnemonic, operand_t *operands, 
                           size_t operand_count, instruction_t *inst);
int x86_32_encode_instruction(instruction_t *inst, uint8_t *buffer, size_t *length);
int x86_32_parse_register(const char *reg_name, register_t *reg);
bool x86_32_is_valid_register(register_t reg);
const char *x86_32_get_register_name(register_t reg);
int x86_32_parse_addressing(const char *addr_str, addressing_mode_t *mode);
bool x86_32_validate_addressing(addressing_mode_t *mode, instruction_t *inst);
int x86_32_handle_directive(const char *directive, const char *args);
size_t x86_32_get_instruction_size(instruction_t *inst);
size_t x86_32_get_alignment(section_type_t section);
bool x86_32_validate_instruction(instruction_t *inst);
bool x86_32_validate_operand_combination(const char *mnemonic, 
                                       operand_t *operands, 
                                       size_t operand_count);

// CPU feature detection
bool x86_32_supports_feature(x86_32_cpu_level_t min_level);
void x86_32_set_cpu_level(x86_32_cpu_level_t level);

#endif // X86_32_H
