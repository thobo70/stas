#ifndef X86_64_H
#define X86_64_H

#include "../arch_interface.h"

// x86-64 specific register definitions
typedef enum {
    // 8-bit registers
    AL, CL, DL, BL, AH, CH, DH, BH,
    SPL, BPL, SIL, DIL,
    R8B, R9B, R10B, R11B, R12B, R13B, R14B, R15B,
    
    // 16-bit registers
    AX, CX, DX, BX, SP, BP, SI, DI,
    R8W, R9W, R10W, R11W, R12W, R13W, R14W, R15W,
    
    // 32-bit registers
    EAX, ECX, EDX, EBX, ESP, EBP, ESI, EDI,
    R8D, R9D, R10D, R11D, R12D, R13D, R14D, R15D,
    
    // 64-bit registers
    RAX, RCX, RDX, RBX, RSP, RBP, RSI, RDI,
    R8, R9, R10, R11, R12, R13, R14, R15,
    
    // Special registers
    RIP, RFLAGS
} x86_64_register_id_t;

// x86-64 instruction prefixes
typedef enum {
    PREFIX_NONE = 0x00,
    PREFIX_LOCK = 0xF0,
    PREFIX_REPNE = 0xF2,
    PREFIX_REP = 0xF3,
    PREFIX_CS = 0x2E,
    PREFIX_SS = 0x36,
    PREFIX_DS = 0x3E,
    PREFIX_ES = 0x26,
    PREFIX_FS = 0x64,
    PREFIX_GS = 0x65,
    PREFIX_OPERAND_SIZE = 0x66,
    PREFIX_ADDRESS_SIZE = 0x67
} x86_64_prefix_t;

// x86-64 REX prefix
typedef struct {
    uint8_t w : 1;  // 64-bit operand size
    uint8_t r : 1;  // Extension of ModR/M reg field
    uint8_t x : 1;  // Extension of SIB index field
    uint8_t b : 1;  // Extension of ModR/M r/m field or SIB base field
    uint8_t prefix : 4;  // Always 0100 (0x4)
} rex_prefix_t;

// ModR/M byte
typedef struct {
    uint8_t rm : 3;   // R/M field
    uint8_t reg : 3;  // Reg field
    uint8_t mod : 2;  // Mod field
} modrm_byte_t;

// SIB byte
typedef struct {
    uint8_t base : 3;   // Base field
    uint8_t index : 3;  // Index field
    uint8_t scale : 2;  // Scale field
} sib_byte_t;

// x86-64 instruction encoding structure
typedef struct {
    uint8_t prefixes[4];     // Legacy prefixes
    uint8_t prefix_count;
    rex_prefix_t rex;        // REX prefix
    bool has_rex;
    uint8_t opcode[3];       // Opcode bytes
    uint8_t opcode_length;
    modrm_byte_t modrm;      // ModR/M byte
    bool has_modrm;
    sib_byte_t sib;          // SIB byte
    bool has_sib;
    int64_t displacement;    // Displacement
    uint8_t disp_size;       // Displacement size (0, 1, 2, 4, 8)
    int64_t immediate;       // Immediate value
    uint8_t imm_size;        // Immediate size (0, 1, 2, 4, 8)
} x86_64_encoding_t;

// Function declarations
arch_ops_t *x86_64_get_arch_ops(void);
int x86_64_init(void);
void x86_64_cleanup(void);
int x86_64_parse_instruction(const char *mnemonic, operand_t *operands, 
                           size_t operand_count, instruction_t *inst);
int x86_64_encode_instruction(instruction_t *inst, uint8_t *buffer, size_t *length);
int x86_64_parse_register(const char *reg_name, asm_register_t *reg);
bool x86_64_is_valid_register(asm_register_t reg);
const char *x86_64_get_register_name(asm_register_t reg);
int x86_64_parse_addressing(const char *addr_str, addressing_mode_t *mode);
bool x86_64_validate_addressing(addressing_mode_t *mode, instruction_t *inst);
int x86_64_handle_directive(const char *directive, const char *args);
size_t x86_64_get_instruction_size(instruction_t *inst);
size_t x86_64_get_alignment(section_type_t section);
bool x86_64_validate_instruction(instruction_t *inst);
bool x86_64_validate_operand_combination(const char *mnemonic, 
                                       operand_t *operands, 
                                       size_t operand_count);

#endif // X86_64_H
