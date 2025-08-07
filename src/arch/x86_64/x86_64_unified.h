/*
 * x86-64 Architecture Implementation
 * Single, comprehensive implementation following STAS Development Manifest
 * CPU-accurate instruction encoding with AT&T syntax compliance
 */

#ifndef X86_64_H
#define X86_64_H

#include "../../include/arch_interface.h"
#include <stdint.h>
#include <stdbool.h>

//=============================================================================
// Register Definitions (CPU-accurate encoding values)
//=============================================================================

typedef enum {
    // 8-bit registers (encoding values match CPU)
    AL = 0, CL = 1, DL = 2, BL = 3, AH = 4, CH = 5, DH = 6, BH = 7,
    SPL = 4, BPL = 5, SIL = 6, DIL = 7,  // REX-only registers
    R8B = 8, R9B = 9, R10B = 10, R11B = 11, R12B = 12, R13B = 13, R14B = 14, R15B = 15,
    
    // 16-bit registers  
    AX = 0, CX = 1, DX = 2, BX = 3, SP = 4, BP = 5, SI = 6, DI = 7,
    R8W = 8, R9W = 9, R10W = 10, R11W = 11, R12W = 12, R13W = 13, R14W = 14, R15W = 15,
    
    // 32-bit registers
    EAX = 0, ECX = 1, EDX = 2, EBX = 3, ESP = 4, EBP = 5, ESI = 6, EDI = 7,
    R8D = 8, R9D = 9, R10D = 10, R11D = 11, R12D = 12, R13D = 13, R14D = 14, R15D = 15,
    
    // 64-bit registers
    RAX = 0, RCX = 1, RDX = 2, RBX = 3, RSP = 4, RBP = 5, RSI = 6, RDI = 7,
    R8 = 8, R9 = 9, R10 = 10, R11 = 11, R12 = 12, R13 = 13, R14 = 14, R15 = 15,
    
    // Special registers
    RIP, RFLAGS,
    
    // Segment registers
    ES = 0, CS = 1, SS = 2, DS = 3, FS = 4, GS = 5
} x86_64_register_id_t;

//=============================================================================
// Instruction Categories (aligned with CPU documentation)
//=============================================================================

typedef enum {
    X86_64_CAT_DATA_MOVEMENT,
    X86_64_CAT_ARITHMETIC,
    X86_64_CAT_LOGICAL,
    X86_64_CAT_SHIFT,
    X86_64_CAT_SHIFT_ROTATE,
    X86_64_CAT_CONTROL_FLOW,
    X86_64_CAT_CONDITIONAL_JUMP,
    X86_64_CAT_COMPARISON,
    X86_64_CAT_STRING,
    X86_64_CAT_FLAG_CONTROL,
    X86_64_CAT_SYSTEM,
    X86_64_CAT_UNKNOWN
} x86_64_instruction_category_t;

//=============================================================================
// Register Information Structure
//=============================================================================

typedef struct {
    const char *name;           // Register name (e.g., "%rax")
    x86_64_register_id_t id;    // Register ID enum
    uint8_t size;               // Size in bytes (1, 2, 4, 8)
    uint8_t encoding;           // Hardware encoding value
    bool needs_rex_extension;   // Requires REX prefix for access
    bool needs_rex_w;           // Requires REX.W for 64-bit operation
    uint8_t default_prefix;     // Default prefix byte (0 if none)
} x86_64_register_info_t;

typedef struct {
    const char *mnemonic;
    x86_64_instruction_category_t category;
    uint8_t opcode[4];          // Up to 4 bytes for complex instructions
    uint8_t opcode_length;
    bool uses_modrm;            // Requires ModR/M byte
    bool needs_rex;             // May require REX prefix  
    bool rex_w;                 // Requires REX.W for 64-bit operation
    uint8_t modrm_reg;          // ModR/M reg field extension (for single operand instructions)
    uint8_t operand_count;      // Number of operands expected
    uint16_t valid_modes;       // Bitmask: bit 4=16-bit, bit 5=32-bit, bit 6=64-bit
    uint8_t prefix_byte;        // Required prefix byte (0 if none)
    const char *description;
} x86_64_instruction_info_t;

//=============================================================================
// Addressing Modes (AT&T syntax)
//=============================================================================

typedef enum {
    X86_64_ADDR_IMMEDIATE,      // $value
    X86_64_ADDR_REGISTER,       // %reg
    X86_64_ADDR_DIRECT,         // address
    X86_64_ADDR_INDIRECT,       // (%reg), offset(%reg), (%base,%index,scale)
    X86_64_ADDR_RIP_RELATIVE,   // symbol(%rip)
    X86_64_ADDR_INVALID         // Invalid addressing mode
} x86_64_address_type_t;

typedef struct {
    x86_64_address_type_t type;
    x86_64_register_id_t base_reg;
    x86_64_register_id_t index_reg;
    x86_64_register_id_t segment_reg;
    uint8_t scale;              // 1, 2, 4, or 8
    int32_t displacement;
    bool has_displacement;
    bool has_segment_override;
    bool has_base;
    bool has_index;
} x86_64_address_t;

//=============================================================================
// REX Prefix (64-bit mode extensions)
//=============================================================================

typedef struct {
    uint8_t w : 1;  // 64-bit operand size
    uint8_t r : 1;  // Extension of ModR/M reg field
    uint8_t x : 1;  // Extension of SIB index field
    uint8_t b : 1;  // Extension of ModR/M r/m field or SIB base field
} x86_64_rex_prefix_t;

//=============================================================================
// Core Functions
//=============================================================================

// Initialization and cleanup
int x86_64_init(void);
void x86_64_cleanup(void);

// Instruction parsing and encoding
int x86_64_parse_instruction(const char *line, instruction_t *inst);

// Register handling
const x86_64_register_info_t *x86_64_find_register(const char *name);
int x86_64_parse_register(const char *reg_str, asm_register_t *reg);
bool x86_64_is_valid_register(const char *reg_str);
uint8_t x86_64_get_register_encoding(x86_64_register_id_t reg_id);
bool x86_64_register_needs_rex(x86_64_register_id_t reg_id);

// Instruction lookup
const x86_64_instruction_info_t *x86_64_find_instruction(const char *mnemonic);
bool x86_64_is_instruction_supported(const char *mnemonic);

// Encoding helpers
uint8_t x86_64_encode_rex_prefix(bool w, bool r, bool x, bool b);
int x86_64_encode_modrm(uint8_t mod, uint8_t reg, uint8_t rm, uint8_t *output);
int x86_64_encode_sib(uint8_t scale, uint8_t index, uint8_t base, uint8_t *output);

// Validation functions
int x86_64_validate_operands(const char *mnemonic, operand_t *operands, size_t count);
bool x86_64_is_valid_operand_combination(const char *mnemonic, operand_t *operands, size_t count);

// Processor mode support (16/32/64-bit compatibility)
typedef enum {
    X86_64_MODE_16BIT = 16,
    X86_64_MODE_32BIT = 32,
    X86_64_MODE_64BIT = 64
} x86_64_processor_mode_t;

void x86_64_set_processor_mode(x86_64_processor_mode_t mode);
x86_64_processor_mode_t x86_64_get_processor_mode(void);
bool x86_64_instruction_valid_in_mode(const char *mnemonic, x86_64_processor_mode_t mode);

// Addressing mode functions
int x86_64_parse_addressing_mode(const char *addr_str, x86_64_address_t *addr);
int x86_64_encode_addressing_mode(const x86_64_address_t *addr, uint8_t reg_field, 
                                  uint8_t *encoding, size_t *encoding_len);
bool x86_64_validate_addressing_mode(const x86_64_address_t *addr);
x86_64_address_type_t x86_64_detect_address_type(const char *addr_str);

// Code generation functions  
int x86_64_assemble_instruction(const char *mnemonic, 
                                const char **operand_strings,
                                int operand_count,
                                uint8_t *output,
                                size_t *output_length);

const x86_64_register_info_t *x86_64_find_register_by_id(x86_64_register_id_t id);

// Architecture interface implementation
const arch_ops_t *get_x86_64_ops(void);

#endif // X86_64_H
