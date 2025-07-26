#ifndef X86_16_H
#define X86_16_H

#include "arch_interface.h"

// x86-16 opcodes using proper enum structure
typedef enum {
    // Base instruction set
    X86_16_OP_MOV_REG_REG,      // MOV r16, r16
    X86_16_OP_MOV_REG_MEM,      // MOV r16, m16
    X86_16_OP_MOV_MEM_REG,      // MOV m16, r16
    X86_16_OP_MOV_REG_IMM,      // MOV r16, imm16
    X86_16_OP_ADD_REG_REG,      // ADD r16, r16
    X86_16_OP_SUB_REG_REG,      // SUB r16, r16
    X86_16_OP_CMP_REG_REG,      // CMP r16, r16
    X86_16_OP_JMP_REL,          // JMP rel16
    X86_16_OP_JMP_SHORT,        // JMP rel8
    X86_16_OP_CALL_REL,         // CALL rel16
    X86_16_OP_RET,              // RET
    X86_16_OP_PUSH_REG,         // PUSH r16
    X86_16_OP_POP_REG,          // POP r16
    X86_16_OP_INT,              // INT imm8
    X86_16_OP_NOP,              // NOP
    X86_16_OP_HLT,              // HLT
    
    // Basic conditional jumps
    X86_16_OP_JE,               // JE rel8
    X86_16_OP_JNE,              // JNE rel8  
    X86_16_OP_JL,               // JL rel8
    X86_16_OP_JG,               // JG rel8
    
    // Phase 1 additions - Logical operations
    X86_16_OP_AND_REG_REG,      // AND r16, r16
    X86_16_OP_AND_REG_IMM,      // AND r16, imm16
    X86_16_OP_OR_REG_REG,       // OR r16, r16  
    X86_16_OP_OR_REG_IMM,       // OR r16, imm16
    X86_16_OP_XOR_REG_REG,      // XOR r16, r16
    X86_16_OP_XOR_REG_IMM,      // XOR r16, imm16
    X86_16_OP_NOT_REG,          // NOT r16
    X86_16_OP_TEST_REG_REG,     // TEST r16, r16
    X86_16_OP_TEST_REG_IMM,     // TEST r16, imm16
    
    // Phase 1 additions - Arithmetic operations
    X86_16_OP_ADD_REG_IMM,      // ADD r16, imm16
    X86_16_OP_SUB_REG_IMM,      // SUB r16, imm16
    X86_16_OP_CMP_REG_IMM,      // CMP r16, imm16
    X86_16_OP_MUL_REG,          // MUL r16
    X86_16_OP_IMUL_REG,         // IMUL r16
    X86_16_OP_DIV_REG,          // DIV r16
    X86_16_OP_IDIV_REG,         // IDIV r16
    X86_16_OP_INC_REG,          // INC r16
    X86_16_OP_DEC_REG,          // DEC r16
    X86_16_OP_NEG_REG,          // NEG r16
    
    // Phase 1 additions - Shift operations
    X86_16_OP_SHL_REG_CL,       // SHL r16, CL
    X86_16_OP_SHR_REG_CL,       // SHR r16, CL
    X86_16_OP_SAR_REG_CL,       // SAR r16, CL
    X86_16_OP_ROL_REG_CL,       // ROL r16, CL
    X86_16_OP_ROR_REG_CL,       // ROR r16, CL
    X86_16_OP_SHL_REG_1,        // SHL r16, 1
    X86_16_OP_SHR_REG_1,        // SHR r16, 1
    X86_16_OP_SAR_REG_1,        // SAR r16, 1
    X86_16_OP_ROL_REG_1,        // ROL r16, 1
    X86_16_OP_ROR_REG_1,        // ROR r16, 1
    
    // Phase 1 additions - Additional conditional jumps
    X86_16_OP_JA,               // JA rel8
    X86_16_OP_JAE,              // JAE rel8
    X86_16_OP_JB,               // JB rel8
    X86_16_OP_JBE,              // JBE rel8
    X86_16_OP_JC,               // JC rel8
    X86_16_OP_JNC,              // JNC rel8
    X86_16_OP_JO,               // JO rel8
    X86_16_OP_JNO,              // JNO rel8
    X86_16_OP_JS,               // JS rel8
    X86_16_OP_JNS,              // JNS rel8
    X86_16_OP_JP,               // JP rel8
    X86_16_OP_JNP,              // JNP rel8
    X86_16_OP_JZ,               // JZ rel8
    X86_16_OP_JNZ,              // JNZ rel8
    X86_16_OP_JLE,              // JLE rel8
    X86_16_OP_JGE,              // JGE rel8
    
    // Phase 1 additions - Flag operations
    X86_16_OP_CLC,              // CLC
    X86_16_OP_STC,              // STC
    X86_16_OP_CMC,              // CMC
    X86_16_OP_CLD,              // CLD
    X86_16_OP_STD,              // STD
    X86_16_OP_CLI,              // CLI
    X86_16_OP_STI,              // STI
    
    // Phase 1 additions - String operations
    X86_16_OP_MOVSW,            // MOVSW
    X86_16_OP_STOSW,            // STOSW
    X86_16_OP_LODSW,            // LODSW
    X86_16_OP_SCASW,            // SCASW
    X86_16_OP_CMPSW,            // CMPSW
    
    // Must be last for count
    X86_16_OP_COUNT
} x86_16_opcode_t;

// Machine code mappings for opcodes
extern const uint16_t x86_16_opcode_map[X86_16_OP_COUNT];

// Register constants for x86-16 
typedef enum {
    X86_16_REG_AX = 0,
    X86_16_REG_CX = 1,
    X86_16_REG_DX = 2,
    X86_16_REG_BX = 3,
    X86_16_REG_SP = 4,
    X86_16_REG_BP = 5,
    X86_16_REG_SI = 6,
    X86_16_REG_DI = 7,
    X86_16_REG_ES = 8,
    X86_16_REG_CS = 9,
    X86_16_REG_SS = 10,
    X86_16_REG_DS = 11,
    X86_16_REG_FS = 12,
    X86_16_REG_GS = 13
} x86_16_register_t;

// 8-bit register constants for internal use  
typedef enum {
    X86_16_REG_AL = 0,
    X86_16_REG_CL = 1,
    X86_16_REG_DL = 2,
    X86_16_REG_BL = 3,
    X86_16_REG_AH = 4,
    X86_16_REG_CH = 5,
    X86_16_REG_DH = 6,
    X86_16_REG_BH = 7
} x86_16_register_8bit_t;

// Additional register constants for internal use
#define X86_16_REG_IP    14
#define X86_16_REG_FLAGS 15

// Additional aliases for specific uses
#define CL_16  X86_16_REG_CL

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

// ModR/M byte structure for x86-16
typedef union {
    struct {
        uint8_t rm   : 3;    // R/M field
        uint8_t reg  : 3;    // REG field
        uint8_t mod  : 2;    // MOD field
    } fields;
    uint8_t byte;
} x86_16_modrm_t;

// x86-16 instruction structure
typedef struct {
    x86_16_prefix_t prefixes[4];     // Maximum 4 prefixes
    uint8_t prefix_count;
    x86_16_opcode_t opcode;
    x86_16_modrm_t modrm;
    bool has_modrm;
    uint8_t sib;                     // Scale-Index-Base (if applicable)
    bool has_sib;
    uint32_t displacement;           // Displacement
    uint8_t disp_size;               // Size of displacement in bytes
    uint32_t immediate;              // Immediate value
    uint8_t imm_size;                // Size of immediate in bytes
    uint8_t size;                    // Total instruction size
} x86_16_instruction_t;

// x86-16 operand types
typedef enum {
    X86_16_OPERAND_NONE,
    X86_16_OPERAND_REGISTER,
    X86_16_OPERAND_IMMEDIATE,
    X86_16_OPERAND_MEMORY,
    X86_16_OPERAND_RELATIVE
} x86_16_operand_type_t;

// x86-16 operand structure
typedef struct {
    x86_16_operand_type_t type;
    union {
        x86_16_register_t reg;       // Register operand
        int32_t immediate;           // Immediate value
        struct {                     // Memory operand
            x86_16_register_t base;
            x86_16_register_t index;
            uint8_t scale;
            int32_t displacement;
            x86_16_register_t segment;
        } memory;
        int32_t relative;            // Relative offset
    } value;
    uint8_t size;                    // Operand size in bytes
} x86_16_operand_t;

// x86-16 architecture context structure
typedef struct {
    // Architecture-specific state
    bool initialized;
    
    // Current instruction state
    x86_16_instruction_t current_instruction;
    uint32_t current_address;
    
    // Architecture validation state
    bool strict_mode;                // Strict x86-16 compliance
    bool allow_80286_extensions;     // Allow 80286+ features
    
    // Directive state
    char current_arch[16];          // Current architecture (.arch directive)
} x86_16_context_t;

// Function declarations
extern x86_16_context_t x86_16_context;

// Core x86-16 functions
int x86_16_init(void);
void x86_16_cleanup(void);
bool x86_16_validate_instruction(const char *mnemonic, const operand_t *operands, size_t operand_count);
bool x86_16_encode_instruction(const char *mnemonic, const operand_t *operands, size_t operand_count, uint8_t *output, size_t *output_size);
bool x86_16_is_valid_register(const asm_register_t reg);
const char *x86_16_get_register_name(const asm_register_t reg);

// x86-16 specific functions
bool x86_16_parse_operand(const char *operand_str, x86_16_operand_t *operand);
bool x86_16_encode_modrm(const x86_16_operand_t *operands, size_t operand_count, x86_16_modrm_t *modrm);
uint8_t x86_16_get_register_encoding(x86_16_register_t reg);
bool x86_16_is_valid_addressing_mode(const x86_16_operand_t *operand);

// Directive handlers
bool x86_16_handle_arch_directive(const char *args);
bool x86_16_handle_code16_directive(void);

// Helper functions
bool x86_16_is_segment_register(x86_16_register_t reg);
bool x86_16_is_general_register(x86_16_register_t reg);
bool x86_16_is_8bit_register(x86_16_register_8bit_t reg);
uint8_t x86_16_calculate_instruction_size(const x86_16_instruction_t *instr);

#endif // X86_16_H
