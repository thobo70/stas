/*
 * x86-64 Architecture Module for STAS
 * AMD64/Intel 64-bit instruction set implementation
 */

#include "x86_64.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>

// Safe string duplication function
static char *safe_strdup(const char *s) {
    if (!s) return NULL;
    size_t len = strlen(s) + 1;
    char *dup = malloc(len);
    if (dup) {
        memcpy(dup, s, len);
    }
    return dup;
}

// x86-64 register table
static const struct {
    const char *name;
    x86_64_register_id_t id;
    uint8_t size;
    uint8_t encoding;
} x86_64_registers[] = {
    // 8-bit registers
    {"al", AL, 1, 0}, {"cl", CL, 1, 1}, {"dl", DL, 1, 2}, {"bl", BL, 1, 3},
    {"ah", AH, 1, 4}, {"ch", CH, 1, 5}, {"dh", DH, 1, 6}, {"bh", BH, 1, 7},
    {"spl", SPL, 1, 4}, {"bpl", BPL, 1, 5}, {"sil", SIL, 1, 6}, {"dil", DIL, 1, 7},
    {"r8b", R8B, 1, 0}, {"r9b", R9B, 1, 1}, {"r10b", R10B, 1, 2}, {"r11b", R11B, 1, 3},
    {"r12b", R12B, 1, 4}, {"r13b", R13B, 1, 5}, {"r14b", R14B, 1, 6}, {"r15b", R15B, 1, 7},
    
    // 16-bit registers
    {"ax", AX, 2, 0}, {"cx", CX, 2, 1}, {"dx", DX, 2, 2}, {"bx", BX, 2, 3},
    {"sp", SP, 2, 4}, {"bp", BP, 2, 5}, {"si", SI, 2, 6}, {"di", DI, 2, 7},
    {"r8w", R8W, 2, 0}, {"r9w", R9W, 2, 1}, {"r10w", R10W, 2, 2}, {"r11w", R11W, 2, 3},
    {"r12w", R12W, 2, 4}, {"r13w", R13W, 2, 5}, {"r14w", R14W, 2, 6}, {"r15w", R15W, 2, 7},
    
    // 32-bit registers
    {"eax", EAX, 4, 0}, {"ecx", ECX, 4, 1}, {"edx", EDX, 4, 2}, {"ebx", EBX, 4, 3},
    {"esp", ESP, 4, 4}, {"ebp", EBP, 4, 5}, {"esi", ESI, 4, 6}, {"edi", EDI, 4, 7},
    {"r8d", R8D, 4, 0}, {"r9d", R9D, 4, 1}, {"r10d", R10D, 4, 2}, {"r11d", R11D, 4, 3},
    {"r12d", R12D, 4, 4}, {"r13d", R13D, 4, 5}, {"r14d", R14D, 4, 6}, {"r15d", R15D, 4, 7},
    
    // 64-bit registers
    {"rax", RAX, 8, 0}, {"rcx", RCX, 8, 1}, {"rdx", RDX, 8, 2}, {"rbx", RBX, 8, 3},
    {"rsp", RSP, 8, 4}, {"rbp", RBP, 8, 5}, {"rsi", RSI, 8, 6}, {"rdi", RDI, 8, 7},
    {"r8", R8, 8, 0}, {"r9", R9, 8, 1}, {"r10", R10, 8, 2}, {"r11", R11, 8, 3},
    {"r12", R12, 8, 4}, {"r13", R13, 8, 5}, {"r14", R14, 8, 6}, {"r15", R15, 8, 7},
    
    // Special registers
    {"rip", RIP, 8, 0}, {"rflags", RFLAGS, 8, 0},
    
    {NULL, 0, 0, 0} // Sentinel
};

// Common x86-64 instruction opcodes (basic set)
static const struct {
    const char *mnemonic;
    uint8_t opcode;
    uint8_t opcode_length;
    bool needs_modrm;
} x86_64_instructions[] = {
    {"mov", 0x89, 1, true},    // MOV r/m64, r64
    {"movq", 0x89, 1, true},   // MOV r/m64, r64 (AT&T syntax)
    {"add", 0x01, 1, true},    // ADD r/m64, r64
    {"sub", 0x29, 1, true},    // SUB r/m64, r64
    {"push", 0x50, 1, false},  // PUSH r64
    {"pop", 0x58, 1, false},   // POP r64
    {"call", 0xE8, 1, false},  // CALL rel32
    {"ret", 0xC3, 1, false},   // RET
    {"nop", 0x90, 1, false},   // NOP
    {"syscall", 0x0F, 2, false}, // SYSCALL (0x0F 0x05)
    
    {NULL, 0, 0, false} // Sentinel
};

//=============================================================================
// Helper Functions
//=============================================================================

static char *x86_64_strlower(const char *str) {
    if (!str) return NULL;
    
    size_t len = strlen(str);
    char *lower = malloc(len + 1);
    if (!lower) return NULL;
    
    for (size_t i = 0; i < len; i++) {
        lower[i] = tolower(str[i]);
    }
    lower[len] = '\0';
    
    return lower;
}

//=============================================================================
// Architecture Operations Implementation
//=============================================================================

int x86_64_init(void) {
    // Initialize x86-64 architecture module
    return 0;
}

void x86_64_cleanup(void) {
    // Cleanup x86-64 architecture module
}

int x86_64_parse_register(const char *reg_name, asm_register_t *reg) {
    if (!reg_name || !reg) {
        return -1;
    }
    
    // Remove % prefix if present
    const char *name = reg_name;
    if (name[0] == '%') {
        name++;
    }
    
    char *lower_name = x86_64_strlower(name);
    if (!lower_name) {
        return -1;
    }
    
    // Search for register in table
    for (int i = 0; x86_64_registers[i].name != NULL; i++) {
        if (strcmp(lower_name, x86_64_registers[i].name) == 0) {
            reg->id = x86_64_registers[i].id;
            reg->name = safe_strdup(x86_64_registers[i].name);
            reg->size = x86_64_registers[i].size;
            reg->encoding = x86_64_registers[i].encoding;
            free(lower_name);
            return 0;
        }
    }
    
    free(lower_name);
    return -1; // Register not found
}

bool x86_64_is_valid_register(asm_register_t reg) {
    // Check if register ID is within valid range
    return reg.id <= RFLAGS;
}

const char *x86_64_get_register_name(asm_register_t reg) {
    for (int i = 0; x86_64_registers[i].name != NULL; i++) {
        if (x86_64_registers[i].id == reg.id) {
            return x86_64_registers[i].name;
        }
    }
    return NULL;
}

int x86_64_parse_instruction(const char *mnemonic, operand_t *operands, 
                           size_t operand_count, instruction_t *inst) {
    if (!mnemonic || !inst) {
        return -1;
    }
    
    char *lower_mnemonic = x86_64_strlower(mnemonic);
    if (!lower_mnemonic) {
        return -1;
    }
    
    // Search for instruction in table
    for (int i = 0; x86_64_instructions[i].mnemonic != NULL; i++) {
        if (strcmp(lower_mnemonic, x86_64_instructions[i].mnemonic) == 0) {
            inst->mnemonic = safe_strdup(mnemonic);
            inst->operands = operands;
            inst->operand_count = operand_count;
            inst->encoding = NULL; // Will be filled by encode_instruction
            inst->encoding_length = 0;
            
            free(lower_mnemonic);
            return 0;
        }
    }
    
    free(lower_mnemonic);
    return -1; // Instruction not found
}

int x86_64_encode_instruction(instruction_t *inst, uint8_t *buffer, size_t *length) {
    if (!inst || !buffer || !length) {
        return -1;
    }
    
    // This is a simplified encoding implementation
    // Real implementation would handle all x86-64 encoding complexities
    
    char *lower_mnemonic = x86_64_strlower(inst->mnemonic);
    if (!lower_mnemonic) {
        return -1;
    }
    
    // Find instruction in table
    for (int i = 0; x86_64_instructions[i].mnemonic != NULL; i++) {
        if (strcmp(lower_mnemonic, x86_64_instructions[i].mnemonic) == 0) {
            
            if (strcmp(lower_mnemonic, "syscall") == 0) {
                // SYSCALL instruction: 0x0F 0x05
                buffer[0] = 0x0F;
                buffer[1] = 0x05;
                *length = 2;
                free(lower_mnemonic);
                return 0;
            }
            
            if (strcmp(lower_mnemonic, "nop") == 0) {
                // NOP instruction: 0x90
                buffer[0] = 0x90;
                *length = 1;
                free(lower_mnemonic);
                return 0;
            }
            
            if (strcmp(lower_mnemonic, "ret") == 0) {
                // RET instruction: 0xC3
                buffer[0] = 0xC3;
                *length = 1;
                free(lower_mnemonic);
                return 0;
            }
            
            // For other instructions, we need proper ModR/M encoding
            // This is a stub implementation
            buffer[0] = x86_64_instructions[i].opcode;
            *length = x86_64_instructions[i].opcode_length;
            
            free(lower_mnemonic);
            return 0;
        }
    }
    
    free(lower_mnemonic);
    return -1;
}

int x86_64_parse_addressing(const char *addr_str, addressing_mode_t *mode) {
    // Stub implementation for addressing mode parsing
    if (!addr_str || !mode) {
        return -1;
    }
    
    // This would parse x86-64 addressing modes like:
    // %rax                     -> ADDR_INDIRECT
    // 8(%rax)                  -> ADDR_INDEXED with offset
    // (%rax,%rbx,2)           -> ADDR_INDEXED with base, index, scale
    // symbol(%rip)            -> ADDR_RIP_RELATIVE
    
    return 0; // Stub
}

bool x86_64_validate_addressing(addressing_mode_t *mode, instruction_t *inst) {
    // Stub implementation
    (void)mode; // Suppress unused parameter warning
    (void)inst; // Suppress unused parameter warning
    return true;
}

int x86_64_handle_directive(const char *directive, const char *args) {
    // Handle x86-64 specific directives
    (void)args; // Suppress unused parameter warning
    if (!directive) {
        return -1;
    }
    
    // x86-64 specific directives like .code64
    if (strcmp(directive, ".code64") == 0) {
        return 0; // Set 64-bit mode
    }
    
    return -1; // Unknown directive
}

size_t x86_64_get_instruction_size(instruction_t *inst) {
    if (!inst) {
        return 0;
    }
    
    // Simplified size calculation
    // Real implementation would analyze full instruction encoding
    return inst->encoding_length > 0 ? inst->encoding_length : 1;
}

size_t x86_64_get_alignment(section_type_t section) {
    switch (section) {
        case SECTION_TEXT:
            return 16; // 16-byte alignment for code
        case SECTION_DATA:
        case SECTION_RODATA:
            return 8;  // 8-byte alignment for data
        case SECTION_BSS:
            return 8;  // 8-byte alignment for BSS
        default:
            return 1;  // Default alignment
    }
}

bool x86_64_validate_instruction(instruction_t *inst) {
    // Validate instruction structure
    return inst && inst->mnemonic;
}

bool x86_64_validate_operand_combination(const char *mnemonic, 
                                       operand_t *operands, 
                                       size_t operand_count) {
    // Validate operand combinations for specific instructions
    (void)operands; // Suppress unused parameter warning
    if (!mnemonic) {
        return false;
    }
    
    // Simplified validation
    return operand_count <= 3; // x86-64 instructions have at most 3 operands
}

//=============================================================================
// Architecture Operations Structure
//=============================================================================

static arch_ops_t x86_64_ops = {
    .name = "x86_64",
    .init = x86_64_init,
    .cleanup = x86_64_cleanup,
    .parse_instruction = x86_64_parse_instruction,
    .encode_instruction = x86_64_encode_instruction,
    .parse_register = x86_64_parse_register,
    .is_valid_register = x86_64_is_valid_register,
    .get_register_name = x86_64_get_register_name,
    .parse_addressing = x86_64_parse_addressing,
    .validate_addressing = x86_64_validate_addressing,
    .handle_directive = x86_64_handle_directive,
    .get_instruction_size = x86_64_get_instruction_size,
    .get_alignment = x86_64_get_alignment,
    .validate_instruction = x86_64_validate_instruction,
    .validate_operand_combination = x86_64_validate_operand_combination
};

arch_ops_t *x86_64_get_arch_ops(void) {
    return &x86_64_ops;
}

// Plugin entry point for x86_64
arch_ops_t *get_arch_ops_x86_64(void) {
    return x86_64_get_arch_ops();
}
