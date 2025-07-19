/*
 * x86-64 Architecture Module for STAS
 * AMD64/Intel 64-bit instruction set implementation
 */

#include "x86_64.h"
#include "x86_64_advanced.h"
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
    {"addq", 0x01, 1, true},   // ADD r/m64, r64 (AT&T 64-bit syntax)
    {"sub", 0x29, 1, true},    // SUB r/m64, r64
    {"subq", 0x29, 1, true},   // SUB r/m64, r64 (AT&T 64-bit syntax)
    {"push", 0x50, 1, false},  // PUSH r64
    {"pushq", 0x50, 1, false}, // PUSH r64 (AT&T 64-bit syntax)
    {"pop", 0x58, 1, false},   // POP r64
    {"popq", 0x58, 1, false},  // POP r64 (AT&T 64-bit syntax)
    {"call", 0xE8, 1, false},  // CALL rel32
    {"ret", 0xC3, 1, false},   // RET
    {"nop", 0x90, 1, false},   // NOP
    {"syscall", 0x0F, 2, false}, // SYSCALL (0x0F 0x05)
    
    // Comparison instructions
    {"cmp", 0x39, 1, true},    // CMP r/m64, r64
    {"cmpq", 0x39, 1, true},   // CMP r/m64, r64 (AT&T 64-bit syntax)
    {"test", 0x85, 1, true},   // TEST r/m64, r64
    {"testq", 0x85, 1, true},  // TEST r/m64, r64 (AT&T 64-bit syntax)
    
    // Conditional jumps (short form - 8-bit relative)
    {"je", 0x74, 1, false},    // Jump if equal
    {"jne", 0x75, 1, false},   // Jump if not equal
    {"jz", 0x74, 1, false},    // Jump if zero (same as JE)
    {"jnz", 0x75, 1, false},   // Jump if not zero (same as JNE)
    {"jl", 0x7C, 1, false},    // Jump if less
    {"jge", 0x7D, 1, false},   // Jump if greater or equal
    {"jle", 0x7E, 1, false},   // Jump if less or equal
    {"jg", 0x7F, 1, false},    // Jump if greater
    {"jmp", 0xEB, 1, false},   // Unconditional jump (short)
    
    // Logical operations
    {"and", 0x21, 1, true},    // AND r/m64, r64
    {"andq", 0x21, 1, true},   // AND r/m64, r64 (AT&T 64-bit syntax)
    {"or", 0x09, 1, true},     // OR r/m64, r64
    {"orq", 0x09, 1, true},    // OR r/m64, r64 (AT&T 64-bit syntax)
    {"xor", 0x31, 1, true},    // XOR r/m64, r64
    {"xorq", 0x31, 1, true},   // XOR r/m64, r64 (AT&T 64-bit syntax)
    
    // More arithmetic
    {"inc", 0xFF, 1, true},    // INC r/m64
    {"incq", 0xFF, 1, true},   // INC r/m64 (AT&T 64-bit syntax)
    {"dec", 0xFF, 1, true},    // DEC r/m64
    {"decq", 0xFF, 1, true},   // DEC r/m64 (AT&T 64-bit syntax)
    
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
    
    // This is an enhanced encoding implementation
    // Handles basic x86-64 instructions with proper REX prefix and ModR/M encoding
    
    char *lower_mnemonic = x86_64_strlower(inst->mnemonic);
    if (!lower_mnemonic) {
        return -1;
    }
    
    size_t pos = 0;
    
    // Handle specific instructions
    if (strcmp(lower_mnemonic, "syscall") == 0) {
        // SYSCALL instruction: 0x0F 0x05
        buffer[pos++] = 0x0F;
        buffer[pos++] = 0x05;
        *length = pos;
        free(lower_mnemonic);
        return 0;
    }
    
    if (strcmp(lower_mnemonic, "nop") == 0) {
        // NOP instruction: 0x90
        buffer[pos++] = 0x90;
        *length = pos;
        free(lower_mnemonic);
        return 0;
    }
    
    if (strcmp(lower_mnemonic, "ret") == 0) {
        // RET instruction: 0xC3
        buffer[pos++] = 0xC3;
        *length = pos;
        free(lower_mnemonic);
        return 0;
    }
    
    // Handle MOV instructions
    if (strcmp(lower_mnemonic, "movq") == 0) {
        if (inst->operand_count == 2) {
            if (inst->operands[0].type == OPERAND_REGISTER && inst->operands[1].type == OPERAND_REGISTER) {
                // MOV reg, reg (AT&T: movq %src, %dst) - need REX.W + 0x89 + ModR/M
                buffer[pos++] = 0x48; // REX.W prefix for 64-bit operation
                buffer[pos++] = 0x89; // MOV r/m64, r64 opcode
                
                // AT&T syntax: operands[0]=source, operands[1]=destination
                uint8_t src_reg = inst->operands[0].value.reg.encoding & 0x07;
                uint8_t dst_reg = inst->operands[1].value.reg.encoding & 0x07;
                buffer[pos++] = 0xC0 | (src_reg << 3) | dst_reg; // mod=11, reg=src, r/m=dst
                
                *length = pos;
                free(lower_mnemonic);
                return 0;
            }
            if (inst->operands[0].type == OPERAND_IMMEDIATE && inst->operands[1].type == OPERAND_REGISTER) {
                // MOV imm, reg (AT&T: movq $imm, %reg) - need REX.W + (0xB8+reg) + imm64
                uint8_t reg_enc = inst->operands[1].value.reg.encoding & 0x07;
                buffer[pos++] = 0x48; // REX.W prefix
                buffer[pos++] = 0xB8 + reg_enc; // MOV r64, imm64 opcode
                
                // Add 64-bit immediate (little-endian)
                int64_t imm = inst->operands[0].value.immediate;
                buffer[pos++] = imm & 0xFF;
                buffer[pos++] = (imm >> 8) & 0xFF;
                buffer[pos++] = (imm >> 16) & 0xFF;
                buffer[pos++] = (imm >> 24) & 0xFF;
                buffer[pos++] = (imm >> 32) & 0xFF;
                buffer[pos++] = (imm >> 40) & 0xFF;
                buffer[pos++] = (imm >> 48) & 0xFF;
                buffer[pos++] = (imm >> 56) & 0xFF;
                
                *length = pos;
                free(lower_mnemonic);
                return 0;
            }
        }
    }
    
    // Handle other basic instructions with similar logic
    if (strcmp(lower_mnemonic, "addq") == 0 && inst->operand_count == 2 && 
        inst->operands[0].type == OPERAND_REGISTER && inst->operands[1].type == OPERAND_REGISTER) {
        buffer[pos++] = 0x48; // REX.W prefix
        buffer[pos++] = 0x01; // ADD r/m64, r64 opcode
        
        uint8_t src_reg = inst->operands[1].value.reg.encoding & 0x07;
        uint8_t dst_reg = inst->operands[0].value.reg.encoding & 0x07;
        buffer[pos++] = 0xC0 | (src_reg << 3) | dst_reg;
        
        *length = pos;
        free(lower_mnemonic);
        return 0;
    }
    
    if (strcmp(lower_mnemonic, "subq") == 0 && inst->operand_count == 2 && 
        inst->operands[0].type == OPERAND_REGISTER && inst->operands[1].type == OPERAND_REGISTER) {
        buffer[pos++] = 0x48; // REX.W prefix
        buffer[pos++] = 0x29; // SUB r/m64, r64 opcode
        
        uint8_t src_reg = inst->operands[1].value.reg.encoding & 0x07;
        uint8_t dst_reg = inst->operands[0].value.reg.encoding & 0x07;
        buffer[pos++] = 0xC0 | (src_reg << 3) | dst_reg;
        
        *length = pos;
        free(lower_mnemonic);
        return 0;
    }
    
    // Handle comparison instructions
    if ((strcmp(lower_mnemonic, "cmpq") == 0 || strcmp(lower_mnemonic, "cmp") == 0) && 
        inst->operand_count == 2 && inst->operands[0].type == OPERAND_REGISTER && 
        inst->operands[1].type == OPERAND_REGISTER) {
        buffer[pos++] = 0x48; // REX.W prefix
        buffer[pos++] = 0x39; // CMP opcode
        
        uint8_t src_reg = inst->operands[1].value.reg.encoding & 0x07;
        uint8_t dst_reg = inst->operands[0].value.reg.encoding & 0x07;
        buffer[pos++] = 0xC0 | (src_reg << 3) | dst_reg;
        
        *length = pos;
        free(lower_mnemonic);
        return 0;
    }
    
    // Handle logical operations
    if ((strcmp(lower_mnemonic, "andq") == 0 || strcmp(lower_mnemonic, "and") == 0) && 
        inst->operand_count == 2 && inst->operands[0].type == OPERAND_REGISTER && 
        inst->operands[1].type == OPERAND_REGISTER) {
        buffer[pos++] = 0x48; // REX.W prefix
        buffer[pos++] = 0x21; // AND opcode
        
        uint8_t src_reg = inst->operands[1].value.reg.encoding & 0x07;
        uint8_t dst_reg = inst->operands[0].value.reg.encoding & 0x07;
        buffer[pos++] = 0xC0 | (src_reg << 3) | dst_reg;
        
        *length = pos;
        free(lower_mnemonic);
        return 0;
    }
    
    if ((strcmp(lower_mnemonic, "orq") == 0 || strcmp(lower_mnemonic, "or") == 0) && 
        inst->operand_count == 2 && inst->operands[0].type == OPERAND_REGISTER && 
        inst->operands[1].type == OPERAND_REGISTER) {
        buffer[pos++] = 0x48; // REX.W prefix
        buffer[pos++] = 0x09; // OR opcode
        
        uint8_t src_reg = inst->operands[1].value.reg.encoding & 0x07;
        uint8_t dst_reg = inst->operands[0].value.reg.encoding & 0x07;
        buffer[pos++] = 0xC0 | (src_reg << 3) | dst_reg;
        
        *length = pos;
        free(lower_mnemonic);
        return 0;
    }
    
    if ((strcmp(lower_mnemonic, "xorq") == 0 || strcmp(lower_mnemonic, "xor") == 0) && 
        inst->operand_count == 2 && inst->operands[0].type == OPERAND_REGISTER && 
        inst->operands[1].type == OPERAND_REGISTER) {
        buffer[pos++] = 0x48; // REX.W prefix
        buffer[pos++] = 0x31; // XOR opcode
        
        uint8_t src_reg = inst->operands[1].value.reg.encoding & 0x07;
        uint8_t dst_reg = inst->operands[0].value.reg.encoding & 0x07;
        buffer[pos++] = 0xC0 | (src_reg << 3) | dst_reg;
        
        *length = pos;
        free(lower_mnemonic);
        return 0;
    }
    
    // Handle conditional jumps (short form - 8-bit displacement)
    if (strcmp(lower_mnemonic, "je") == 0 || strcmp(lower_mnemonic, "jz") == 0) {
        buffer[pos++] = 0x74; // JE/JZ opcode
        buffer[pos++] = 0x00; // Placeholder for displacement (would need to be calculated)
        *length = pos;
        free(lower_mnemonic);
        return 0;
    }
    
    if (strcmp(lower_mnemonic, "jne") == 0 || strcmp(lower_mnemonic, "jnz") == 0) {
        buffer[pos++] = 0x75; // JNE/JNZ opcode
        buffer[pos++] = 0x00; // Placeholder for displacement
        *length = pos;
        free(lower_mnemonic);
        return 0;
    }
    
    // Handle unconditional jumps
    if (strcmp(lower_mnemonic, "jmp") == 0) {
        buffer[pos++] = 0xEB; // JMP short opcode
        buffer[pos++] = 0x00; // Placeholder for displacement
        *length = pos;
        free(lower_mnemonic);
        return 0;
    }
    
    // Handle single operand instructions like INC/DEC
    if ((strcmp(lower_mnemonic, "incq") == 0 || strcmp(lower_mnemonic, "inc") == 0) && 
        inst->operand_count == 1 && inst->operands[0].type == OPERAND_REGISTER) {
        buffer[pos++] = 0x48; // REX.W prefix
        buffer[pos++] = 0xFF; // INC/DEC opcode
        
        uint8_t reg_enc = inst->operands[0].value.reg.encoding & 0x07;
        buffer[pos++] = 0xC0 | reg_enc; // ModR/M: mod=11, reg=000 (INC), r/m=register
        
        *length = pos;
        free(lower_mnemonic);
        return 0;
    }
    
    if ((strcmp(lower_mnemonic, "decq") == 0 || strcmp(lower_mnemonic, "dec") == 0) && 
        inst->operand_count == 1 && inst->operands[0].type == OPERAND_REGISTER) {
        buffer[pos++] = 0x48; // REX.W prefix
        buffer[pos++] = 0xFF; // INC/DEC opcode
        
        uint8_t reg_enc = inst->operands[0].value.reg.encoding & 0x07;
        buffer[pos++] = 0xC8 | reg_enc; // ModR/M: mod=11, reg=001 (DEC), r/m=register
        
        *length = pos;
        free(lower_mnemonic);
        return 0;
    }
    if ((strcmp(lower_mnemonic, "push") == 0 || strcmp(lower_mnemonic, "pushq") == 0) && 
        inst->operand_count == 1 && inst->operands[0].type == OPERAND_REGISTER) {
        uint8_t reg_enc = inst->operands[0].value.reg.encoding & 0x07;
        buffer[pos++] = 0x50 + reg_enc; // PUSH r64
        
        *length = pos;
        free(lower_mnemonic);
        return 0;
    }
    
    if ((strcmp(lower_mnemonic, "pop") == 0 || strcmp(lower_mnemonic, "popq") == 0) && 
        inst->operand_count == 1 && inst->operands[0].type == OPERAND_REGISTER) {
        uint8_t reg_enc = inst->operands[0].value.reg.encoding & 0x07;
        buffer[pos++] = 0x58 + reg_enc; // POP r64
        
        *length = pos;
        free(lower_mnemonic);
        return 0;
    }
    
    // Phase 6.1: Try advanced instruction sets before fallback
    
    // Check for SSE instructions
    if (is_sse_instruction(lower_mnemonic)) {
        int result = encode_sse_instruction(inst, buffer, length);
        free(lower_mnemonic);
        return result;
    }
    
    // Check for AVX instructions  
    if (is_avx_instruction(lower_mnemonic)) {
        int result = encode_avx_instruction(inst, buffer, length);
        free(lower_mnemonic);
        return result;
    }
    
    // Check for advanced control flow instructions
    if (is_advanced_control_instruction(lower_mnemonic)) {
        int result = encode_advanced_control_instruction(inst, buffer, length);
        free(lower_mnemonic);
        return result;
    }
    
    // Fall back to basic encoding for unimplemented instructions
    // Find instruction in table
    for (int i = 0; x86_64_instructions[i].mnemonic != NULL; i++) {
        if (strcmp(lower_mnemonic, x86_64_instructions[i].mnemonic) == 0) {
            buffer[pos++] = x86_64_instructions[i].opcode;
            *length = pos;
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
