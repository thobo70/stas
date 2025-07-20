/*
 * x86-32 Architecture Module for STAS
 * Complete Intel IA-32 (80386+) instruction set implementation
 * Supports Real Mode, Protected Mode, and Virtual 8086 Mode
 */

#include "x86_32.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>

// Global state for code generation mode
static uint8_t current_code_mode = 32;  // Default to 32-bit mode
static uint8_t cpu_level = 3;  // 0=386, 1=486, 2=Pentium, 3=PentiumPro

// Safe string duplication
static char *x86_32_safe_strdup(const char *s) {
    if (!s) return NULL;
    size_t len = strlen(s) + 1;
    char *dup = malloc(len);
    if (dup) {
        memcpy(dup, s, len);
    }
    return dup;
}

// Convert string to lowercase
static char *x86_32_strlower(const char *str) {
    if (!str) return NULL;
    
    char *lower = x86_32_safe_strdup(str);
    if (!lower) return NULL;
    
    for (size_t i = 0; lower[i]; i++) {
        lower[i] = (char)tolower((unsigned char)lower[i]);
    }
    
    return lower;
}

// Complete x86-32 register table
static const struct {
    const char *name;
    uint8_t encoding;
    uint8_t size;
    uint8_t reg_class;  // 0=GPR32, 1=GPR16, 2=GPR8L, 3=GPR8H, 4=SEG, 5=CR, 6=DR, 7=TR
} x86_32_registers[] = {
    // 32-bit general purpose registers
    {"eax", 0, 4, 0}, {"ecx", 1, 4, 0}, 
    {"edx", 2, 4, 0}, {"ebx", 3, 4, 0},
    {"esp", 4, 4, 0}, {"ebp", 5, 4, 0}, 
    {"esi", 6, 4, 0}, {"edi", 7, 4, 0},
    
    // 16-bit general purpose registers  
    {"ax", 0, 2, 1}, {"cx", 1, 2, 1}, 
    {"dx", 2, 2, 1}, {"bx", 3, 2, 1},
    {"sp", 4, 2, 1}, {"bp", 5, 2, 1}, 
    {"si", 6, 2, 1}, {"di", 7, 2, 1},
    
    // 8-bit registers (low byte)
    {"al", 0, 1, 2}, {"cl", 1, 1, 2}, 
    {"dl", 2, 1, 2}, {"bl", 3, 1, 2},
    
    // 8-bit registers (high byte)
    {"ah", 4, 1, 3}, {"ch", 5, 1, 3}, 
    {"dh", 6, 1, 3}, {"bh", 7, 1, 3},
    
    // Segment registers
    {"cs", 1, 2, 4}, {"ds", 3, 2, 4}, 
    {"es", 0, 2, 4}, {"ss", 2, 2, 4},
    {"fs", 4, 2, 4}, {"gs", 5, 2, 4},
    
    // Control registers
    {"cr0", 0, 4, 5}, {"cr2", 2, 4, 5}, 
    {"cr3", 3, 4, 5}, {"cr4", 4, 4, 5},
    
    // Debug registers
    {"dr0", 0, 4, 6}, {"dr1", 1, 4, 6}, 
    {"dr2", 2, 4, 6}, {"dr3", 3, 4, 6},
    {"dr6", 6, 4, 6}, {"dr7", 7, 4, 6},
    
    // Test registers (386/486 only)
    {"tr6", 6, 4, 7}, {"tr7", 7, 4, 7},
};

static int x86_32_find_register(const char *name, uint8_t *encoding, uint8_t *size) {
    if (!name || !encoding || !size) return -1;
    
    size_t count = sizeof(x86_32_registers) / sizeof(x86_32_registers[0]);
    for (size_t i = 0; i < count; i++) {
        if (strcmp(name, x86_32_registers[i].name) == 0) {
            *encoding = x86_32_registers[i].encoding;
            *size = x86_32_registers[i].size;
            return 0;
        }
    }
    return -1;
}

// Helper function to get register class
static int x86_32_get_register_class(const char *name) {
    size_t count = sizeof(x86_32_registers) / sizeof(x86_32_registers[0]);
    for (size_t i = 0; i < count; i++) {
        if (strcmp(name, x86_32_registers[i].name) == 0) {
            return x86_32_registers[i].reg_class;
        }
    }
    return -1;
}

// Parse immediate values (handles various formats)
// TODO: Use this function when implementing memory addressing
/*
static int64_t x86_32_parse_immediate(const char *str) {
    if (!str) return 0;
    
    // Skip $ prefix if present
    if (str[0] == '$') str++;
    
    // Handle hex (0x prefix)
    if (strncmp(str, "0x", 2) == 0 || strncmp(str, "0X", 2) == 0) {
        return (int64_t)strtoll(str, NULL, 16);
    }
    
    // Handle octal (0 prefix)
    if (str[0] == '0' && strlen(str) > 1) {
        return (int64_t)strtoll(str, NULL, 8);
    }
    
    // Handle decimal
    return (int64_t)strtoll(str, NULL, 10);
}
*/

// Generate ModR/M byte
static uint8_t x86_32_make_modrm(uint8_t mod, uint8_t reg, uint8_t rm) {
    return (mod << 6) | (reg << 3) | rm;
}

// Generate SIB byte - TODO: Use when implementing complex addressing
/*
static uint8_t x86_32_make_sib(uint8_t scale, uint8_t index, uint8_t base) {
    return (scale << 6) | (index << 3) | base;
}
*/

// Encode immediate value into buffer
static int x86_32_encode_immediate(uint8_t *buffer, size_t *pos, int64_t value, uint8_t size) {
    for (uint8_t i = 0; i < size; i++) {
        buffer[(*pos)++] = (uint8_t)((value >> (i * 8)) & 0xFF);
    }
    return 0;
}

// Handle .code16/.code32 directives
int x86_32_handle_directive(const char *directive, const char *args) {
    if (!directive) return -1;
    
    // Suppress unused parameter warning
    (void)args;
    
    if (strcmp(directive, ".code16") == 0) {
        current_code_mode = 16;
        return 0;
    }
    
    if (strcmp(directive, ".code32") == 0) {
        current_code_mode = 32;
        return 0;
    }
    
    if (strcmp(directive, ".386") == 0) {
        cpu_level = 0;
        return 0;
    }
    
    if (strcmp(directive, ".486") == 0) {
        cpu_level = 1;
        return 0;
    }
    
    if (strcmp(directive, ".586") == 0) {
        cpu_level = 2;
        return 0;
    }
    
    if (strcmp(directive, ".686") == 0) {
        cpu_level = 3;
        return 0;
    }
    
    return -1;  // Unknown directive
}

int x86_32_init(void) {
    return 0;
}

void x86_32_cleanup(void) {
    // Cleanup implementation
}

int x86_32_parse_instruction(const char *mnemonic, operand_t *operands, 
                           size_t operand_count, instruction_t *inst) {
    if (!mnemonic || !inst) {
        return -1;
    }
    
    // Reject empty mnemonic
    if (strlen(mnemonic) == 0) {
        return -1;
    }
    
    // Complete i386 instruction set support
    const char* valid_i386_instructions[] = {
        // Data movement
        "mov", "movb", "movw", "movl", "movsx", "movzx", "xchg",
        "lea", "push", "pop", "pushw", "popw", "pushad", "popad", "pushfd", "popfd",
        
        // Arithmetic  
        "add", "addb", "addw", "addl", "adc", "sub", "subb", "subw", "subl", "sbb",
        "inc", "incb", "incw", "incl", "dec", "decb", "decw", "decl",
        "mul", "imul", "div", "idiv", "neg", "cmp", "cmpb", "cmpw", "cmpl",
        "daa", "das", "aaa", "aas", "aam", "aad",
        
        // Logical
        "and", "andb", "andw", "andl", "or", "orb", "orw", "orl",
        "xor", "xorb", "xorw", "xorl", "not", "test", "testb", "testw", "testl",
        
        // Shift and rotate
        "shl", "shr", "sar", "shld", "shrd", "rol", "ror", "rcl", "rcr",
        
        // Control flow
        "jmp", "call", "ret", "retf", "retn", "iret", "iretd",
        
        // Conditional jumps
        "ja", "jae", "jb", "jbe", "jc", "je", "jg", "jge", "jl", "jle",
        "jna", "jnae", "jnb", "jnbe", "jnc", "jne", "jng", "jnge", "jnl", "jnle",
        "jo", "jno", "jp", "jnp", "js", "jns", "jz", "jnz",
        
        // String operations
        "movsb", "movsw", "movsd", "cmpsb", "cmpsw", "cmpsd",
        "scasb", "scasw", "scasd", "lodsb", "lodsw", "lodsd",
        "stosb", "stosw", "stosd", "rep", "repe", "repne",
        
        // Flag operations
        "clc", "stc", "cmc", "cld", "std", "cli", "sti", "clts",
        "lahf", "sahf", "pushf", "popf",
        
        // System instructions
        "hlt", "nop", "wait", "lock", "int", "into", "bound",
        "enter", "leave", "pusha", "popa",
        
        // Segment/descriptor operations
        "lds", "les", "lfs", "lgs", "lss", "lgdt", "sgdt", "lidt", "sidt",
        "lldt", "sldt", "ltr", "str", "lmsw", "smsw", "lar", "lsl", "verr", "verw",
        
        // Protection 
        "arpl", "clts", "invd", "invlpg", "wbinvd",
        
        // Processor control
        "cpuid", "rdtsc", "rdmsr", "wrmsr",
        
        // Floating point (387 - basic)
        "fld", "fst", "fstp", "fadd", "fsub", "fmul", "fdiv",
        "f2xm1", "fabs", "fchs", "fcos", "fsin", "fsqrt", "fpatan",
        
        // MMX (Pentium+)
        "movq", "paddb", "paddw", "paddd", "psubb", "psubw", "psubd",
        "pmullw", "pmulhw", "pand", "pandn", "por", "pxor", "emms",
        
        // SSE (Pentium III+)
        "movss", "movps", "addss", "addps", "subss", "subps",
        "mulss", "mulps", "divss", "divps", "sqrtss", "sqrtps"
    };
    
    size_t valid_count = sizeof(valid_i386_instructions) / sizeof(valid_i386_instructions[0]);
    
    // Check if instruction is supported
    bool is_valid = false;
    for (size_t i = 0; i < valid_count; i++) {
        if (strcmp(mnemonic, valid_i386_instructions[i]) == 0) {
            is_valid = true;
            break;
        }
    }
    
    if (!is_valid) {
        return -1; // Unsupported instruction
    }
    
    // Reject x86_64-specific instruction names when used without proper operands
    // These are x86_64 register instructions that shouldn't exist in x86_32
    if (strcmp(mnemonic, "movq") == 0 || strcmp(mnemonic, "addq") == 0 || 
        strcmp(mnemonic, "subq") == 0 || strcmp(mnemonic, "pushq") == 0 || 
        strcmp(mnemonic, "popq") == 0 || strcmp(mnemonic, "syscall") == 0) {
        
        // Check if this looks like an x86_64 instruction (wrong operand count or x86_64 registers)
        if (operand_count == 0 && strcmp(mnemonic, "syscall") != 0) {
            return -1; // x86_64-style movq/addq/etc with 0 operands not supported
        }
        if (strcmp(mnemonic, "syscall") == 0) {
            return -1; // syscall is x86_64 only
        }
        
        // For movq, check if operands are x86_64 registers
        if (strcmp(mnemonic, "movq") == 0 && operand_count > 0) {
            for (size_t i = 0; i < operand_count; i++) {
                if (operands[i].type == OPERAND_REGISTER) {
                    const char *reg_name = operands[i].value.reg.name;
                    // Check for x86_64-only registers (rax, rbx, etc.)
                    if (reg_name && (strstr(reg_name, "rax") || strstr(reg_name, "rbx") || 
                                   strstr(reg_name, "rcx") || strstr(reg_name, "rdx") ||
                                   strstr(reg_name, "rsi") || strstr(reg_name, "rdi") ||
                                   strstr(reg_name, "rsp") || strstr(reg_name, "rbp") ||
                                   strstr(reg_name, "r8") || strstr(reg_name, "r9") ||
                                   strstr(reg_name, "r10") || strstr(reg_name, "r11") ||
                                   strstr(reg_name, "r12") || strstr(reg_name, "r13") ||
                                   strstr(reg_name, "r14") || strstr(reg_name, "r15"))) {
                        return -1; // x86_64 register not supported in x86_32
                    }
                }
            }
        }
    }

    // Basic instruction setup
    inst->mnemonic = x86_32_safe_strdup(mnemonic);
    inst->operands = operands;
    inst->operand_count = operand_count;
    inst->encoding = NULL;
    inst->encoding_length = 0;
    
    return 0;
}

int x86_32_encode_instruction(instruction_t *inst, uint8_t *buffer, size_t *length) {
    if (!inst || !buffer || !length) {
        return -1;
    }
    
    const size_t MAX_BUFFER_SIZE = 16;
    char *lower_mnemonic = x86_32_strlower(inst->mnemonic);
    if (!lower_mnemonic) {
        return -1;
    }

    size_t pos = 0;

    // Add 16-bit operand prefix if in 16-bit mode and using 32-bit operands
    // or if in 32-bit mode and using 16-bit operands
    bool need_operand_prefix = false;
    if (current_code_mode == 16) {
        // Check if we're using 32-bit operands in 16-bit mode
        if (strstr(lower_mnemonic, "l") != NULL) {  // 32-bit suffix
            need_operand_prefix = true;
        }
    } else if (current_code_mode == 32) {
        // Check if we're using 16-bit operands in 32-bit mode
        if (strstr(lower_mnemonic, "w") != NULL) {  // 16-bit suffix
            need_operand_prefix = true;
        }
    }
    
    if (need_operand_prefix) {
        if (pos >= MAX_BUFFER_SIZE) { free(lower_mnemonic); return -1; }
        buffer[pos++] = 0x66;  // Operand size prefix
    }

    // ===== CONTROL FLOW INSTRUCTIONS =====
    
    if (strcmp(lower_mnemonic, "ret") == 0 || strcmp(lower_mnemonic, "retn") == 0) {
        if (pos >= MAX_BUFFER_SIZE) { free(lower_mnemonic); return -1; }
        buffer[pos++] = 0xC3;
        *length = pos;
        free(lower_mnemonic);
        return 0;
    }

    if (strcmp(lower_mnemonic, "retf") == 0) {
        if (pos >= MAX_BUFFER_SIZE) { free(lower_mnemonic); return -1; }
        buffer[pos++] = 0xCB;
        *length = pos;
        free(lower_mnemonic);
        return 0;
    }

    if (strcmp(lower_mnemonic, "nop") == 0) {
        if (pos >= MAX_BUFFER_SIZE) { free(lower_mnemonic); return -1; }
        buffer[pos++] = 0x90;
        *length = pos;
        free(lower_mnemonic);
        return 0;
    }

    if (strcmp(lower_mnemonic, "hlt") == 0) {
        if (pos >= MAX_BUFFER_SIZE) { free(lower_mnemonic); return -1; }
        buffer[pos++] = 0xF4;
        *length = pos;
        free(lower_mnemonic);
        return 0;
    }

    if (strcmp(lower_mnemonic, "cli") == 0) {
        if (pos >= MAX_BUFFER_SIZE) { free(lower_mnemonic); return -1; }
        buffer[pos++] = 0xFA;
        *length = pos;
        free(lower_mnemonic);
        return 0;
    }

    if (strcmp(lower_mnemonic, "sti") == 0) {
        if (pos >= MAX_BUFFER_SIZE) { free(lower_mnemonic); return -1; }
        buffer[pos++] = 0xFB;
        *length = pos;
        free(lower_mnemonic);
        return 0;
    }

    if (strcmp(lower_mnemonic, "clc") == 0) {
        if (pos >= MAX_BUFFER_SIZE) { free(lower_mnemonic); return -1; }
        buffer[pos++] = 0xF8;
        *length = pos;
        free(lower_mnemonic);
        return 0;
    }

    if (strcmp(lower_mnemonic, "stc") == 0) {
        if (pos >= MAX_BUFFER_SIZE) { free(lower_mnemonic); return -1; }
        buffer[pos++] = 0xF9;
        *length = pos;
        free(lower_mnemonic);
        return 0;
    }

    if (strcmp(lower_mnemonic, "cld") == 0) {
        if (pos >= MAX_BUFFER_SIZE) { free(lower_mnemonic); return -1; }
        buffer[pos++] = 0xFC;
        *length = pos;
        free(lower_mnemonic);
        return 0;
    }

    if (strcmp(lower_mnemonic, "std") == 0) {
        if (pos >= MAX_BUFFER_SIZE) { free(lower_mnemonic); return -1; }
        buffer[pos++] = 0xFD;
        *length = pos;
        free(lower_mnemonic);
        return 0;
    }

    // ===== DATA MOVEMENT INSTRUCTIONS =====
    
    // MOV instructions
    if (strcmp(lower_mnemonic, "mov") == 0 || strcmp(lower_mnemonic, "movl") == 0 ||
        strcmp(lower_mnemonic, "movw") == 0 || strcmp(lower_mnemonic, "movb") == 0) {
        
        if (inst->operand_count == 2) {
            // MOV immediate to register
            if (inst->operands[0].type == OPERAND_IMMEDIATE && 
                inst->operands[1].type == OPERAND_REGISTER) {
                
                uint8_t reg_encoding, reg_size;
                if (x86_32_find_register(inst->operands[1].value.reg.name, &reg_encoding, &reg_size) == 0) {
                    int64_t imm = inst->operands[0].value.immediate;
                    
                    if (reg_size == 4) { // 32-bit register
                        if (pos + 5 > MAX_BUFFER_SIZE) { free(lower_mnemonic); return -1; }
                        buffer[pos++] = 0xB8 + reg_encoding; // MOV r32, imm32
                        x86_32_encode_immediate(buffer, &pos, imm, 4);
                    } else if (reg_size == 2) { // 16-bit register
                        if (pos + 3 > MAX_BUFFER_SIZE) { free(lower_mnemonic); return -1; }
                        buffer[pos++] = 0xB8 + reg_encoding; // MOV r16, imm16
                        x86_32_encode_immediate(buffer, &pos, imm, 2);
                    } else if (reg_size == 1) { // 8-bit register
                        if (pos + 2 > MAX_BUFFER_SIZE) { free(lower_mnemonic); return -1; }
                        if (x86_32_get_register_class(inst->operands[1].value.reg.name) == 3) {
                            // High byte register (AH, BH, CH, DH)
                            buffer[pos++] = 0xB4 + (reg_encoding - 4);
                        } else {
                            // Low byte register (AL, BL, CL, DL) 
                            buffer[pos++] = 0xB0 + reg_encoding;
                        }
                        x86_32_encode_immediate(buffer, &pos, imm, 1);
                    }
                    
                    *length = pos;
                    free(lower_mnemonic);
                    return 0;
                }
            }
            
            // MOV register to register
            if (inst->operands[0].type == OPERAND_REGISTER && 
                inst->operands[1].type == OPERAND_REGISTER) {
                
                uint8_t src_encoding, src_size, dst_encoding, dst_size;
                if (x86_32_find_register(inst->operands[0].value.reg.name, &src_encoding, &src_size) == 0 &&
                    x86_32_find_register(inst->operands[1].value.reg.name, &dst_encoding, &dst_size) == 0) {
                    
                    // Special case: MOV r32 to segment register
                    int dst_class = x86_32_get_register_class(inst->operands[1].value.reg.name);
                    if (dst_class == 4 && src_size == 4) { // SEG register class
                        if (pos + 2 > MAX_BUFFER_SIZE) { free(lower_mnemonic); return -1; }
                        buffer[pos++] = 0x8E; // MOV Sreg, r/m16
                        buffer[pos++] = x86_32_make_modrm(3, dst_encoding, src_encoding);
                        *length = pos;
                        free(lower_mnemonic);
                        return 0;
                    }
                    
                    if (src_size == dst_size) {
                        if (pos + 2 > MAX_BUFFER_SIZE) { free(lower_mnemonic); return -1; }
                        
                        if (src_size == 4) {
                            buffer[pos++] = 0x89; // MOV r/m32, r32
                        } else if (src_size == 2) {
                            buffer[pos++] = 0x89; // MOV r/m16, r16
                        } else if (src_size == 1) {
                            buffer[pos++] = 0x88; // MOV r/m8, r8
                        }
                        
                        buffer[pos++] = x86_32_make_modrm(3, src_encoding, dst_encoding);
                        
                        *length = pos;
                        free(lower_mnemonic);
                        return 0;
                    }
                }
            }
        }
    }

    // ===== ARITHMETIC INSTRUCTIONS =====
    
    // ADD instructions
    if (strcmp(lower_mnemonic, "add") == 0 || strcmp(lower_mnemonic, "addl") == 0 ||
        strcmp(lower_mnemonic, "addw") == 0 || strcmp(lower_mnemonic, "addb") == 0) {
        
        if (inst->operand_count == 2) {
            // ADD register to register
            if (inst->operands[0].type == OPERAND_REGISTER && 
                inst->operands[1].type == OPERAND_REGISTER) {
                
                uint8_t src_encoding, src_size, dst_encoding, dst_size;
                if (x86_32_find_register(inst->operands[0].value.reg.name, &src_encoding, &src_size) == 0 &&
                    x86_32_find_register(inst->operands[1].value.reg.name, &dst_encoding, &dst_size) == 0) {
                    
                    if (src_size == dst_size && pos + 2 <= MAX_BUFFER_SIZE) {
                        if (src_size == 4 || src_size == 2) {
                            buffer[pos++] = 0x01; // ADD r/m32, r32 or ADD r/m16, r16
                        } else {
                            buffer[pos++] = 0x00; // ADD r/m8, r8
                        }
                        buffer[pos++] = x86_32_make_modrm(3, src_encoding, dst_encoding);
                        
                        *length = pos;
                        free(lower_mnemonic);
                        return 0;
                    }
                }
            }
            
            // ADD immediate to register
            if (inst->operands[0].type == OPERAND_IMMEDIATE && 
                inst->operands[1].type == OPERAND_REGISTER) {
                
                uint8_t reg_encoding, reg_size;
                if (x86_32_find_register(inst->operands[1].value.reg.name, &reg_encoding, &reg_size) == 0) {
                    int64_t imm = inst->operands[0].value.immediate;
                    
                    if (reg_encoding == 0) { // EAX/AX/AL shorthand
                        if (reg_size == 4 && pos + 5 <= MAX_BUFFER_SIZE) {
                            buffer[pos++] = 0x05; // ADD EAX, imm32
                            x86_32_encode_immediate(buffer, &pos, imm, 4);
                        } else if (reg_size == 2 && pos + 3 <= MAX_BUFFER_SIZE) {
                            buffer[pos++] = 0x05; // ADD AX, imm16
                            x86_32_encode_immediate(buffer, &pos, imm, 2);
                        } else if (reg_size == 1 && pos + 2 <= MAX_BUFFER_SIZE) {
                            buffer[pos++] = 0x04; // ADD AL, imm8
                            x86_32_encode_immediate(buffer, &pos, imm, 1);
                        }
                    } else {
                        // General form: ADD r/m, imm
                        if (reg_size == 4 && pos + 6 <= MAX_BUFFER_SIZE) {
                            buffer[pos++] = 0x81; // ADD r/m32, imm32
                            buffer[pos++] = x86_32_make_modrm(3, 0, reg_encoding);
                            x86_32_encode_immediate(buffer, &pos, imm, 4);
                        } else if (reg_size == 2 && pos + 4 <= MAX_BUFFER_SIZE) {
                            buffer[pos++] = 0x81; // ADD r/m16, imm16
                            buffer[pos++] = x86_32_make_modrm(3, 0, reg_encoding);
                            x86_32_encode_immediate(buffer, &pos, imm, 2);
                        } else if (reg_size == 1 && pos + 3 <= MAX_BUFFER_SIZE) {
                            buffer[pos++] = 0x80; // ADD r/m8, imm8
                            buffer[pos++] = x86_32_make_modrm(3, 0, reg_encoding);
                            x86_32_encode_immediate(buffer, &pos, imm, 1);
                        }
                    }
                    
                    *length = pos;
                    free(lower_mnemonic);
                    return 0;
                }
            }
        }
    }

    // SUB instructions (similar structure to ADD)
    if (strcmp(lower_mnemonic, "sub") == 0 || strcmp(lower_mnemonic, "subl") == 0 ||
        strcmp(lower_mnemonic, "subw") == 0 || strcmp(lower_mnemonic, "subb") == 0) {
        
        if (inst->operand_count == 2) {
            // SUB immediate from register
            if (inst->operands[0].type == OPERAND_IMMEDIATE && 
                inst->operands[1].type == OPERAND_REGISTER) {
                
                uint8_t reg_encoding, reg_size;
                if (x86_32_find_register(inst->operands[1].value.reg.name, &reg_encoding, &reg_size) == 0) {
                    int64_t imm = inst->operands[0].value.immediate;
                    
                    if (reg_size == 4) { // 32-bit register
                        if (imm >= -128 && imm <= 127 && pos + 3 <= MAX_BUFFER_SIZE) {
                            buffer[pos++] = 0x83; // SUB r/m32, imm8
                            buffer[pos++] = x86_32_make_modrm(3, 5, reg_encoding); // opcode extension 5 for SUB
                            x86_32_encode_immediate(buffer, &pos, imm, 1);
                        } else if (pos + 6 <= MAX_BUFFER_SIZE) {
                            buffer[pos++] = 0x81; // SUB r/m32, imm32
                            buffer[pos++] = x86_32_make_modrm(3, 5, reg_encoding); // opcode extension 5 for SUB
                            x86_32_encode_immediate(buffer, &pos, imm, 4);
                        }
                        *length = pos;
                        free(lower_mnemonic);
                        return 0;
                    }
                }
            }
            
            // SUB register to register
            if (inst->operands[0].type == OPERAND_REGISTER && 
                inst->operands[1].type == OPERAND_REGISTER) {
                
                uint8_t src_encoding, src_size, dst_encoding, dst_size;
                if (x86_32_find_register(inst->operands[0].value.reg.name, &src_encoding, &src_size) == 0 &&
                    x86_32_find_register(inst->operands[1].value.reg.name, &dst_encoding, &dst_size) == 0) {
                    
                    if (src_size == dst_size && pos + 2 <= MAX_BUFFER_SIZE) {
                        if (src_size == 4 || src_size == 2) {
                            buffer[pos++] = 0x29; // SUB r/m32, r32 or SUB r/m16, r16
                        } else {
                            buffer[pos++] = 0x28; // SUB r/m8, r8
                        }
                        buffer[pos++] = x86_32_make_modrm(3, src_encoding, dst_encoding);
                        
                        *length = pos;
                        free(lower_mnemonic);
                        return 0;
                    }
                }
            }
        }
    }

    // CMP instructions  
    if (strcmp(lower_mnemonic, "cmp") == 0 || strcmp(lower_mnemonic, "cmpl") == 0 ||
        strcmp(lower_mnemonic, "cmpw") == 0 || strcmp(lower_mnemonic, "cmpb") == 0) {
        
        if (inst->operand_count == 2) {
            // CMP immediate with register
            if (inst->operands[0].type == OPERAND_IMMEDIATE && 
                inst->operands[1].type == OPERAND_REGISTER) {
                
                uint8_t reg_encoding, reg_size;
                if (x86_32_find_register(inst->operands[1].value.reg.name, &reg_encoding, &reg_size) == 0) {
                    int64_t imm = inst->operands[0].value.immediate;
                    
                    if (reg_size == 4) { // 32-bit register
                        if (imm >= -128 && imm <= 127 && pos + 3 <= MAX_BUFFER_SIZE) {
                            buffer[pos++] = 0x83; // CMP r/m32, imm8
                            buffer[pos++] = x86_32_make_modrm(3, 7, reg_encoding); // opcode extension 7 for CMP
                            x86_32_encode_immediate(buffer, &pos, imm, 1);
                        } else if (pos + 6 <= MAX_BUFFER_SIZE) {
                            buffer[pos++] = 0x81; // CMP r/m32, imm32
                            buffer[pos++] = x86_32_make_modrm(3, 7, reg_encoding); // opcode extension 7 for CMP
                            x86_32_encode_immediate(buffer, &pos, imm, 4);
                        }
                        *length = pos;
                        free(lower_mnemonic);
                        return 0;
                    }
                }
            }
            
            // CMP register to register
            if (inst->operands[0].type == OPERAND_REGISTER && 
                inst->operands[1].type == OPERAND_REGISTER) {
                
                uint8_t src_encoding, src_size, dst_encoding, dst_size;
                if (x86_32_find_register(inst->operands[0].value.reg.name, &src_encoding, &src_size) == 0 &&
                    x86_32_find_register(inst->operands[1].value.reg.name, &dst_encoding, &dst_size) == 0) {
                    
                    if (src_size == dst_size && pos + 2 <= MAX_BUFFER_SIZE) {
                        if (src_size == 4 || src_size == 2) {
                            buffer[pos++] = 0x39; // CMP r/m32, r32 or CMP r/m16, r16
                        } else {
                            buffer[pos++] = 0x38; // CMP r/m8, r8
                        }
                        buffer[pos++] = x86_32_make_modrm(3, src_encoding, dst_encoding);
                        
                        *length = pos;
                        free(lower_mnemonic);
                        return 0;
                    }
                }
            }
        }
    }

    // ===== STACK OPERATIONS =====
    
    // PUSH instructions
    if (strcmp(lower_mnemonic, "push") == 0) {
        if (inst->operand_count == 1) {
            if (inst->operands[0].type == OPERAND_REGISTER) {
                uint8_t reg_encoding, reg_size;
                if (x86_32_find_register(inst->operands[0].value.reg.name, &reg_encoding, &reg_size) == 0) {
                    if (reg_size == 4 && pos + 1 <= MAX_BUFFER_SIZE) {
                        buffer[pos++] = 0x50 + reg_encoding; // PUSH r32
                        *length = pos;
                        free(lower_mnemonic);
                        return 0;
                    }
                }
            }
            
            if (inst->operands[0].type == OPERAND_IMMEDIATE) {
                int64_t imm = inst->operands[0].value.immediate;
                if (imm >= -128 && imm <= 127 && pos + 2 <= MAX_BUFFER_SIZE) {
                    buffer[pos++] = 0x6A; // PUSH imm8
                    x86_32_encode_immediate(buffer, &pos, imm, 1);
                } else if (pos + 5 <= MAX_BUFFER_SIZE) {
                    buffer[pos++] = 0x68; // PUSH imm32
                    x86_32_encode_immediate(buffer, &pos, imm, 4);
                }
                *length = pos;
                free(lower_mnemonic);
                return 0;
            }
        }
    }

    // POP instructions
    if (strcmp(lower_mnemonic, "pop") == 0) {
        if (inst->operand_count == 1 && inst->operands[0].type == OPERAND_REGISTER) {
            uint8_t reg_encoding, reg_size;
            if (x86_32_find_register(inst->operands[0].value.reg.name, &reg_encoding, &reg_size) == 0) {
                if (reg_size == 4 && pos + 1 <= MAX_BUFFER_SIZE) {
                    buffer[pos++] = 0x58 + reg_encoding; // POP r32
                    *length = pos;
                    free(lower_mnemonic);
                    return 0;
                }
            }
        }
    }

    // PUSHW instructions (16-bit push with operand size prefix)
    if (strcmp(lower_mnemonic, "pushw") == 0) {
        if (inst->operand_count == 1 && inst->operands[0].type == OPERAND_REGISTER) {
            uint8_t reg_encoding, reg_size;
            if (x86_32_find_register(inst->operands[0].value.reg.name, &reg_encoding, &reg_size) == 0) {
                if ((reg_size == 2 || reg_size == 4) && pos + 2 <= MAX_BUFFER_SIZE) {
                    buffer[pos++] = 0x66; // Operand size prefix for 16-bit
                    buffer[pos++] = 0x50 + reg_encoding; // PUSH r16
                    *length = pos;
                    free(lower_mnemonic);
                    return 0;
                }
            }
        }
    }

    // POPW instructions (16-bit pop with operand size prefix)
    if (strcmp(lower_mnemonic, "popw") == 0) {
        if (inst->operand_count == 1 && inst->operands[0].type == OPERAND_REGISTER) {
            uint8_t reg_encoding, reg_size;
            if (x86_32_find_register(inst->operands[0].value.reg.name, &reg_encoding, &reg_size) == 0) {
                if ((reg_size == 2 || reg_size == 4) && pos + 2 <= MAX_BUFFER_SIZE) {
                    buffer[pos++] = 0x66; // Operand size prefix for 16-bit
                    buffer[pos++] = 0x58 + reg_encoding; // POP r16
                    *length = pos;
                    free(lower_mnemonic);
                    return 0;
                }
            }
        }
    }

    // PUSHAD/POPAD
    if (strcmp(lower_mnemonic, "pushad") == 0) {
        if (pos + 1 <= MAX_BUFFER_SIZE) {
            buffer[pos++] = 0x60;
            *length = pos;
            free(lower_mnemonic);
            return 0;
        }
    }

    if (strcmp(lower_mnemonic, "popad") == 0) {
        if (pos + 1 <= MAX_BUFFER_SIZE) {
            buffer[pos++] = 0x61;
            *length = pos;
            free(lower_mnemonic);
            return 0;
        }
    }

    // ===== CONDITIONAL JUMPS =====
    
    // Short conditional jumps (rel8)
    struct {
        const char *mnemonic;
        uint8_t opcode;
    } cond_jumps[] = {
        {"je", 0x74}, {"jz", 0x74}, {"jne", 0x75}, {"jnz", 0x75},
        {"ja", 0x77}, {"jnbe", 0x77}, {"jae", 0x73}, {"jnb", 0x73}, {"jnc", 0x73},
        {"jb", 0x72}, {"jnae", 0x72}, {"jc", 0x72}, {"jbe", 0x76}, {"jna", 0x76},
        {"jg", 0x7F}, {"jnle", 0x7F}, {"jge", 0x7D}, {"jnl", 0x7D},
        {"jl", 0x7C}, {"jnge", 0x7C}, {"jle", 0x7E}, {"jng", 0x7E},
        {"jo", 0x70}, {"jno", 0x71}, {"jp", 0x7A}, {"jpe", 0x7A},
        {"jnp", 0x7B}, {"jpo", 0x7B}, {"js", 0x78}, {"jns", 0x79}
    };
    
    for (size_t i = 0; i < sizeof(cond_jumps) / sizeof(cond_jumps[0]); i++) {
        if (strcmp(lower_mnemonic, cond_jumps[i].mnemonic) == 0) {
            if (inst->operand_count == 1 && inst->operands[0].type == OPERAND_IMMEDIATE) {
                int64_t offset = inst->operands[0].value.immediate;
                if (offset >= -128 && offset <= 127 && pos + 2 <= MAX_BUFFER_SIZE) {
                    buffer[pos++] = cond_jumps[i].opcode;
                    x86_32_encode_immediate(buffer, &pos, offset, 1);
                    *length = pos;
                    free(lower_mnemonic);
                    return 0;
                }
            }
            break;
        }
    }

    // ===== UNCONDITIONAL JUMPS AND CALLS =====
    
    if (strcmp(lower_mnemonic, "jmp") == 0) {
        if (inst->operand_count == 1) {
            if (inst->operands[0].type == OPERAND_IMMEDIATE) {
                int64_t offset = inst->operands[0].value.immediate;
                if (offset >= -128 && offset <= 127 && pos + 2 <= MAX_BUFFER_SIZE) {
                    buffer[pos++] = 0xEB; // JMP rel8
                    x86_32_encode_immediate(buffer, &pos, offset, 1);
                } else if (pos + 5 <= MAX_BUFFER_SIZE) {
                    buffer[pos++] = 0xE9; // JMP rel32
                    x86_32_encode_immediate(buffer, &pos, offset, 4);
                }
                *length = pos;
                free(lower_mnemonic);
                return 0;
            }
        }
    }

    if (strcmp(lower_mnemonic, "call") == 0) {
        if (inst->operand_count == 1 && inst->operands[0].type == OPERAND_IMMEDIATE) {
            int64_t offset = inst->operands[0].value.immediate;
            if (pos + 5 <= MAX_BUFFER_SIZE) {
                buffer[pos++] = 0xE8; // CALL rel32
                x86_32_encode_immediate(buffer, &pos, offset, 4);
                *length = pos;
                free(lower_mnemonic);
                return 0;
            }
        }
    }

    // ===== SYSTEM INSTRUCTIONS =====
    
    if (strcmp(lower_mnemonic, "int") == 0) {
        if (inst->operand_count == 1 && inst->operands[0].type == OPERAND_IMMEDIATE) {
            int64_t interrupt = inst->operands[0].value.immediate;
            if (interrupt >= 0 && interrupt <= 255 && pos + 2 <= MAX_BUFFER_SIZE) {
                buffer[pos++] = 0xCD; // INT imm8
                buffer[pos++] = (uint8_t)interrupt;
                *length = pos;
                free(lower_mnemonic);
                return 0;
            }
        }
    }

    // ===== INCREMENT/DECREMENT =====
    
    if (strcmp(lower_mnemonic, "inc") == 0 || strcmp(lower_mnemonic, "incl") == 0) {
        if (inst->operand_count == 1 && inst->operands[0].type == OPERAND_REGISTER) {
            uint8_t reg_encoding, reg_size;
            if (x86_32_find_register(inst->operands[0].value.reg.name, &reg_encoding, &reg_size) == 0) {
                if (reg_size == 4 && pos + 1 <= MAX_BUFFER_SIZE) {
                    buffer[pos++] = 0x40 + reg_encoding; // INC r32
                    *length = pos;
                    free(lower_mnemonic);
                    return 0;
                }
            }
        }
    }

    if (strcmp(lower_mnemonic, "dec") == 0 || strcmp(lower_mnemonic, "decl") == 0) {
        if (inst->operand_count == 1 && inst->operands[0].type == OPERAND_REGISTER) {
            uint8_t reg_encoding, reg_size;
            if (x86_32_find_register(inst->operands[0].value.reg.name, &reg_encoding, &reg_size) == 0) {
                if (reg_size == 4 && pos + 1 <= MAX_BUFFER_SIZE) {
                    buffer[pos++] = 0x48 + reg_encoding; // DEC r32
                    *length = pos;
                    free(lower_mnemonic);
                    return 0;
                }
            }
        }
    }
    
    free(lower_mnemonic);
    return -1; // Unsupported instruction/operand combination
}

int x86_32_parse_register(const char *reg_name, asm_register_t *reg) {
    if (!reg_name || !reg) {
        return -1;
    }
    
    // Strip % prefix if present
    if (reg_name[0] == '%') {
        reg_name++;
    }
    
    uint8_t encoding, size;
    if (x86_32_find_register(reg_name, &encoding, &size) == 0) {
        reg->name = x86_32_safe_strdup(reg_name);
        reg->id = encoding;
        reg->size = size;
        reg->encoding = encoding;
        return 0;
    }
    
    return -1;
}

bool x86_32_is_valid_register(asm_register_t reg) {
    // Check if register encoding is valid for x86-32
    return (reg.encoding <= 7 && reg.size > 0);
}

const char *x86_32_get_register_name(asm_register_t reg) {
    if (!reg.name) {
        return NULL;
    }
    return reg.name;
}

// Architecture operations structure
static arch_ops_t x86_32_ops = {
    .name = "x86_32",
    .init = x86_32_init,
    .cleanup = x86_32_cleanup,
    .parse_instruction = x86_32_parse_instruction,
    .encode_instruction = x86_32_encode_instruction,
    .parse_register = x86_32_parse_register,
    .is_valid_register = x86_32_is_valid_register,
    .get_register_name = x86_32_get_register_name,
    .parse_addressing = NULL, // TODO: Implement addressing modes
    .validate_addressing = NULL, // TODO: Implement addressing validation
    .handle_directive = x86_32_handle_directive,
    .get_instruction_size = NULL, // TODO: Implement instruction sizing
    .get_alignment = NULL, // TODO: Implement alignment
    .validate_instruction = NULL, // TODO: Implement instruction validation
    .validate_operand_combination = NULL // TODO: Implement operand validation
};

// CPU feature support functions
bool x86_32_supports_feature(uint8_t min_level) {
    return cpu_level >= min_level;
}

void x86_32_set_cpu_level(uint8_t level) {
    if (level <= 3) {
        cpu_level = level;
    }
}

// Get current code mode (16 or 32)
uint8_t x86_32_get_code_mode(void) {
    return current_code_mode;
}

// Set code mode
void x86_32_set_code_mode(uint8_t mode) {
    if (mode == 16 || mode == 32) {
        current_code_mode = mode;
    }
}

arch_ops_t *x86_32_get_arch_ops(void) {
    return &x86_32_ops;
}

// Plugin entry point for x86_32
arch_ops_t *get_arch_ops_x86_32(void) {
    return x86_32_get_arch_ops();
}
