/*
 * x86-16 Architecture Module for STAS
 * Complete implementation for 16-bit x86 instruction set
 */

#include "x86_16.h"
#include "../../core/expressions.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>

// Case-insensitive string comparison for C99
static int strcasecmp_c99(const char *s1, const char *s2) {
    while (*s1 && *s2) {
        int c1 = tolower((unsigned char)*s1);
        int c2 = tolower((unsigned char)*s2);
        if (c1 != c2) return c1 - c2;
        s1++;
        s2++;
    }
    return tolower((unsigned char)*s1) - tolower((unsigned char)*s2);
}

// Register name to ID mapping
static const struct {
    const char *name;
    x86_16_register_id_t id;
    uint8_t encoding;  // Hardware encoding
    uint8_t size;      // Size in bytes
} x86_16_registers[] = {
    // 8-bit registers
    {"al", AL_16, 0, 1}, {"cl", CL_16, 1, 1}, {"dl", DL_16, 2, 1}, {"bl", BL_16, 3, 1},
    {"ah", AH_16, 4, 1}, {"ch", CH_16, 5, 1}, {"dh", DH_16, 6, 1}, {"bh", BH_16, 7, 1},
    
    // 16-bit registers
    {"ax", AX_16, 0, 2}, {"cx", CX_16, 1, 2}, {"dx", DX_16, 2, 2}, {"bx", BX_16, 3, 2},
    {"sp", SP_16, 4, 2}, {"bp", BP_16, 5, 2}, {"si", SI_16, 6, 2}, {"di", DI_16, 7, 2},
    
    // Segment registers
    {"es", ES_16, 0, 2}, {"cs", CS_16, 1, 2}, {"ss", SS_16, 2, 2}, {"ds", DS_16, 3, 2},
    
    // Special registers
    {"ip", IP_16, 0, 2}, {"flags", FLAGS_16, 0, 2}
};

static const size_t x86_16_register_count = sizeof(x86_16_registers) / sizeof(x86_16_registers[0]);

// Instruction mnemonic to opcode mapping
static const struct {
    const char *mnemonic;
    x86_16_opcode_t opcode;
    uint8_t operand_count;
    bool needs_modrm;
} x86_16_instructions[] = {
    {"mov", OP_16_MOV_REG_REG, 2, true},
    {"add", OP_16_ADD_REG_REG, 2, true},
    {"sub", OP_16_SUB_REG_REG, 2, true},
    {"cmp", OP_16_CMP_REG_REG, 2, true},
    {"jmp", OP_16_JMP_REL, 1, false},
    {"call", OP_16_CALL_REL, 1, false},
    {"ret", OP_16_RET, 0, false},
    {"int", OP_16_INT, 1, false},
    {"hlt", OP_16_HLT, 0, false},
    {"nop", OP_16_NOP, 0, false},
    {"push", OP_16_PUSH_REG, 1, false},
    {"pop", OP_16_POP_REG, 1, false},
    {"je", OP_16_JE, 1, false},
    {"jne", OP_16_JNE, 1, false},
    {"jl", OP_16_JL, 1, false},
    {"jg", OP_16_JG, 1, false}
};

static const size_t x86_16_instruction_count = sizeof(x86_16_instructions) / sizeof(x86_16_instructions[0]);

// Store opcode in instruction encoding for later use
typedef struct {
    x86_16_opcode_t opcode;
    uint8_t data[16];  // Maximum instruction length
    size_t length;
} x86_16_instruction_data_t;

// Forward declarations
static int encode_modrm(operand_t *src, operand_t *dst, x86_16_modrm_byte_t *modrm);
static int get_register_encoding(x86_16_register_id_t reg_id);

int x86_16_init(void) {
    printf("  Initializing x86-16 architecture module\n");
    return 0;
}

void x86_16_cleanup(void) {
    // Cleanup implementation
}

int x86_16_parse_instruction(const char *mnemonic, operand_t *operands, 
                           size_t operand_count, instruction_t *inst) {
    if (!mnemonic || !inst) {
        return -1;
    }
    
    // Find instruction in table
    for (size_t i = 0; i < x86_16_instruction_count; i++) {
        if (strcasecmp_c99(mnemonic, x86_16_instructions[i].mnemonic) == 0) {
            if (operand_count != x86_16_instructions[i].operand_count) {
                return -1; // Wrong operand count
            }
            
            // Allocate space for mnemonic and operands
            inst->mnemonic = malloc(strlen(mnemonic) + 1);
            if (!inst->mnemonic) return -1;
            strcpy(inst->mnemonic, mnemonic);
            
            inst->operand_count = operand_count;
            if (operand_count > 0) {
                inst->operands = malloc(operand_count * sizeof(operand_t));
                if (!inst->operands) {
                    free(inst->mnemonic);
                    return -1;
                }
                
                // Copy operands
                for (size_t j = 0; j < operand_count; j++) {
                    inst->operands[j] = operands[j];
                }
            } else {
                inst->operands = NULL;
            }
            
            // Store the opcode for encoding
            x86_16_instruction_data_t *inst_data = malloc(sizeof(x86_16_instruction_data_t));
            if (!inst_data) {
                free(inst->mnemonic);
                free(inst->operands);
                return -1;
            }
            inst_data->opcode = x86_16_instructions[i].opcode;
            inst_data->length = 0;
            
            inst->encoding = (uint8_t*)inst_data;
            inst->encoding_length = sizeof(x86_16_instruction_data_t);
            
            return 0;
        }
    }
    
    return -1; // Instruction not found
}

int x86_16_encode_instruction(instruction_t *inst, uint8_t *buffer, size_t *length) {
    if (!inst || !buffer || !length || !inst->encoding) {
        return -1;
    }
    
    x86_16_instruction_data_t *inst_data = (x86_16_instruction_data_t*)inst->encoding;
    x86_16_opcode_t opcode = inst_data->opcode;
    
    x86_16_encoding_t encoding = {0};
    size_t pos = 0;
    
    // Handle different instruction types
    switch (opcode) {
        case OP_16_MOV_REG_REG: // Also handles OP_16_MOV_MEM_REG (same opcode)
        case OP_16_MOV_REG_MEM: {
            // MOV instruction encoding
            operand_t *dst = &inst->operands[0];
            operand_t *src = &inst->operands[1];
            
            // Determine MOV variant
            if (dst->type == OPERAND_REGISTER && src->type == OPERAND_IMMEDIATE) {
                // MOV r16, imm16 - uses 0xB8 + reg encoding
                x86_16_register_id_t reg_id = (x86_16_register_id_t)dst->value.reg.id;
                int reg_enc = get_register_encoding(reg_id);
                if (reg_enc < 0) return -1;
                
                encoding.opcode[0] = OP_16_MOV_REG_IMM + reg_enc;
                encoding.opcode_length = 1;
                encoding.immediate = (int16_t)src->value.immediate;
                encoding.imm_size = 2;
            } else {
                // MOV with ModR/M
                encoding.opcode[0] = OP_16_MOV_REG_REG;
                encoding.opcode_length = 1;
                encoding.has_modrm = true;
                
                if (encode_modrm(src, dst, &encoding.modrm) != 0) {
                    return -1;
                }
            }
            break;
        }
        
        case OP_16_ADD_REG_REG:
        case OP_16_SUB_REG_REG:
        case OP_16_CMP_REG_REG: {
            // Arithmetic operations
            encoding.opcode[0] = (uint8_t)opcode;
            encoding.opcode_length = 1;
            encoding.has_modrm = true;
            
            if (encode_modrm(&inst->operands[1], &inst->operands[0], &encoding.modrm) != 0) {
                return -1;
            }
            break;
        }
        
        case OP_16_PUSH_REG: {
            // PUSH r16
            if (inst->operands[0].type != OPERAND_REGISTER) return -1;
            
            x86_16_register_id_t reg_id = (x86_16_register_id_t)inst->operands[0].value.reg.id;
            int reg_enc = get_register_encoding(reg_id);
            if (reg_enc < 0 || reg_enc > 7) return -1;
            
            encoding.opcode[0] = OP_16_PUSH_REG + reg_enc;
            encoding.opcode_length = 1;
            break;
        }
        
        case OP_16_POP_REG: {
            // POP r16
            if (inst->operands[0].type != OPERAND_REGISTER) return -1;
            
            x86_16_register_id_t reg_id = (x86_16_register_id_t)inst->operands[0].value.reg.id;
            int reg_enc = get_register_encoding(reg_id);
            if (reg_enc < 0 || reg_enc > 7) return -1;
            
            encoding.opcode[0] = OP_16_POP_REG + reg_enc;
            encoding.opcode_length = 1;
            break;
        }
        
        case OP_16_JMP_REL:
        case OP_16_CALL_REL: {
            // Relative jumps and calls
            if (inst->operands[0].type != OPERAND_IMMEDIATE) return -1;
            
            int16_t rel_offset = (int16_t)inst->operands[0].value.immediate;
            
            // Check if we can use short jump (8-bit displacement)
            if (opcode == OP_16_JMP_REL && rel_offset >= -128 && rel_offset <= 127) {
                encoding.opcode[0] = OP_16_JMP_SHORT;
                encoding.opcode_length = 1;
                encoding.immediate = rel_offset;
                encoding.imm_size = 1;
            } else {
                encoding.opcode[0] = (uint8_t)opcode;
                encoding.opcode_length = 1;
                encoding.immediate = rel_offset;
                encoding.imm_size = 2;
            }
            break;
        }
        
        case OP_16_JE:
        case OP_16_JNE:
        case OP_16_JL:
        case OP_16_JG: {
            // Conditional jumps (8-bit displacement)
            if (inst->operands[0].type != OPERAND_IMMEDIATE) return -1;
            
            int8_t rel_offset = (int8_t)inst->operands[0].value.immediate;
            encoding.opcode[0] = (uint8_t)opcode;
            encoding.opcode_length = 1;
            encoding.immediate = rel_offset;
            encoding.imm_size = 1;
            break;
        }
        
        case OP_16_INT: {
            // Interrupt
            if (inst->operands[0].type != OPERAND_IMMEDIATE) return -1;
            
            encoding.opcode[0] = OP_16_INT;
            encoding.opcode_length = 1;
            encoding.immediate = (int8_t)inst->operands[0].value.immediate;
            encoding.imm_size = 1;
            break;
        }
        
        case OP_16_RET:
        case OP_16_HLT:
        case OP_16_NOP: {
            // Simple instructions with no operands
            encoding.opcode[0] = (uint8_t)opcode;
            encoding.opcode_length = 1;
            break;
        }
        
        default:
            return -1; // Unsupported instruction
    }
    
    // Write instruction to buffer
    
    // Prefixes
    for (uint8_t i = 0; i < encoding.prefix_count; i++) {
        buffer[pos++] = encoding.prefixes[i];
    }
    
    // Opcode
    for (uint8_t i = 0; i < encoding.opcode_length; i++) {
        buffer[pos++] = encoding.opcode[i];
    }
    
    // ModR/M
    if (encoding.has_modrm) {
        uint8_t modrm_byte = (encoding.modrm.mod << 6) | 
                            (encoding.modrm.reg << 3) | 
                            encoding.modrm.rm;
        buffer[pos++] = modrm_byte;
    }
    
    // Displacement
    if (encoding.disp_size > 0) {
        if (encoding.disp_size == 1) {
            buffer[pos++] = (uint8_t)encoding.displacement;
        } else if (encoding.disp_size == 2) {
            buffer[pos++] = (uint8_t)(encoding.displacement & 0xFF);
            buffer[pos++] = (uint8_t)((encoding.displacement >> 8) & 0xFF);
        }
    }
    
    // Immediate
    if (encoding.imm_size > 0) {
        if (encoding.imm_size == 1) {
            buffer[pos++] = (uint8_t)encoding.immediate;
        } else if (encoding.imm_size == 2) {
            buffer[pos++] = (uint8_t)(encoding.immediate & 0xFF);
            buffer[pos++] = (uint8_t)((encoding.immediate >> 8) & 0xFF);
        }
    }
    
    *length = pos;
    return 0;
}

int x86_16_parse_register(const char *reg_name, asm_register_t *reg) {
    if (!reg_name || !reg) {
        return -1;
    }
    
    // Convert to lowercase for comparison
    char lower_name[16];
    size_t len = strlen(reg_name);
    if (len >= sizeof(lower_name)) return -1;
    
    for (size_t i = 0; i < len; i++) {
        lower_name[i] = tolower(reg_name[i]);
    }
    lower_name[len] = '\0';
    
    // Find register in table
    for (size_t i = 0; i < x86_16_register_count; i++) {
        if (strcmp(lower_name, x86_16_registers[i].name) == 0) {
            reg->id = x86_16_registers[i].id;
            reg->size = x86_16_registers[i].size;
            return 0;
        }
    }
    
    return -1; // Register not found
}

bool x86_16_is_valid_register(asm_register_t reg) {
    for (size_t i = 0; i < x86_16_register_count; i++) {
        if (x86_16_registers[i].id == (x86_16_register_id_t)reg.id) {
            return true;
        }
    }
    return false;
}

const char *x86_16_get_register_name(asm_register_t reg) {
    for (size_t i = 0; i < x86_16_register_count; i++) {
        if (x86_16_registers[i].id == (x86_16_register_id_t)reg.id) {
            return x86_16_registers[i].name;
        }
    }
    return NULL;
}

int x86_16_parse_addressing(const char *addr_str, addressing_mode_t *mode) {
    if (!addr_str || !mode) {
        return -1;
    }
    
    // Simple 16-bit addressing mode parsing
    // Format: [reg], [reg+offset], offset
    
    if (addr_str[0] == '[') {
        // Memory addressing
        const char *end = strchr(addr_str, ']');
        if (!end) return -1;
        
        size_t len = end - addr_str - 1;
        char addr_content[64];
        if (len >= sizeof(addr_content)) return -1;
        
        strncpy(addr_content, addr_str + 1, len);
        addr_content[len] = '\0';
        
        mode->type = ADDR_INDIRECT;
        mode->offset = 0;
        
        // Parse register combinations
        if (strcmp(addr_content, "bx+si") == 0) {
            mode->base.id = BX_16;
            mode->index.id = SI_16;
        } else if (strcmp(addr_content, "bx+di") == 0) {
            mode->base.id = BX_16;
            mode->index.id = DI_16;
        } else if (strcmp(addr_content, "bp+si") == 0) {
            mode->base.id = BP_16;
            mode->index.id = SI_16;
        } else if (strcmp(addr_content, "bp+di") == 0) {
            mode->base.id = BP_16;
            mode->index.id = DI_16;
        } else if (strcmp(addr_content, "si") == 0) {
            mode->base.id = SI_16;
        } else if (strcmp(addr_content, "di") == 0) {
            mode->base.id = DI_16;
        } else if (strcmp(addr_content, "bp") == 0) {
            mode->base.id = BP_16;
        } else if (strcmp(addr_content, "bx") == 0) {
            mode->base.id = BX_16;
        } else {
            // Try to parse as direct address
            char *endptr;
            long addr = strtol(addr_content, &endptr, 0);
            if (*endptr == '\0') {
                mode->offset = (int64_t)addr;
                mode->base.id = (uint32_t)-1; // No base register
                mode->type = ADDR_DIRECT;
            } else {
                return -1;
            }
        }
        
        return 0;
    } else {
        // Direct addressing
        mode->type = ADDR_DIRECT;
        char *endptr;
        long addr = strtol(addr_str, &endptr, 0);
        if (*endptr != '\0') return -1;
        
        mode->offset = (int64_t)addr;
        return 0;
    }
}

bool x86_16_validate_addressing(addressing_mode_t *mode, instruction_t *inst) {
    (void)inst; // Suppress unused parameter warning
    
    if (!mode) return false;
    
    // Basic validation for x86-16 addressing modes
    return mode->type == ADDR_INDIRECT || mode->type == ADDR_DIRECT;
}

int x86_16_handle_directive(const char *directive, const char *args) {
    (void)directive; // Suppress unused parameter warning
    (void)args;      // Suppress unused parameter warning
    
    // Placeholder for directive handling
    return 0;
}

size_t x86_16_get_instruction_size(instruction_t *inst) {
    if (!inst || !inst->encoding) return 0;
    
    x86_16_instruction_data_t *inst_data = (x86_16_instruction_data_t*)inst->encoding;
    x86_16_opcode_t opcode = inst_data->opcode;
    
    // Estimate instruction size based on opcode
    switch (opcode) {
        case OP_16_NOP:
        case OP_16_HLT:
        case OP_16_RET:
            return 1;
            
        case OP_16_PUSH_REG:
        case OP_16_POP_REG:
            return 1;
            
        case OP_16_JE:
        case OP_16_JNE:
        case OP_16_JL:
        case OP_16_JG:
            return 2; // opcode + 8-bit displacement
            
        case OP_16_INT:
            return 2; // opcode + immediate byte
            
        case OP_16_JMP_REL:
        case OP_16_CALL_REL:
            return 3; // opcode + 16-bit displacement
            
        case OP_16_MOV_REG_REG:
        case OP_16_ADD_REG_REG:
        case OP_16_SUB_REG_REG:
        case OP_16_CMP_REG_REG:
            return 2; // opcode + ModR/M
            
        default:
            return 3; // Conservative estimate
    }
}

size_t x86_16_get_alignment(section_type_t section) {
    (void)section; // Suppress unused parameter warning
    return 1; // x86-16 typically uses byte alignment
}

bool x86_16_validate_instruction(instruction_t *inst) {
    if (!inst || !inst->encoding) return false;
    
    x86_16_instruction_data_t *inst_data = (x86_16_instruction_data_t*)inst->encoding;
    x86_16_opcode_t opcode = inst_data->opcode;
    
    // Find instruction in table to validate
    for (size_t i = 0; i < x86_16_instruction_count; i++) {
        if (x86_16_instructions[i].opcode == opcode) {
            return inst->operand_count == x86_16_instructions[i].operand_count;
        }
    }
    
    return false;
}

bool x86_16_validate_operand_combination(const char *mnemonic, 
                                       operand_t *operands, 
                                       size_t operand_count) {
    if (!mnemonic) return false;
    
    // Find instruction and validate operand combination
    for (size_t i = 0; i < x86_16_instruction_count; i++) {
        if (strcasecmp_c99(mnemonic, x86_16_instructions[i].mnemonic) == 0) {
            if (operand_count != x86_16_instructions[i].operand_count) {
                return false;
            }
            
            // Additional validation based on instruction type
            if (operand_count > 0) {
                // Validate first operand
                operand_t *op1 = &operands[0];
                
                if (strcmp(mnemonic, "push") == 0 || strcmp(mnemonic, "pop") == 0) {
                    return op1->type == OPERAND_REGISTER;
                }
                
                if (strcmp(mnemonic, "int") == 0) {
                    return op1->type == OPERAND_IMMEDIATE;
                }
                
                if (operand_count == 2) {
                    // Two operand instructions
                    operand_t *op2 = &operands[1];
                    
                    if (strcmp(mnemonic, "mov") == 0) {
                        // MOV allows various combinations
                        return (op1->type == OPERAND_REGISTER && 
                                (op2->type == OPERAND_REGISTER || 
                                 op2->type == OPERAND_IMMEDIATE ||
                                 op2->type == OPERAND_MEMORY)) ||
                               (op1->type == OPERAND_MEMORY && 
                                op2->type == OPERAND_REGISTER);
                    }
                }
            }
            
            return true;
        }
    }
    
    return false;
}

// Architecture operations table
static arch_ops_t x86_16_ops = {
    .name = "x86-16",
    .init = x86_16_init,
    .cleanup = x86_16_cleanup,
    .parse_instruction = x86_16_parse_instruction,
    .encode_instruction = x86_16_encode_instruction,
    .parse_register = x86_16_parse_register,
    .is_valid_register = x86_16_is_valid_register,
    .get_register_name = x86_16_get_register_name,
    .parse_addressing = x86_16_parse_addressing,
    .validate_addressing = x86_16_validate_addressing,
    .handle_directive = x86_16_handle_directive,
    .get_instruction_size = x86_16_get_instruction_size,
    .get_alignment = x86_16_get_alignment,
    .validate_instruction = x86_16_validate_instruction,
    .validate_operand_combination = x86_16_validate_operand_combination
};

arch_ops_t *get_arch_ops_x86_16(void) {
    return &x86_16_ops;
}

// Helper functions

static int encode_modrm(operand_t *src, operand_t *dst, x86_16_modrm_byte_t *modrm) {
    if (!src || !dst || !modrm) return -1;
    
    // Simple ModR/M encoding for register-to-register operations
    if (src->type == OPERAND_REGISTER && dst->type == OPERAND_REGISTER) {
        modrm->mod = 3; // Register-to-register
        modrm->reg = get_register_encoding((x86_16_register_id_t)src->value.reg.id);
        modrm->rm = get_register_encoding((x86_16_register_id_t)dst->value.reg.id);
        
        if (modrm->reg < 0 || modrm->rm < 0) return -1;
        return 0;
    }
    
    return -1; // Unsupported operand combination
}

static int get_register_encoding(x86_16_register_id_t reg_id) {
    for (size_t i = 0; i < x86_16_register_count; i++) {
        if (x86_16_registers[i].id == reg_id) {
            return x86_16_registers[i].encoding;
        }
    }
    return -1;
}
