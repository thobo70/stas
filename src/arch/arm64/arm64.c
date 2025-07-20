/*
 * ARM64 (AArch64) Architecture Module for STAS
 * ARMv8-A 64-bit instruction set implementation
 */

#define _GNU_SOURCE  // Enable strdup and other GNU extensions
#include "arm64.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>

#define MAX_OPERANDS 3  // ARM64 instructions typically have at most 3 operands

//=============================================================================
// ARM64 Register Tables
//=============================================================================

// ARM64 X registers (64-bit)
static const struct {
    const char *name;
    arm64_x_register_t id;
    uint8_t size;
    uint8_t encoding;
} arm64_x_registers[] = {
    {"x0", ARM64_X0, 8, 0}, {"x1", ARM64_X1, 8, 1}, {"x2", ARM64_X2, 8, 2}, {"x3", ARM64_X3, 8, 3},
    {"x4", ARM64_X4, 8, 4}, {"x5", ARM64_X5, 8, 5}, {"x6", ARM64_X6, 8, 6}, {"x7", ARM64_X7, 8, 7},
    {"x8", ARM64_X8, 8, 8}, {"x9", ARM64_X9, 8, 9}, {"x10", ARM64_X10, 8, 10}, {"x11", ARM64_X11, 8, 11},
    {"x12", ARM64_X12, 8, 12}, {"x13", ARM64_X13, 8, 13}, {"x14", ARM64_X14, 8, 14}, {"x15", ARM64_X15, 8, 15},
    {"x16", ARM64_X16, 8, 16}, {"x17", ARM64_X17, 8, 17}, {"x18", ARM64_X18, 8, 18}, {"x19", ARM64_X19, 8, 19},
    {"x20", ARM64_X20, 8, 20}, {"x21", ARM64_X21, 8, 21}, {"x22", ARM64_X22, 8, 22}, {"x23", ARM64_X23, 8, 23},
    {"x24", ARM64_X24, 8, 24}, {"x25", ARM64_X25, 8, 25}, {"x26", ARM64_X26, 8, 26}, {"x27", ARM64_X27, 8, 27},
    {"x28", ARM64_X28, 8, 28}, {"x29", ARM64_X29, 8, 29}, {"x30", ARM64_X30, 8, 30}, {"xzr", ARM64_XZR, 8, 31},
    {NULL, 0, 0, 0}
};

// ARM64 W registers (32-bit)
static const struct {
    const char *name;
    arm64_w_register_t id;
    uint8_t size;
    uint8_t encoding;
} arm64_w_registers[] = {
    {"w0", ARM64_W0, 4, 0}, {"w1", ARM64_W1, 4, 1}, {"w2", ARM64_W2, 4, 2}, {"w3", ARM64_W3, 4, 3},
    {"w4", ARM64_W4, 4, 4}, {"w5", ARM64_W5, 4, 5}, {"w6", ARM64_W6, 4, 6}, {"w7", ARM64_W7, 4, 7},
    {"w8", ARM64_W8, 4, 8}, {"w9", ARM64_W9, 4, 9}, {"w10", ARM64_W10, 4, 10}, {"w11", ARM64_W11, 4, 11},
    {"w12", ARM64_W12, 4, 12}, {"w13", ARM64_W13, 4, 13}, {"w14", ARM64_W14, 4, 14}, {"w15", ARM64_W15, 4, 15},
    {"w16", ARM64_W16, 4, 16}, {"w17", ARM64_W17, 4, 17}, {"w18", ARM64_W18, 4, 18}, {"w19", ARM64_W19, 4, 19},
    {"w20", ARM64_W20, 4, 20}, {"w21", ARM64_W21, 4, 21}, {"w22", ARM64_W22, 4, 22}, {"w23", ARM64_W23, 4, 23},
    {"w24", ARM64_W24, 4, 24}, {"w25", ARM64_W25, 4, 25}, {"w26", ARM64_W26, 4, 26}, {"w27", ARM64_W27, 4, 27},
    {"w28", ARM64_W28, 4, 28}, {"w29", ARM64_W29, 4, 29}, {"w30", ARM64_W30, 4, 30}, {"wzr", ARM64_WZR, 4, 31},
    {NULL, 0, 0, 0}
};

// Special registers
static const struct {
    const char *name;
    uint8_t encoding;
    uint8_t size;
} arm64_special_registers[] = {
    {"sp", 31, 8},    // Stack Pointer
    {"lr", 30, 8},    // Link Register (same as X30)
    {"fp", 29, 8},    // Frame Pointer (same as X29)
    {NULL, 0, 0}
};

//=============================================================================
// ARM64 Instruction Table
//=============================================================================

static const arm64_instruction_t arm64_instructions[] = {
    // Data processing - immediate
    {"add",  0x11000000, 0x11000000, ARM64_FORMAT_DATA_PROCESSING_IMM, true,  true,  false, true,  "Add immediate"},
    {"sub",  0x51000000, 0x51000000, ARM64_FORMAT_DATA_PROCESSING_IMM, true,  true,  false, true,  "Subtract immediate"},
    {"mov",  0x52800000, 0x52800000, ARM64_FORMAT_DATA_PROCESSING_IMM, true,  false, false, true,  "Move immediate"},
    
    // Data processing - register
    {"add",  0x0b000000, 0x0b000000, ARM64_FORMAT_DATA_PROCESSING_REG, true,  true,  true,  false, "Add register"},
    {"sub",  0x4b000000, 0x4b000000, ARM64_FORMAT_DATA_PROCESSING_REG, true,  true,  true,  false, "Subtract register"},
    {"mov",  0x2a000000, 0x2a000000, ARM64_FORMAT_DATA_PROCESSING_REG, true,  false, true,  false, "Move register"},
    
    // Load/store
    {"ldr",  0xf9400000, 0xf9400000, ARM64_FORMAT_LOAD_STORE, true,  true,  false, true,  "Load register"},
    {"str",  0xf9000000, 0xf9000000, ARM64_FORMAT_LOAD_STORE, false, true,  true,  true,  "Store register"},
    
    // Branch
    {"b",    0x14000000, 0x14000000, ARM64_FORMAT_BRANCH, false, false, false, true,  "Unconditional branch"},
    {"bl",   0x94000000, 0x94000000, ARM64_FORMAT_BRANCH, false, false, false, true,  "Branch with link"},
    {"ret",  0xd65f0000, 0xd65f03c0, ARM64_FORMAT_BRANCH, false, false, false, false, "Return"},
    
    // System
    {"nop",  0xd503201f, 0xd503201f, ARM64_FORMAT_SYSTEM, false, false, false, false, "No operation"},
    
    {NULL, 0, 0, ARM64_FORMAT_UNKNOWN, false, false, false, false, NULL}
};

//=============================================================================
// Utility Functions
//=============================================================================

// Safe string duplication
static char *arm64_safe_strdup(const char *s) {
    if (!s) return NULL;
    size_t len = strlen(s) + 1;
    char *dup = malloc(len);
    if (dup) {
        memcpy(dup, s, len);
    }
    return dup;
}

// Convert string to lowercase
static char *arm64_strlower(const char *str) {
    if (!str) return NULL;
    
    char *lower = arm64_safe_strdup(str);
    if (!lower) return NULL;
    
    for (char *p = lower; *p; p++) {
        *p = tolower(*p);
    }
    return lower;
}

//=============================================================================
// ARM64 Architecture Interface Implementation
//=============================================================================

int arm64_init(void) {
    // Initialize ARM64 architecture module
    return 0;
}

void arm64_cleanup(void) {
    // Cleanup ARM64 architecture module
}

//=============================================================================
// Register Parsing and Validation
//=============================================================================

int parse_arm64_register(const char *reg_name, uint8_t *reg_num, uint8_t *size) {
    if (!reg_name || !reg_num || !size) {
        return -1;
    }
    
    // Remove % prefix if present (for compatibility)
    const char *name = (reg_name[0] == '%') ? reg_name + 1 : reg_name;
    
    // Convert to lowercase for comparison
    char *lower_name = arm64_strlower(name);
    if (!lower_name) return -1;
    
    // Check X registers (64-bit)
    for (int i = 0; arm64_x_registers[i].name != NULL; i++) {
        if (strcmp(lower_name, arm64_x_registers[i].name) == 0) {
            *reg_num = arm64_x_registers[i].encoding;
            *size = arm64_x_registers[i].size;
            free(lower_name);
            return 0;
        }
    }
    
    // Check W registers (32-bit)
    for (int i = 0; arm64_w_registers[i].name != NULL; i++) {
        if (strcmp(lower_name, arm64_w_registers[i].name) == 0) {
            *reg_num = arm64_w_registers[i].encoding;
            *size = arm64_w_registers[i].size;
            free(lower_name);
            return 0;
        }
    }
    
    // Check special registers
    for (int i = 0; arm64_special_registers[i].name != NULL; i++) {
        if (strcmp(lower_name, arm64_special_registers[i].name) == 0) {
            *reg_num = arm64_special_registers[i].encoding;
            *size = arm64_special_registers[i].size;
            free(lower_name);
            return 0;
        }
    }
    
    free(lower_name);
    return -1; // Register not found
}

bool is_arm64_register(const char *reg_name) {
    uint8_t dummy_reg, dummy_size;
    return parse_arm64_register(reg_name, &dummy_reg, &dummy_size) == 0;
}

const char* get_arm64_register_name(uint8_t reg_num, uint8_t size) {
    // Return register name for given number and size
    if (size == 8) {
        // 64-bit X registers
        for (int i = 0; arm64_x_registers[i].name != NULL; i++) {
            if (arm64_x_registers[i].encoding == reg_num) {
                return arm64_x_registers[i].name;
            }
        }
    } else if (size == 4) {
        // 32-bit W registers
        for (int i = 0; arm64_w_registers[i].name != NULL; i++) {
            if (arm64_w_registers[i].encoding == reg_num) {
                return arm64_w_registers[i].name;
            }
        }
    }
    
    return NULL;
}

//=============================================================================
// Register Parsing and Management
//=============================================================================

int arm64_parse_register(const char *reg_name, asm_register_t *reg) {
    if (!reg_name || !reg) {
        return -1;
    }
    
    // Parse X registers (64-bit)
    for (int i = 0; arm64_x_registers[i].name != NULL; i++) {
        if (strcmp(reg_name, arm64_x_registers[i].name) == 0) {
            reg->id = arm64_x_registers[i].id;
            reg->name = strdup(reg_name);
            reg->size = arm64_x_registers[i].size;
            reg->encoding = arm64_x_registers[i].encoding;
            return 0;
        }
    }
    
    // Parse W registers (32-bit)
    for (int i = 0; arm64_w_registers[i].name != NULL; i++) {
        if (strcmp(reg_name, arm64_w_registers[i].name) == 0) {
            reg->id = arm64_w_registers[i].id + 100; // Offset to differentiate from X registers
            reg->name = strdup(reg_name);
            reg->size = arm64_w_registers[i].size;
            reg->encoding = arm64_w_registers[i].encoding;
            return 0;
        }
    }
    
    // Parse special registers
    for (int i = 0; arm64_special_registers[i].name != NULL; i++) {
        if (strcmp(reg_name, arm64_special_registers[i].name) == 0) {
            reg->id = 300 + i; // Offset for special registers
            reg->name = strdup(reg_name);
            reg->size = arm64_special_registers[i].size;
            reg->encoding = arm64_special_registers[i].encoding;
            return 0;
        }
    }
    
    // Parse V registers (vector) - dynamic parsing
    int reg_num;
    if (sscanf(reg_name, "v%d", &reg_num) == 1) {
        if (reg_num >= 0 && reg_num <= 31) {
            reg->id = reg_num + 200; // Offset for V registers
            reg->name = strdup(reg_name);
            reg->size = 16; // 128-bit vector
            reg->encoding = reg_num;
            return 0;
        }
    }
    
    return -1; // Unknown register
}

bool is_arm64_register_impl(asm_register_t reg) {
    // Check if register ID is in valid ranges
    if (reg.id <= 31) return true;     // X registers
    if (reg.id >= 100 && reg.id <= 131) return true;  // W registers  
    if (reg.id >= 200 && reg.id <= 231) return true;  // V registers
    return false;
}

const char *get_arm64_register_name_impl(asm_register_t reg) {
    return reg.name;
}

//=============================================================================
// Instruction Parsing and Validation
//=============================================================================

int arm64_parse_instruction(const char *mnemonic, operand_t *operands, 
                           size_t operand_count, instruction_t *inst) {
    if (!mnemonic || !inst) {
        return -1;
    }
    
    // Initialize instruction structure
    memset(inst, 0, sizeof(instruction_t));
    inst->mnemonic = arm64_safe_strdup(mnemonic);
    if (!inst->mnemonic) {
        return -1;
    }
    
    // Copy operands
    inst->operand_count = operand_count;
    if (operand_count > 0 && operands) {
        inst->operands = malloc(operand_count * sizeof(operand_t));
        if (!inst->operands) {
            free(inst->mnemonic);
            return -1;
        }
        for (size_t i = 0; i < operand_count; i++) {
            inst->operands[i] = operands[i];
        }
    } else {
        inst->operands = NULL;
    }
    
    return 0;
}

bool arm64_validate_instruction(instruction_t *inst) {
    if (!inst || !inst->mnemonic) {
        return false;
    }
    
    // Find instruction in table
    char *lower_mnemonic = arm64_strlower(inst->mnemonic);
    if (!lower_mnemonic) return false;
    
    for (int i = 0; arm64_instructions[i].mnemonic != NULL; i++) {
        if (strcmp(lower_mnemonic, arm64_instructions[i].mnemonic) == 0) {
            free(lower_mnemonic);
            return true; // Valid instruction found
        }
    }
    
    free(lower_mnemonic);
    return false; // Invalid instruction
}

//=============================================================================
// ARM64 Instruction Encoding
//=============================================================================

int arm64_encode_instruction(instruction_t *inst, uint8_t *buffer, size_t *length) {
    if (!inst || !buffer || !length) {
        return -1;
    }
    
    char *lower_mnemonic = arm64_strlower(inst->mnemonic);
    if (!lower_mnemonic) {
        return -1;
    }
    
    // Find instruction in table
    const arm64_instruction_t *arm_inst = NULL;
    for (int i = 0; arm64_instructions[i].mnemonic != NULL; i++) {
        if (strcmp(lower_mnemonic, arm64_instructions[i].mnemonic) == 0) {
            arm_inst = &arm64_instructions[i];
            break;
        }
    }
    
    if (!arm_inst) {
        free(lower_mnemonic);
        return -1;
    }
    
    // Encode based on instruction format
    uint32_t instruction_word = arm_inst->opcode_value;
    
    switch (arm_inst->format) {
        case ARM64_FORMAT_DATA_PROCESSING_IMM:
            if (encode_arm64_data_processing_instruction(inst, buffer, length) == 0) {
                free(lower_mnemonic);
                return 0;
            }
            break;
            
        case ARM64_FORMAT_DATA_PROCESSING_REG:
            if (encode_arm64_data_processing_instruction(inst, buffer, length) == 0) {
                free(lower_mnemonic);
                return 0;
            }
            break;
            
        case ARM64_FORMAT_LOAD_STORE:
            if (encode_arm64_load_store_instruction(inst, buffer, length) == 0) {
                free(lower_mnemonic);
                return 0;
            }
            break;
            
        case ARM64_FORMAT_BRANCH:
            if (encode_arm64_branch_instruction(inst, buffer, length) == 0) {
                free(lower_mnemonic);
                return 0;
            }
            break;
            
        case ARM64_FORMAT_SYSTEM:
            // Simple system instructions (like NOP)
            buffer[0] = (instruction_word >> 0) & 0xFF;
            buffer[1] = (instruction_word >> 8) & 0xFF;
            buffer[2] = (instruction_word >> 16) & 0xFF;
            buffer[3] = (instruction_word >> 24) & 0xFF;
            *length = 4;
            free(lower_mnemonic);
            return 0;
            
        default:
            break;
    }
    
    free(lower_mnemonic);
    return -1;
}

//=============================================================================
// ARM64 Specific Encoding Functions
//=============================================================================

int encode_arm64_data_processing_instruction(instruction_t *inst, uint8_t *buffer, size_t *length) {
    if (!inst || !buffer || !length) return -1;
    
    char *lower_mnemonic = arm64_strlower(inst->mnemonic);
    if (!lower_mnemonic) return -1;
    
    uint32_t instruction = 0;
    
    // Handle basic data processing instructions
    if (strcmp(lower_mnemonic, "add") == 0 && inst->operand_count == 3) {
        // ADD Xd, Xn, #imm or ADD Xd, Xn, Xm
        if (inst->operands[2].type == OPERAND_IMMEDIATE) {
            // ADD Xd, Xn, #imm
            instruction = 0x91000000; // ADD (immediate) base opcode
            
            // Extract register numbers (simplified)
            uint8_t rd = 0, rn = 1; // Placeholder register encoding
            uint32_t imm = (uint32_t)inst->operands[2].value.immediate;
            
            instruction |= (imm & 0xFFF) << 10;  // 12-bit immediate
            instruction |= (rn & 0x1F) << 5;     // Rn field
            instruction |= (rd & 0x1F);          // Rd field
        } else {
            // ADD Xd, Xn, Xm
            instruction = 0x8b000000; // ADD (shifted register) base opcode
            
            uint8_t rd = 0, rn = 1, rm = 2; // Placeholder register encoding
            
            instruction |= (rm & 0x1F) << 16;    // Rm field
            instruction |= (rn & 0x1F) << 5;     // Rn field
            instruction |= (rd & 0x1F);          // Rd field
        }
    } else if (strcmp(lower_mnemonic, "mov") == 0 && inst->operand_count == 2) {
        if (inst->operands[1].type == OPERAND_IMMEDIATE) {
            // MOV Xd, #imm
            instruction = 0xd2800000; // MOVZ base opcode
            
            uint8_t rd = 0; // Placeholder register encoding
            uint32_t imm = (uint32_t)inst->operands[1].value.immediate;
            
            instruction |= (imm & 0xFFFF) << 5;  // 16-bit immediate
            instruction |= (rd & 0x1F);          // Rd field
        } else {
            // MOV Xd, Xm (alias for ORR Xd, XZR, Xm)
            instruction = 0xaa0003e0; // ORR with XZR base opcode
            
            uint8_t rd = 0, rm = 1; // Placeholder register encoding
            
            instruction |= (rm & 0x1F) << 16;    // Rm field
            instruction |= (rd & 0x1F);          // Rd field
        }
    }
    
    // Write instruction in little-endian format
    buffer[0] = (instruction >> 0) & 0xFF;
    buffer[1] = (instruction >> 8) & 0xFF;
    buffer[2] = (instruction >> 16) & 0xFF;
    buffer[3] = (instruction >> 24) & 0xFF;
    *length = 4;
    
    free(lower_mnemonic);
    return 0;
}

int encode_arm64_load_store_instruction(instruction_t *inst, uint8_t *buffer, size_t *length) {
    (void)inst; // Suppress unused parameter warning
    
    // Placeholder implementation
    uint32_t instruction = 0xf9400000; // LDR base opcode
    
    buffer[0] = (instruction >> 0) & 0xFF;
    buffer[1] = (instruction >> 8) & 0xFF;
    buffer[2] = (instruction >> 16) & 0xFF;
    buffer[3] = (instruction >> 24) & 0xFF;
    *length = 4;
    
    return 0;
}

int encode_arm64_branch_instruction(instruction_t *inst, uint8_t *buffer, size_t *length) {
    if (!inst || !buffer || !length) return -1;
    
    char *lower_mnemonic = arm64_strlower(inst->mnemonic);
    if (!lower_mnemonic) return -1;
    
    uint32_t instruction = 0;
    
    if (strcmp(lower_mnemonic, "ret") == 0) {
        // RET instruction
        instruction = 0xd65f03c0;
    } else if (strcmp(lower_mnemonic, "b") == 0) {
        // Unconditional branch
        instruction = 0x14000000;
        // TODO: Add branch target encoding
    } else if (strcmp(lower_mnemonic, "bl") == 0) {
        // Branch with link
        instruction = 0x94000000;
        // TODO: Add branch target encoding
    }
    
    buffer[0] = (instruction >> 0) & 0xFF;
    buffer[1] = (instruction >> 8) & 0xFF;
    buffer[2] = (instruction >> 16) & 0xFF;
    buffer[3] = (instruction >> 24) & 0xFF;
    *length = 4;
    
    free(lower_mnemonic);
    return 0;
}

int encode_arm64_simd_fp_instruction(instruction_t *inst, uint8_t *buffer, size_t *length) {
    (void)inst; // Suppress unused parameter warning
    
    // Placeholder for SIMD/FP instructions
    uint32_t instruction = 0x1e204000; // FADD base opcode
    
    buffer[0] = (instruction >> 0) & 0xFF;
    buffer[1] = (instruction >> 8) & 0xFF;
    buffer[2] = (instruction >> 16) & 0xFF;
    buffer[3] = (instruction >> 24) & 0xFF;
    *length = 4;
    
    return 0;
}

//=============================================================================
// ARM64 Addressing and Utility Functions
//=============================================================================

int arm64_parse_addressing(const char *addr_str, addressing_mode_t *mode) {
    // Stub implementation for ARM64 addressing mode parsing
    if (!addr_str || !mode) {
        return -1;
    }
    
    // TODO: Implement ARM64-specific addressing mode parsing
    return 0;
}

bool arm64_validate_addressing(addressing_mode_t *mode, instruction_t *inst) {
    // Stub implementation for ARM64 addressing validation
    (void)mode;
    (void)inst;
    return true;
}

int arm64_handle_directive(const char *directive, const char *args) {
    // Stub implementation for ARM64-specific directives
    (void)directive;
    (void)args;
    return 0;
}

size_t arm64_get_instruction_size(instruction_t *inst) {
    // ARM64 instructions are always 32 bits (4 bytes)
    (void)inst;
    return 4;
}

size_t arm64_get_alignment(section_type_t section) {
    // ARM64 alignment requirements
    switch (section) {
        case SECTION_TEXT:
            return 4;  // Instructions must be 4-byte aligned
        case SECTION_DATA:
        case SECTION_RODATA:
            return 8;  // Data should be 8-byte aligned for performance
        case SECTION_BSS:
            return 8;
        default:
            return 1;
    }
}

bool arm64_validate_operand_combination(const char *mnemonic, 
                                       operand_t *operands, 
                                       size_t operand_count) {
    // Validate operand combinations for specific instructions
    (void)operands; // Suppress unused parameter warning
    if (!mnemonic) {
        return false;
    }
    
    // ARM64 instructions typically have 2-3 operands
    return operand_count <= 3;
}

//=============================================================================
// ARM64 Architecture Operations Structure
//=============================================================================

static arch_ops_t arm64_ops = {
    .name = "arm64",
    .init = arm64_init,
    .cleanup = arm64_cleanup,
    .parse_instruction = arm64_parse_instruction,
    .encode_instruction = arm64_encode_instruction,
    .parse_register = arm64_parse_register,
    .is_valid_register = is_arm64_register_impl,
    .get_register_name = get_arm64_register_name_impl,
    .parse_addressing = arm64_parse_addressing,
    .validate_addressing = arm64_validate_addressing,
    .handle_directive = arm64_handle_directive,
    .get_instruction_size = arm64_get_instruction_size,
    .get_alignment = arm64_get_alignment,
    .validate_instruction = arm64_validate_instruction,
    .validate_operand_combination = arm64_validate_operand_combination
};

arch_ops_t *arm64_get_arch_ops(void) {
    return &arm64_ops;
}

// Plugin entry point for ARM64
arch_ops_t *get_arch_ops_arm64(void) {
    return arm64_get_arch_ops();
}
