#include "testing_core.h"
#include "../../include/arch_interface.h"
#include "../../src/arch/x86_16/x86_16.h"
#include "../../include/x86_32.h"
#include "../../include/x86_64.h"
#include <stdio.h>
#include <string.h>
#include <stdlib.h>

// Forward declarations for architecture operations
extern arch_ops_t *get_arch_ops_x86_16(void);
extern arch_ops_t *get_arch_ops_x86_32(void);
extern arch_ops_t *get_arch_ops_x86_64(void);
extern arch_ops_t *get_arch_ops_arm64(void);
extern arch_ops_t *get_riscv_arch_ops(void);

// ========================================
// HELPER FUNCTIONS
// ========================================

static arch_ops_t* get_arch_ops_by_name(const char* arch_name) {
    if (strcmp(arch_name, "x86_16") == 0) return get_arch_ops_x86_16();
    if (strcmp(arch_name, "x86_32") == 0) return get_arch_ops_x86_32();
    if (strcmp(arch_name, "x86_64") == 0) return get_arch_ops_x86_64();
    if (strcmp(arch_name, "arm64") == 0) return get_arch_ops_arm64();
    if (strcmp(arch_name, "riscv") == 0) return get_riscv_arch_ops();
    return NULL;
}

static bool test_instruction_recognition(arch_ops_t* arch_ops, const instruction_def_t* instr) {
    if (!arch_ops || !arch_ops->parse_instruction || !instr) return false;
    
    operand_t dummy_operands[4] = {0};
    instruction_t test_instr = {0};
    
    int result = arch_ops->parse_instruction(instr->mnemonic, dummy_operands, 
                                           instr->operand_count, &test_instr);
    
    // Note: Don't free the instruction fields as they may not be heap-allocated
    
    return result == 0;
}

static void setup_dummy_operands(operand_t* operands, size_t operand_count, const char* arch_name, const char* mnemonic) {
    // Initialize all operands to zero
    memset(operands, 0, sizeof(operand_t) * operand_count);
    
    // Check if this is a shift operation that needs special operand handling
    bool is_shift_op = (strcmp(mnemonic, "shl") == 0 || strcmp(mnemonic, "shr") == 0 ||
                       strcmp(mnemonic, "sal") == 0 || strcmp(mnemonic, "sar") == 0 ||
                       strcmp(mnemonic, "rol") == 0 || strcmp(mnemonic, "ror") == 0 ||
                       strcmp(mnemonic, "rcl") == 0 || strcmp(mnemonic, "rcr") == 0);
    
    bool is_3op_shift = (strcmp(mnemonic, "shld") == 0 || strcmp(mnemonic, "shrd") == 0);
    
    // Check if this is a control flow instruction that needs immediate operands
    bool is_control_flow = (strcmp(mnemonic, "jmp") == 0 || strcmp(mnemonic, "call") == 0 ||
                           strcmp(mnemonic, "je") == 0 || strcmp(mnemonic, "jne") == 0 ||
                           strcmp(mnemonic, "jz") == 0 || strcmp(mnemonic, "jnz") == 0 ||
                           strcmp(mnemonic, "jl") == 0 || strcmp(mnemonic, "jle") == 0 ||
                           strcmp(mnemonic, "jg") == 0 || strcmp(mnemonic, "jge") == 0 ||
                           strcmp(mnemonic, "ja") == 0 || strcmp(mnemonic, "jae") == 0 ||
                           strcmp(mnemonic, "jb") == 0 || strcmp(mnemonic, "jbe") == 0 ||
                           strcmp(mnemonic, "jc") == 0 || strcmp(mnemonic, "jnc") == 0 ||
                           strcmp(mnemonic, "jo") == 0 || strcmp(mnemonic, "jno") == 0 ||
                           strcmp(mnemonic, "js") == 0 || strcmp(mnemonic, "jns") == 0 ||
                           strcmp(mnemonic, "loop") == 0 || strcmp(mnemonic, "loope") == 0 ||
                           strcmp(mnemonic, "loopne") == 0 || strcmp(mnemonic, "jecxz") == 0 ||
                           // Jump aliases
                           strcmp(mnemonic, "jna") == 0 || strcmp(mnemonic, "jnae") == 0 ||
                           strcmp(mnemonic, "jnb") == 0 || strcmp(mnemonic, "jnbe") == 0 ||
                           strcmp(mnemonic, "jng") == 0 || strcmp(mnemonic, "jnge") == 0 ||
                           strcmp(mnemonic, "jnl") == 0 || strcmp(mnemonic, "jnle") == 0 ||
                           strcmp(mnemonic, "jnp") == 0 || strcmp(mnemonic, "jp") == 0 ||
                           strcmp(mnemonic, "jpe") == 0 || strcmp(mnemonic, "jpo") == 0);
    
    // Check if this is a set instruction that needs 8-bit register
    bool is_set_instr = (strncmp(mnemonic, "set", 3) == 0);
    
    // Check if this is a bit manipulation instruction needing immediate + register
    bool is_bit_manip = (strcmp(mnemonic, "bt") == 0 || strcmp(mnemonic, "btc") == 0 ||
                        strcmp(mnemonic, "btr") == 0 || strcmp(mnemonic, "bts") == 0);
    
    // Check if this is LEA instruction that needs memory operand
    bool is_lea = (strcmp(mnemonic, "lea") == 0 || strcmp(mnemonic, "leal") == 0 ||
                   strcmp(mnemonic, "leaw") == 0 || strcmp(mnemonic, "leaq") == 0);
    
    // Check if this is MOVZX/MOVSX instruction that needs different sized operands
    bool is_extend = (strcmp(mnemonic, "movzx") == 0 || strcmp(mnemonic, "movsx") == 0);
    
    // Check if this is a segment load instruction (LDS, LES, LFS, LGS, LSS)
    bool is_segment_load = (strcmp(mnemonic, "lds") == 0 || strcmp(mnemonic, "les") == 0 ||
                           strcmp(mnemonic, "lfs") == 0 || strcmp(mnemonic, "lgs") == 0 ||
                           strcmp(mnemonic, "lss") == 0);
    
    // Check if this is ENTER instruction that needs two immediate operands
    bool is_enter = (strcmp(mnemonic, "enter") == 0);
    
    // Check if this is a descriptor table instruction (LGDT, SGDT, LIDT, SIDT)
    bool is_descriptor_table = (strcmp(mnemonic, "lgdt") == 0 || strcmp(mnemonic, "sgdt") == 0 ||
                               strcmp(mnemonic, "lidt") == 0 || strcmp(mnemonic, "sidt") == 0);
    
    // Set up appropriate dummy operands based on architecture
    for (size_t i = 0; i < operand_count && i < 4; i++) {
        if (strcmp(arch_name, "x86_32") == 0) {
            // Special handling for control flow instructions
            if (is_control_flow && operand_count == 1) {
                // Control flow instructions need immediate relative offsets
                operands[i].type = OPERAND_IMMEDIATE;
                operands[i].value.immediate = 10; // Short relative jump
                operands[i].size = 1;
            }
            // Special handling for set instructions
            else if (is_set_instr && operand_count == 1) {
                // Set instructions need 8-bit register
                operands[i].type = OPERAND_REGISTER;
                operands[i].value.reg.name = "al";
                operands[i].value.reg.size = 1;
                operands[i].value.reg.encoding = 0;
                operands[i].size = 1;
            }
            // Special handling for bit manipulation instructions
            else if (is_bit_manip && operand_count == 2) {
                if (i == 0) {
                    // First operand: immediate bit index (AT&T: source comes first)
                    operands[i].type = OPERAND_IMMEDIATE;
                    operands[i].value.immediate = 5;
                    operands[i].size = 1;
                } else {
                    // Second operand: register
                    operands[i].type = OPERAND_REGISTER;
                    operands[i].value.reg.name = "eax";
                    operands[i].value.reg.size = 4;
                    operands[i].value.reg.encoding = 0;
                    operands[i].size = 4;
                }
            }
            // Special handling for LEA instruction
            else if (is_lea && operand_count == 2) {
                if (i == 0) {
                    // First operand: memory address (AT&T: source memory comes first)
                    operands[i].type = OPERAND_MEMORY;
                    operands[i].value.memory.base.name = "ebx";
                    operands[i].value.memory.base.size = 4;
                    operands[i].value.memory.base.encoding = 3;
                    operands[i].value.memory.offset = 8;  // 8(%ebx)
                    operands[i].size = 4;
                } else {
                    // Second operand: destination register
                    operands[i].type = OPERAND_REGISTER;
                    operands[i].value.reg.name = "eax";
                    operands[i].value.reg.size = 4;
                    operands[i].value.reg.encoding = 0;
                    operands[i].size = 4;
                }
            }
            // Special handling for MOVZX/MOVSX extension instructions
            else if (is_extend && operand_count == 2) {
                if (i == 0) {
                    // First operand: smaller source register (AT&T: source comes first)
                    operands[i].type = OPERAND_REGISTER;
                    operands[i].value.reg.name = "bl";
                    operands[i].value.reg.size = 1;
                    operands[i].value.reg.encoding = 3;
                    operands[i].size = 1;
                } else {
                    // Second operand: larger destination register
                    operands[i].type = OPERAND_REGISTER;
                    operands[i].value.reg.name = "eax";
                    operands[i].value.reg.size = 4;
                    operands[i].value.reg.encoding = 0;
                    operands[i].size = 4;
                }
            }
            // Special handling for segment load instructions (LDS, LES, LFS, LGS, LSS)
            else if (is_segment_load && operand_count == 2) {
                if (i == 0) {
                    // First operand: memory address for segment:offset (AT&T: source memory comes first)
                    operands[i].type = OPERAND_MEMORY;
                    operands[i].value.memory.base.name = "ebx";
                    operands[i].value.memory.base.size = 4;
                    operands[i].value.memory.base.encoding = 3;
                    operands[i].value.memory.offset = 0;  // (%ebx)
                    operands[i].size = 6; // 6 bytes: 4-byte offset + 2-byte segment
                } else {
                    // Second operand: destination register
                    operands[i].type = OPERAND_REGISTER;
                    operands[i].value.reg.name = "eax";
                    operands[i].value.reg.size = 4;
                    operands[i].value.reg.encoding = 0;
                    operands[i].size = 4;
                }
            }
            // Special handling for ENTER instruction
            else if (is_enter && operand_count == 2) {
                if (i == 0) {
                    // First operand: frame size (16-bit immediate)
                    operands[i].type = OPERAND_IMMEDIATE;
                    operands[i].value.immediate = 16; // 16 bytes frame size
                    operands[i].size = 2;
                } else {
                    // Second operand: nesting level (8-bit immediate)
                    operands[i].type = OPERAND_IMMEDIATE;
                    operands[i].value.immediate = 0; // nesting level 0
                    operands[i].size = 1;
                }
            }
            // Special handling for descriptor table instructions (LGDT, SGDT, LIDT, SIDT)
            else if (is_descriptor_table && operand_count == 1) {
                // Single operand: memory address for descriptor table
                operands[i].type = OPERAND_MEMORY;
                operands[i].value.memory.base.name = "ebx";
                operands[i].value.memory.base.size = 4;
                operands[i].value.memory.base.encoding = 3;
                operands[i].value.memory.offset = 0;  // (%ebx)
                operands[i].size = 6; // 6 bytes: base + limit
            }
            // Special handling for shift operations with AT&T syntax
            else if (is_shift_op && operand_count == 2) {
                if (i == 0) {
                    // First operand: immediate count (AT&T: source comes first)
                    operands[i].type = OPERAND_IMMEDIATE;
                    operands[i].value.immediate = 1;
                    operands[i].size = 1;
                } else {
                    // Second operand: destination register
                    operands[i].type = OPERAND_REGISTER;
                    operands[i].value.reg.name = "eax";
                    operands[i].value.reg.size = 4;
                    operands[i].value.reg.encoding = 0;
                    operands[i].size = 4;
                }
            } else if (is_3op_shift && operand_count == 3) {
                if (i == 0) {
                    // First operand: immediate count (AT&T: count comes first)
                    operands[i].type = OPERAND_IMMEDIATE;
                    operands[i].value.immediate = 1;
                    operands[i].size = 1;
                } else if (i == 1) {
                    // Second operand: source register
                    operands[i].type = OPERAND_REGISTER;
                    operands[i].value.reg.name = "ebx";
                    operands[i].value.reg.size = 4;
                    operands[i].value.reg.encoding = 3;
                    operands[i].size = 4;
                } else {
                    // Third operand: destination register
                    operands[i].type = OPERAND_REGISTER;
                    operands[i].value.reg.name = "eax";
                    operands[i].value.reg.size = 4;
                    operands[i].value.reg.encoding = 0;
                    operands[i].size = 4;
                }
            } else {
                // Default register operands
                operands[i].type = OPERAND_REGISTER;
                operands[i].value.reg.name = (i == 0) ? "eax" : "ebx";
                operands[i].value.reg.size = 4;
                operands[i].value.reg.encoding = (i == 0) ? 0 : 3;
                operands[i].size = 4;
            }
        } else if (strcmp(arch_name, "x86_16") == 0) {
            // Special handling for control flow instructions
            if (is_control_flow && operand_count == 1) {
                // Control flow instructions need immediate relative offsets
                operands[i].type = OPERAND_IMMEDIATE;
                operands[i].value.immediate = 10; // Short relative jump
                operands[i].size = 1;
            }
            // Special handling for set instructions (not available in x86_16, but keeping structure)
            else if (is_set_instr && operand_count == 1) {
                // Set instructions need 8-bit register
                operands[i].type = OPERAND_REGISTER;
                operands[i].value.reg.name = "al";
                operands[i].value.reg.size = 1;
                operands[i].value.reg.encoding = 0;
                operands[i].size = 1;
            }
            // Special handling for shift operations with AT&T syntax
            else if (is_shift_op && operand_count == 2) {
                if (i == 0) {
                    // First operand: immediate count (AT&T: source comes first)
                    operands[i].type = OPERAND_IMMEDIATE;
                    operands[i].value.immediate = 1;
                    operands[i].size = 1;
                } else {
                    // Second operand: destination register
                    operands[i].type = OPERAND_REGISTER;
                    operands[i].value.reg.name = "ax";
                    operands[i].value.reg.size = 2;
                    operands[i].value.reg.encoding = 0;
                    operands[i].size = 2;
                }
            } else if (is_3op_shift && operand_count == 3) {
                if (i == 0) {
                    // First operand: immediate count (AT&T: count comes first)
                    operands[i].type = OPERAND_IMMEDIATE;
                    operands[i].value.immediate = 1;
                    operands[i].size = 1;
                } else if (i == 1) {
                    // Second operand: source register
                    operands[i].type = OPERAND_REGISTER;
                    operands[i].value.reg.name = "bx";
                    operands[i].value.reg.size = 2;
                    operands[i].value.reg.encoding = 3;
                    operands[i].size = 2;
                } else {
                    // Third operand: destination register
                    operands[i].type = OPERAND_REGISTER;
                    operands[i].value.reg.name = "ax";
                    operands[i].value.reg.size = 2;
                    operands[i].value.reg.encoding = 0;
                    operands[i].size = 2;
                }
            } else {
                // Default register operands
                operands[i].type = OPERAND_REGISTER;
                operands[i].value.reg.name = (i == 0) ? "ax" : "bx";
                operands[i].value.reg.size = 2;
                operands[i].value.reg.encoding = (i == 0) ? 0 : 3;
                operands[i].size = 2;
            }
        } else if (strcmp(arch_name, "x86_64") == 0) {
            operands[i].type = OPERAND_REGISTER;
            operands[i].value.reg.name = (i == 0) ? "rax" : "rbx";
            operands[i].value.reg.size = 8;
            operands[i].value.reg.encoding = (i == 0) ? 0 : 3;
            operands[i].size = 8;
        } else if (strcmp(arch_name, "arm64") == 0) {
            operands[i].type = OPERAND_REGISTER;
            operands[i].value.reg.name = (i == 0) ? "x0" : "x1";
            operands[i].value.reg.size = 8;
            operands[i].value.reg.encoding = (i == 0) ? 0 : 1;
            operands[i].size = 8;
        } else if (strcmp(arch_name, "riscv") == 0) {
            operands[i].type = OPERAND_REGISTER;
            operands[i].value.reg.name = (i == 0) ? "x1" : "x2";
            operands[i].value.reg.size = 8;
            operands[i].value.reg.encoding = (i == 0) ? 1 : 2;
            operands[i].size = 8;
        } else {
            // Default to register operands
            operands[i].type = OPERAND_REGISTER;
            operands[i].value.reg.name = "r0";
            operands[i].value.reg.size = 4;
            operands[i].value.reg.encoding = 0;
            operands[i].size = 4;
        }
    }
}

static bool test_instruction_functional(arch_ops_t* arch_ops, const instruction_def_t* instr) {
    if (!test_instruction_recognition(arch_ops, instr)) return false;
    
    // Test encoding capability for functional support
    if (!arch_ops->encode_instruction) return false;
    
    operand_t dummy_operands[4] = {0};
    instruction_t test_instr = {0};
    
    // Set up proper dummy operands - try to identify architecture by testing against known architectures
    const char* arch_name = "unknown";
    
    // Test with each architecture's get function to identify which one this is
    arch_ops_t* x86_16_ops = get_arch_ops_x86_16();
    arch_ops_t* x86_32_ops = get_arch_ops_x86_32();
    arch_ops_t* x86_64_ops = get_arch_ops_x86_64();
    arch_ops_t* arm64_ops = get_arch_ops_arm64();
    arch_ops_t* riscv_ops = get_riscv_arch_ops();
    
    if (arch_ops == x86_32_ops) {
        arch_name = "x86_32";
    } else if (arch_ops == x86_16_ops) {
        arch_name = "x86_16";
    } else if (arch_ops == x86_64_ops) {
        arch_name = "x86_64";
    } else if (arch_ops == arm64_ops) {
        arch_name = "arm64";
    } else if (arch_ops == riscv_ops) {
        arch_name = "riscv";
    }
    
    setup_dummy_operands(dummy_operands, instr->operand_count, arch_name, instr->mnemonic);
    
    int parse_result = arch_ops->parse_instruction(instr->mnemonic, dummy_operands, 
                                                 instr->operand_count, &test_instr);
    
    if (parse_result != 0) return false;
    
    uint8_t buffer[16] = {0};
    size_t length = 0;
    
    int encode_result = arch_ops->encode_instruction(&test_instr, buffer, &length);
    
    // Note: Don't free the instruction fields as they may not be heap-allocated
    
    return encode_result == 0 && length > 0;
}

// ========================================
// CORE TESTING FUNCTIONS
// ========================================

instruction_test_result_t test_instruction_category(const char *arch_name, 
                                                   const instruction_category_t *category) {
    return test_instruction_category_verbose(arch_name, category, false);
}

instruction_test_result_t test_instruction_category_verbose(const char *arch_name, 
                                                           const instruction_category_t *category,
                                                           bool verbose_mode) {
    instruction_test_result_t result = {0};
    arch_ops_t* arch_ops = get_arch_ops_by_name(arch_name);
    
    if (!arch_ops || !category) return result;
    
    result.total = category->instruction_count;
    
    // Arrays to track failed instructions for verbose reporting
    const instruction_def_t **unrecognized = NULL;
    const instruction_def_t **nonfunctional = NULL;
    size_t unrecognized_count = 0;
    size_t nonfunctional_count = 0;
    
    if (verbose_mode) {
        unrecognized = malloc(category->instruction_count * sizeof(instruction_def_t*));
        nonfunctional = malloc(category->instruction_count * sizeof(instruction_def_t*));
    }
    
    for (size_t i = 0; i < category->instruction_count; i++) {
        const instruction_def_t* instr = &category->instructions[i];
        
        if (test_instruction_recognition(arch_ops, instr)) {
            result.recognized++;
            
            if (test_instruction_functional(arch_ops, instr)) {
                result.functional++;
            } else if (verbose_mode) {
                nonfunctional[nonfunctional_count++] = instr;
            }
        } else if (verbose_mode) {
            unrecognized[unrecognized_count++] = instr;
        }
    }
    
    result.recognition_percent = result.total > 0 ? 
        (double)result.recognized / result.total * 100.0 : 0.0;
    result.functional_percent = result.total > 0 ? 
        (double)result.functional / result.total * 100.0 : 0.0;
    
    // Print verbose failure reports
    if (verbose_mode) {
        if (unrecognized_count > 0) {
            printf("      ❌ UNRECOGNIZED (%zu instructions):\n", unrecognized_count);
            for (size_t i = 0; i < unrecognized_count; i++) {
                printf("         • %s", unrecognized[i]->mnemonic);
                if (unrecognized[i]->is_extension) {
                    printf(" (extension)");
                }
                printf("\n");
            }
        }
        
        if (nonfunctional_count > 0) {
            printf("      ⚠️  NON-FUNCTIONAL (%zu instructions):\n", nonfunctional_count);
            for (size_t i = 0; i < nonfunctional_count; i++) {
                printf("         • %s", nonfunctional[i]->mnemonic);
                if (nonfunctional[i]->is_extension) {
                    printf(" (extension)");
                }
                printf(" - parsing OK, encoding failed\n");
            }
        }
        
        free(unrecognized);
        free(nonfunctional);
    }
    
    return result;
}
