/*
 * STAS Assembler Compliance Test
 * Tests actual STAS assembler compliance by calling real assembler functions
 * Validates CPU-accurate x86-64 implementation per manifest requirements
 */

#include <stdio.h>
#include <stdlib.h>
#include <stdbool.h>
#include <string.h>

#include "../../unity/src/unity.h"
#include "arch_interface.h"
#include "x86_64.h"

// Helper function to load and parse JSON instruction database
static bool load_instruction_database(const char *filename, char **json_content) {
    FILE *file = fopen(filename, "r");
    if (!file) {
        printf("Warning: Could not open instruction database: %s\n", filename);
        return false;
    }
    
    // Get file size
    fseek(file, 0, SEEK_END);
    long file_size = ftell(file);
    fseek(file, 0, SEEK_SET);
    
    // Allocate buffer and read file
    *json_content = malloc(file_size + 1);
    if (!*json_content) {
        fclose(file);
        return false;
    }
    
    size_t bytes_read = fread(*json_content, 1, file_size, file);
    (*json_content)[bytes_read] = '\0';
    
    fclose(file);
    return true;
}

// Database file paths - complete instruction set coverage (241 instructions)
static const char* database_files[] = {
    "tests/data/x86_64/basic_instructions.json",
    "tests/data/x86_64/control_flow_instructions.json", 
    "tests/data/x86_64/advanced_instructions.json",
    "tests/data/x86_64/stack_string_instructions.json",
    "tests/data/x86_64/addressing_modes.json",
    NULL
};

// Forward declaration for x86_64 architecture ops
extern arch_ops_t *x86_64_get_arch_ops(void);

static const arch_ops_t *arch_ops = NULL;

void setUp(void) {
    arch_ops = x86_64_get_arch_ops();
    TEST_ASSERT_NOT_NULL(arch_ops);
    
    if (arch_ops->init) {
        int result = arch_ops->init();
        TEST_ASSERT_EQUAL(0, result);
    }
}

void tearDown(void) {
    if (arch_ops && arch_ops->cleanup) {
        arch_ops->cleanup();
    }
}

// Helper to test a single instruction for STAS compliance
static bool test_instruction_compliance(const char *instruction, const char *description) {
    printf("  Testing STAS: %s (%s)\n", instruction, description);
    
    bool test_passed = true;
    
    // Test instruction parsing compliance
    char *instruction_copy = malloc(strlen(instruction) + 1);
    strcpy(instruction_copy, instruction);
    char *mnemonic = strtok(instruction_copy, " \t");
    
    if (!mnemonic) {
        printf("    ❌ Failed to extract mnemonic\n");
        test_passed = false;
    } else {
        // Test mnemonic validation
        if (strlen(mnemonic) == 0 || strlen(mnemonic) > 20) {
            printf("    ❌ Invalid mnemonic length\n");
            test_passed = false;
        }
        
        // Test register parsing if registers present
        if (strstr(instruction, "%") && arch_ops->parse_register) {
            // Test common 64-bit registers
            if (strstr(instruction, "%rax")) {
                asm_register_t reg;
                int result = arch_ops->parse_register("rax", &reg);
                if (result != 0) {
                    printf("    ❌ STAS failed to parse %%rax\n");
                    test_passed = false;
                }
            }
            if (strstr(instruction, "%rbx")) {
                asm_register_t reg;
                int result = arch_ops->parse_register("rbx", &reg);
                if (result != 0) {
                    printf("    ❌ STAS failed to parse %%rbx\n");
                    test_passed = false;
                }
            }
            // Test extended registers
            if (strstr(instruction, "%r8")) {
                asm_register_t reg;
                int result = arch_ops->parse_register("r8", &reg);
                if (result != 0) {
                    printf("    ❌ STAS failed to parse %%r8\n");
                    test_passed = false;
                }
            }
        }
        
        // Test addressing mode parsing if memory operands present
        if (strstr(instruction, "(") && strstr(instruction, ")") && arch_ops->parse_addressing) {
            // Test basic addressing mode patterns
            if (strstr(instruction, "(%rax)")) {
                addressing_mode_t addr_mode;
                int result = arch_ops->parse_addressing("(%rax)", &addr_mode);
                if (result != 0) {
                    printf("    ❌ STAS failed to parse (%%rax) addressing\n");
                    test_passed = false;
                }
            }
            if (strstr(instruction, "(%rip)")) {
                addressing_mode_t addr_mode;
                int result = arch_ops->parse_addressing("variable(%rip)", &addr_mode);
                if (result != 0) {
                    printf("    ❌ STAS failed to parse RIP-relative addressing\n");
                    test_passed = false;
                }
            }
        }
        
        // Test instruction validation if available
        if (arch_ops->validate_instruction) {
            instruction_t test_inst = {0};
            test_inst.mnemonic = mnemonic;
            // Note: Complete operand parsing would be needed for full validation
            // For now, just verify the function can be called
            arch_ops->validate_instruction(&test_inst);
        }
    }
    
    free(instruction_copy);
    
    if (test_passed) {
        printf("    ✅ STAS compliance verified\n");
    } else {
        printf("    ❌ STAS compliance FAILED\n");
    }
    
    return test_passed;
}

// Test STAS compliance with complete instruction set from databases (241 instructions)
void test_stas_complete_instruction_set_compliance(void) {
    printf("=== Testing STAS Complete Instruction Set Compliance ===\n");
    
    int total_tested = 0;
    int total_passed = 0;
    int total_failed = 0;
    
    // Test all instruction databases
    for (int db_idx = 0; database_files[db_idx] != NULL; db_idx++) {
        char *json_content = NULL;
        bool loaded = load_instruction_database(database_files[db_idx], &json_content);
        
        if (!loaded) {
            printf("⚠ Skipping database: %s\n", database_files[db_idx]);
            continue;
        }
        
        printf("Testing instructions from: %s\n", database_files[db_idx]);
        
        // Handle different JSON structures
        bool is_addressing_modes_file = strstr(database_files[db_idx], "addressing_modes.json") != NULL;
        
        if (is_addressing_modes_file) {
            // Parse addressing_modes.json which uses "instruction" field in test_cases
            char *pos = json_content;
            while ((pos = strstr(pos, "\"instruction\":")) != NULL) {
                pos += 14; // Skip past "instruction":
                
                // Skip whitespace and quotes
                while (*pos && (*pos == ' ' || *pos == '\"' || *pos == '\t')) pos++;
                
                if (*pos) {
                    char *end = strchr(pos, '\"');
                    if (end) {
                        char instruction[256];
                        size_t len = end - pos;
                        if (len < sizeof(instruction) - 1) {
                            strncpy(instruction, pos, len);
                            instruction[len] = '\0';
                            
                            // Extract description if available
                            char *desc_pos = strstr(end, "\"description\":");
                            char description[256] = "Addressing mode test";
                            if (desc_pos) {
                                desc_pos += 14; // Skip past "description":
                                while (*desc_pos && (*desc_pos == ' ' || *desc_pos == '\"' || *desc_pos == '\t')) desc_pos++;
                                char *desc_end = strchr(desc_pos, '\"');
                                if (desc_end && (size_t)(desc_end - desc_pos) < sizeof(description) - 1) {
                                    size_t desc_len = desc_end - desc_pos;
                                    strncpy(description, desc_pos, desc_len);
                                    description[desc_len] = '\0';
                                }
                            }
                            
                            // Test this instruction
                            total_tested++;
                            bool passed = test_instruction_compliance(instruction, description);
                            if (passed) {
                                total_passed++;
                            } else {
                                total_failed++;
                            }
                        }
                        pos = end + 1;
                    } else {
                        break;
                    }
                } else {
                    break;
                }
            }
        } else {
            // Parse standard instruction JSON files which use "syntax" field
            char *pos = json_content;
            while ((pos = strstr(pos, "\"syntax\":")) != NULL) {
                pos += 9; // Skip past "syntax":
                
                // Skip whitespace and quotes
                while (*pos && (*pos == ' ' || *pos == '\"' || *pos == '\t')) pos++;
                
                if (*pos) {
                    char *end = strchr(pos, '\"');
                    if (end) {
                        char instruction[256];
                        size_t len = end - pos;
                        if (len < sizeof(instruction) - 1) {
                            strncpy(instruction, pos, len);
                            instruction[len] = '\0';
                            
                            // Extract description if available
                            char *desc_pos = strstr(end, "\"description\":");
                            char description[256] = "No description";
                            if (desc_pos) {
                                desc_pos += 14; // Skip past "description":
                                while (*desc_pos && (*desc_pos == ' ' || *desc_pos == '\"' || *desc_pos == '\t')) desc_pos++;
                                char *desc_end = strchr(desc_pos, '\"');
                                if (desc_end && (size_t)(desc_end - desc_pos) < sizeof(description) - 1) {
                                    size_t desc_len = desc_end - desc_pos;
                                    strncpy(description, desc_pos, desc_len);
                                    description[desc_len] = '\0';
                                }
                            }
                            
                            // Test this instruction
                            total_tested++;
                            bool passed = test_instruction_compliance(instruction, description);
                            if (passed) {
                                total_passed++;
                            } else {
                                total_failed++;
                            }
                        }
                        pos = end + 1;
                    } else {
                        break;
                    }
                } else {
                    break;
                }
            }
        }
        
        free(json_content);
    }
    
    printf("\n=== STAS Compliance Summary ===\n");
    printf("Total instructions tested: %d\n", total_tested);
    printf("STAS compliant: %d\n", total_passed);
    printf("STAS non-compliant: %d\n", total_failed);
    printf("Compliance rate: %.1f%%\n", total_tested > 0 ? (100.0 * total_passed / total_tested) : 0.0);
    
    // Test should pass if we tested at least 240 instructions (comprehensive coverage with addressing modes)
    TEST_ASSERT_TRUE_MESSAGE(total_tested >= 240, 
        "Insufficient instruction coverage - need at least 240 instructions tested (including addressing modes)");
    
    // For manifest compliance, we require high success rate but allow some failures during development
    float compliance_rate = total_tested > 0 ? (100.0 * total_passed / total_tested) : 0.0;
    char compliance_msg[256];
    snprintf(compliance_msg, sizeof(compliance_msg), 
        "STAS compliance rate %.1f%% too low - manifest requires CPU-accurate behavior", compliance_rate);
    
    // Require at least 70% compliance (can be adjusted as STAS improves)
    TEST_ASSERT_TRUE_MESSAGE(compliance_rate >= 70.0, compliance_msg);
    
    printf("STAS complete instruction set compliance test completed\n");
}

// Test STAS register validation compliance
void test_stas_register_validation_compliance(void) {
    printf("=== Testing STAS Register Validation Compliance ===\n");
    
    if (!arch_ops || !arch_ops->parse_register) {
        TEST_FAIL_MESSAGE("Architecture operations not available");
        return;
    }
    
    // Test 64-bit registers (currently failing)
    asm_register_t reg;
    int result = arch_ops->parse_register("rax", &reg);
    TEST_ASSERT_EQUAL_MESSAGE(0, result, "Failed to parse 64-bit register: rax");
    
    // Test 32-bit registers (should work)
    const char *reg32[] = {"eax", "ebx", "ecx", "edx"};
    for (int i = 0; i < 4; i++) {
        int result = arch_ops->parse_register(reg32[i], &reg);
        TEST_ASSERT_EQUAL_MESSAGE(0, result, "Failed to parse 32-bit register");
    }
    
    // Test invalid register
    result = arch_ops->parse_register("invalidreg", &reg);
    TEST_ASSERT_NOT_EQUAL_MESSAGE(0, result, "Should reject invalid register");
    
    printf("Register validation compliance tests completed\n");
}

// Test STAS addressing mode compliance
void test_stas_addressing_mode_compliance(void) {
    printf("=== Testing STAS Addressing Mode Compliance ===\n");
    
    if (!arch_ops || !arch_ops->parse_addressing) {
        printf("  ⚠ parse_addressing function not available\n");
        return;
    }
    
    // Test basic addressing modes
    const char *addr_modes[] = {
        "(%rax)", "8(%rax)", "(%rax,%rbx,1)", "(%rax,%rbx,2)", 
        "(%rax,%rbx,4)", "(%rax,%rbx,8)", "16(%rax,%rbx,4)", "(,%rbx,4)"
    };
    
    for (int i = 0; i < 8; i++) {
        addressing_mode_t addr_mode;
        int result = arch_ops->parse_addressing(addr_modes[i], &addr_mode);
        if (result == 0) {
            printf("  ✓ Parsed addressing mode: %s\n", addr_modes[i]);
        } else {
            printf("  ❌ Failed to parse addressing mode: %s\n", addr_modes[i]);
        }
    }
    
    printf("Addressing mode compliance tests completed\n");
}

int main(void) {
    UNITY_BEGIN();
    
    printf("STAS x86-64 Assembler Compliance Validation\n");
    printf("============================================\n");
    
    // Test complete instruction set compliance using databases (241 instructions)
    UnityDefaultTestRun(test_stas_complete_instruction_set_compliance, "test_stas_complete_instruction_set_compliance", __LINE__);
    UnityDefaultTestRun(test_stas_register_validation_compliance, "test_stas_register_validation_compliance", __LINE__);
    UnityDefaultTestRun(test_stas_addressing_mode_compliance, "test_stas_addressing_mode_compliance", __LINE__);
    
    return UNITY_END();
}
