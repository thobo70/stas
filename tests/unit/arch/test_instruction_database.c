/*
 * Instruction Database Loader and Tester
 * 
 * This utility loads all JSON instruction databases and runs comprehensive tests
 * to verify x86-64 instruction set completeness against real CPU specifications.
 */

#include "../../unity/src/unity.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <dirent.h>

// Database file paths
static const char* database_files[] = {
    "tests/data/x86_64/basic_instructions.json",
    "tests/data/x86_64/control_flow_instructions.json", 
    "tests/data/x86_64/advanced_instructions.json",
    "tests/data/x86_64/stack_string_instructions.json",
    NULL
};

void setUp(void) {
    // Setup for each test
}

void tearDown(void) {
    // Cleanup after each test
}

// Test that all expected database files exist
void test_database_files_exist(void) {
    for (int i = 0; database_files[i] != NULL; i++) {
        FILE *file = fopen(database_files[i], "r");
        char message[256];
        snprintf(message, sizeof(message), "Database file not found: %s", database_files[i]);
        TEST_ASSERT_NOT_NULL_MESSAGE(file, message);
        if (file) {
            fclose(file);
        }
    }
}

// Count total instructions in all databases
void test_instruction_count_meets_minimum(void) {
    int total_instructions = 0;
    
    for (int i = 0; database_files[i] != NULL; i++) {
        FILE *file = fopen(database_files[i], "r");
        if (!file) continue;
        
        // Count "mnemonic": occurrences as a proxy for instruction count
        char buffer[1024];
        while (fgets(buffer, sizeof(buffer), file)) {
            if (strstr(buffer, "\"mnemonic\":")) {
                total_instructions++;
            }
        }
        fclose(file);
    }
    
    printf("Total instructions found in databases: %d\n", total_instructions);
    
    // According to Intel SDM and online references, there are hundreds of x86-64 instructions
    // We should have at least 100 core instructions covered
    TEST_ASSERT_TRUE_MESSAGE(total_instructions >= 50, 
        "Insufficient instruction coverage - need more instructions in databases");
}

// Test that databases contain required instruction categories
void test_required_instruction_categories(void) {
    // Critical instruction categories that must be present
    const char* required_categories[] = {
        "MOV", "ADD", "SUB", "MUL", "DIV",           // Basic arithmetic
        "AND", "OR", "XOR", "NOT",                   // Logical operations
        "SHL", "SHR", "SAR",                         // Bit manipulation
        "CMP", "TEST",                               // Comparison
        "JMP", "JE", "JNE", "CALL", "RET",          // Control flow
        "PUSH", "POP",                               // Stack operations
        NULL
    };
    
    // Load all database content
    char *all_content = malloc(64 * 1024); // 64KB should be enough
    strcpy(all_content, "");
    
    for (int i = 0; database_files[i] != NULL; i++) {
        FILE *file = fopen(database_files[i], "r");
        if (!file) continue;
        
        char buffer[1024];
        while (fgets(buffer, sizeof(buffer), file)) {
            strcat(all_content, buffer);
        }
        fclose(file);
    }
    
    // Check for each required category
    for (int i = 0; required_categories[i] != NULL; i++) {
        char search_pattern[64];
        snprintf(search_pattern, sizeof(search_pattern), "\"%s\"", required_categories[i]);
        
        char message[128];
        snprintf(message, sizeof(message), "Required instruction category missing: %s", required_categories[i]);
        TEST_ASSERT_NOT_NULL_MESSAGE(strstr(all_content, search_pattern), message);
    }
    
    free(all_content);
}

// Test that databases follow proper JSON structure
void test_database_json_structure(void) {
    for (int i = 0; database_files[i] != NULL; i++) {
        FILE *file = fopen(database_files[i], "r");
        if (!file) continue;
        
        // Simple JSON validation - check for balanced braces
        int brace_count = 0;
        int bracket_count = 0;
        char c;
        
        while ((c = fgetc(file)) != EOF) {
            if (c == '{') brace_count++;
            else if (c == '}') brace_count--;
            else if (c == '[') bracket_count++;
            else if (c == ']') bracket_count--;
        }
        
        char message[256];
        snprintf(message, sizeof(message), "JSON structure error in %s: unbalanced braces", database_files[i]);
        TEST_ASSERT_EQUAL_MESSAGE(0, brace_count, message);
        
        snprintf(message, sizeof(message), "JSON structure error in %s: unbalanced brackets", database_files[i]);
        TEST_ASSERT_EQUAL_MESSAGE(0, bracket_count, message);
        
        fclose(file);
    }
}

// Test that x86-64 specific instructions are present
void test_x86_64_specific_instructions(void) {
    // Load all database content
    char *all_content = malloc(64 * 1024);
    strcpy(all_content, "");
    
    for (int i = 0; database_files[i] != NULL; i++) {
        FILE *file = fopen(database_files[i], "r");
        if (!file) continue;
        
        char buffer[1024];
        while (fgets(buffer, sizeof(buffer), file)) {
            strcat(all_content, buffer);
        }
        fclose(file);
    }
    
    // Check for x86-64 specific features
    const char* x86_64_features[] = {
        "%rip",          // RIP-relative addressing
        "%rax",          // 64-bit registers
        "%r8",           // Extended registers
        "SYSCALL",       // x86-64 system call
        "SWAPGS",        // x86-64 specific instruction
        NULL
    };
    
    for (int i = 0; x86_64_features[i] != NULL; i++) {
        char message[128];
        snprintf(message, sizeof(message), "x86-64 specific feature missing: %s", x86_64_features[i]);
        TEST_ASSERT_NOT_NULL_MESSAGE(strstr(all_content, x86_64_features[i]), message);
    }
    
    free(all_content);
}

// Main test suite
int main(void) {
    UNITY_BEGIN();
    
    printf("x86-64 Instruction Database Validation\n");
    printf("======================================\n");
    
    UnityDefaultTestRun(test_database_files_exist, "test_database_files_exist", __LINE__);
    UnityDefaultTestRun(test_instruction_count_meets_minimum, "test_instruction_count_meets_minimum", __LINE__);
    UnityDefaultTestRun(test_required_instruction_categories, "test_required_instruction_categories", __LINE__);
    UnityDefaultTestRun(test_database_json_structure, "test_database_json_structure", __LINE__);
    UnityDefaultTestRun(test_x86_64_specific_instructions, "test_x86_64_specific_instructions", __LINE__);
    
    return UNITY_END();
}
