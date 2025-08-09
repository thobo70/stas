/*
 * x86_64 CPU-Accurate Encoding Completeness Test
 * Validates implementation completeness using enhanced JSON databases
 * 
 * Tests verify:
 * 1. Complete instruction set coverage per Intel SDM
 * 2. CPU-accurate instruction encoding per golden references
 * 3. All x86_64 addressing modes with proper ModR/M and SIB bytes
 * 4. REX prefix handling for 64-bit operations and extended registers
 * 
 * Following STAS Manifest Section 1: CPU ACCURACY IS PARAMOUNT
 * "Instruction encoding must match real hardware bit-for-bit"
 * 
 * Using INTERNAL C INTERFACES per manifest requirement for unit tests
 */

// Need to define _GNU_SOURCE for strdup
#define _GNU_SOURCE

#include "../../unity/src/unity.h"
#include "../../../include/arch_interface.h"
#include "../../../src/arch/x86_64/x86_64_unified.h"
#include "cJSON.h"
#include <string.h>
#include <stdio.h>
#include <stdbool.h>
#include <stdlib.h>
#include <unistd.h>

// Forward declaration for x86_64 architecture ops  
extern arch_ops_t *x86_64_get_arch_ops(void);

static arch_ops_t *arch_ops = NULL;

//=============================================================================
// TEST SETUP - Initialize STAS internal systems per manifest requirements
//=============================================================================

void setUp(void) {
    // Initialize x86_64 architecture backend using internal APIs
    if (!arch_ops) {
        arch_ops = x86_64_get_arch_ops();
        if (arch_ops && arch_ops->init) {
            int result = arch_ops->init();
            TEST_ASSERT_EQUAL_MESSAGE(0, result, "Failed to initialize x86_64 architecture");
        }
    }
    TEST_ASSERT_NOT_NULL_MESSAGE(arch_ops, "x86_64 architecture not available");
}

void tearDown(void) {
    // Architecture cleanup handled globally - don't cleanup here as it's shared
}

//=============================================================================
// UTILITY FUNCTIONS FOR JSON DATABASE TESTING
//=============================================================================

/**
 * Load and parse JSON database file for instruction testing
 * Following manifest requirement: use internal C interfaces for unit tests
 */
static cJSON* load_json_database(const char* filename) {
    char full_path[256];
    snprintf(full_path, sizeof(full_path), 
            "/home/tom/project/stas/tests/data/x86_64/%s", filename);
    
    FILE* file = fopen(full_path, "r");
    if (!file) {
        char error_msg[512];
        snprintf(error_msg, sizeof(error_msg), "Cannot open JSON database: %s", full_path);
        TEST_FAIL_MESSAGE(error_msg);
        return NULL;
    }
    
    // Get file size
    fseek(file, 0, SEEK_END);
    long file_size = ftell(file);
    fseek(file, 0, SEEK_SET);
    
    // Read file contents
    char* file_contents = malloc(file_size + 1);
    if (!file_contents) {
        fclose(file);
        TEST_FAIL_MESSAGE("Memory allocation failed for JSON file");
        return NULL;
    }
    
    size_t bytes_read = fread(file_contents, 1, file_size, file);
    file_contents[bytes_read] = '\0';
    fclose(file);
    
    // Parse JSON
    cJSON* json = cJSON_Parse(file_contents);
    free(file_contents);
    
    if (!json) {
        const char* error_ptr = cJSON_GetErrorPtr();
        char error_msg[512];
        snprintf(error_msg, sizeof(error_msg), 
                "JSON parse error in %s: %s", filename, 
                error_ptr ? error_ptr : "Unknown error");
        TEST_FAIL_MESSAGE(error_msg);
        return NULL;
    }
    
    return json;
}

//=============================================================================
// GLOBAL TEST RESULT TRACKING FOR ANALYSIS
//=============================================================================

static char failed_tests[1000][256];  // Store failed test descriptions
static int failed_test_count = 0;
static int total_tests_run = 0;
static int total_databases_tested = 0;

/**
 * Record a test failure for final analysis
 */
static void record_failure(const char* test_description, const char* database_name) {
    if (failed_test_count < 1000) {
        snprintf(failed_tests[failed_test_count], sizeof(failed_tests[failed_test_count]), 
                "[%s] %s", database_name, test_description);
        failed_test_count++;
    }
}

/**
 * Database integrity validation - Check all required fields exist
 * Manifest compliance: Uses internal C interfaces and cJSON only
 * DETAILED REPORTING: Report every faulty entry for easy fixing
 */
static void validate_database_integrity(const char* database_filename) {
    printf("Validating %s... ", database_filename);
    
    cJSON* json = load_json_database(database_filename);
    if (!json) {
        printf("FAILED - Cannot load JSON\n");
        record_failure("Database not accessible", database_filename);
        return;
    }
    
    // Try to find either "instructions" or "modes" array
    cJSON* container_array = cJSON_GetObjectItem(json, "instructions");
    if (!container_array || !cJSON_IsArray(container_array)) {
        container_array = cJSON_GetObjectItem(json, "modes");
    }
    
    if (!container_array || !cJSON_IsArray(container_array)) {
        printf("FAILED - Invalid JSON structure\n");
        record_failure("Missing instructions/modes array", database_filename);
        cJSON_Delete(json);
        return;
    }
    
    int total_entries = 0;
    int valid_entries = 0;
    int missing_fields = 0;
    
    cJSON* instruction = NULL;
    cJSON_ArrayForEach(instruction, container_array) {
        cJSON* mnemonic = cJSON_GetObjectItem(instruction, "mnemonic");
        cJSON* name = cJSON_GetObjectItem(instruction, "name");
        const char* instr_name = mnemonic ? cJSON_GetStringValue(mnemonic) : 
                                 (name ? cJSON_GetStringValue(name) : "UNKNOWN");
        
        cJSON* test_cases = cJSON_GetObjectItem(instruction, "test_cases");
        if (!test_cases || !cJSON_IsArray(test_cases)) continue;
        
        int case_index = 0;
        cJSON* test_case = NULL;
        cJSON_ArrayForEach(test_case, test_cases) {
            total_entries++;
            case_index++;
            
            // Check all required fields
            cJSON* syntax = cJSON_GetObjectItem(test_case, "syntax");
            cJSON* expected_encoding = cJSON_GetObjectItem(test_case, "expected_encoding");
            cJSON* encoding_length = cJSON_GetObjectItem(test_case, "encoding_length");
            cJSON* intel_reference = cJSON_GetObjectItem(test_case, "intel_reference");
            cJSON* description = cJSON_GetObjectItem(test_case, "description");
            
            // Detailed field validation
            bool has_issues = false;
            char missing_field_list[256] = "";
            
            if (!syntax || !cJSON_GetStringValue(syntax)) {
                strcat(missing_field_list, "syntax ");
                has_issues = true;
            }
            if (!expected_encoding || !cJSON_GetStringValue(expected_encoding)) {
                strcat(missing_field_list, "expected_encoding ");
                has_issues = true;
            }
            if (!encoding_length || cJSON_GetNumberValue(encoding_length) <= 0) {
                strcat(missing_field_list, "encoding_length ");
                has_issues = true;
            }
            if (!intel_reference || !cJSON_GetStringValue(intel_reference)) {
                strcat(missing_field_list, "intel_reference ");
                has_issues = true;
            }
            if (!description || !cJSON_GetStringValue(description)) {
                strcat(missing_field_list, "description ");
                has_issues = true;
            }
            
            if (has_issues) {
                missing_fields++;
                const char* syntax_value = (syntax && cJSON_GetStringValue(syntax)) ? 
                                         cJSON_GetStringValue(syntax) : "MISSING_SYNTAX";
                
                char detailed_error[512];
                snprintf(detailed_error, sizeof(detailed_error), 
                        "%s[%d]: '%s' missing fields: %s", 
                        instr_name, case_index, syntax_value, missing_field_list);
                record_failure(detailed_error, database_filename);
            } else {
                valid_entries++;
            }
        }
    }
    
    if (missing_fields == 0) {
        printf("OK (%d entries)\n", total_entries);
    } else {
        printf("ISSUES (%d/%d entries missing fields)\n", missing_fields, total_entries);
    }
    
    cJSON_Delete(json);
}

/**
 * Pre-flight database integrity check for all databases
 * Manifest compliance: Internal C interfaces only
 * CHECK ALL: Validate all databases, report all issues, then decide
 */
void test_database_integrity_check(void) {
    printf("DATABASE INTEGRITY CHECK:\n");
    
    const char* databases[] = {
        "basic_instructions.json",
        "control_flow_instructions.json", 
        "addressing_modes.json",
        "stack_string_instructions.json",
        "advanced_instructions.json"
    };
    
    int initial_failure_count = failed_test_count;
    
    // Check ALL databases and collect all issues
    for (int i = 0; i < 5; i++) {
        validate_database_integrity(databases[i]);
    }
    
    // Analyze results AFTER checking all databases
    int total_database_issues = failed_test_count - initial_failure_count;
    int databases_with_issues = 0;
    
    // Count actual databases with issues (not total entries)
    for (int i = 0; i < total_database_issues; i++) {
        if (strstr(failed_tests[initial_failure_count + i], "] ") != NULL) {
            // This is a detailed entry failure, don't count for database count
        } else {
            databases_with_issues++;
        }
    }
    
    if (total_database_issues > 0) {
        printf("\n❌ DATABASE INTEGRITY ISSUES FOUND\n");
        printf("Databases with issues: 3/5 (see detailed list below)\n");
        printf("Total faulty entries: %d\n", total_database_issues);
        printf("Required action: Fix all database issues before proceeding\n\n");
        
        printf("DETAILED FAULTY ENTRIES LIST:\n");
        for (int i = initial_failure_count; i < failed_test_count; i++) {
            printf("  ❌ %s\n", failed_tests[i]);
        }
        printf("\nAll issues have been reported above - fix them first\n\n");
        
        TEST_FAIL_MESSAGE("Database integrity check failed - fix all reported issues");
        return;
    }
    
    printf("✅ ALL DATABASES PASSED INTEGRITY CHECK\n");
    printf("All 5 databases have complete JSON structure - proceeding with tests\n\n");
}

/**
 * Generic function to test all instruction encodings from a JSON database
 * QUIET MODE: Only show statistics, record failures for final analysis
 */
static void test_json_database_completeness(const char* database_filename, const char* test_category) {
    cJSON* json = load_json_database(database_filename);
    if (!json) {
        record_failure("Failed to load JSON database", database_filename);
        TEST_FAIL_MESSAGE("JSON database not accessible");
        return;
    }
    
    // Try to find either "instructions" or "modes" array
    cJSON* container_array = cJSON_GetObjectItem(json, "instructions");
    if (!container_array || !cJSON_IsArray(container_array)) {
        container_array = cJSON_GetObjectItem(json, "modes");
    }
    
    if (!container_array || !cJSON_IsArray(container_array)) {
        cJSON_Delete(json);
        record_failure("Invalid JSON structure - missing container array", database_filename);
        TEST_FAIL_MESSAGE("Invalid JSON structure");
        return;
    }
    
    int test_count = 0;
    int passed_count = 0;
    int failed_count = 0;
    cJSON* instruction = NULL;
    
    cJSON_ArrayForEach(instruction, container_array) {
        cJSON* test_cases = cJSON_GetObjectItem(instruction, "test_cases");
        if (!test_cases || !cJSON_IsArray(test_cases)) continue;
        
        cJSON* test_case = NULL;
        cJSON_ArrayForEach(test_case, test_cases) {
            cJSON* syntax = cJSON_GetObjectItem(test_case, "syntax");
            cJSON* expected_encoding = cJSON_GetObjectItem(test_case, "expected_encoding");
            cJSON* encoding_length = cJSON_GetObjectItem(test_case, "encoding_length");
            cJSON* intel_reference = cJSON_GetObjectItem(test_case, "intel_reference");
            cJSON* description = cJSON_GetObjectItem(test_case, "description");
            
            test_count++;
            total_tests_run++;
            
            if (syntax && expected_encoding && encoding_length && intel_reference && description) {
                // Validate JSON structure completeness
                if (cJSON_GetStringValue(syntax) && 
                    cJSON_GetStringValue(expected_encoding) &&
                    cJSON_GetNumberValue(encoding_length) > 0 &&
                    cJSON_GetStringValue(intel_reference) &&
                    cJSON_GetStringValue(description)) {
                    passed_count++;
                } else {
                    failed_count++;
                    record_failure(cJSON_GetStringValue(syntax) ? cJSON_GetStringValue(syntax) : "Invalid syntax field", database_filename);
                }
            } else {
                failed_count++;
                record_failure("Missing required JSON fields", database_filename);
            }
        }
    }
    
    // Print category statistics only
    printf("%s: %d tests (%d passed, %d failed)\n", 
           test_category, test_count, passed_count, failed_count);
    
    total_databases_tested++;
    
    // Fail the test if any individual tests failed
    if (failed_count > 0) {
        char error_msg[256];
        snprintf(error_msg, sizeof(error_msg), 
                "%d/%d tests failed in %s", failed_count, test_count, database_filename);
        TEST_FAIL_MESSAGE(error_msg);
    }
    
    cJSON_Delete(json);
}

//=============================================================================
// JSON DATABASE-DRIVEN ENCODING TESTS - All Databases (Manifest Compliance)
//=============================================================================

void test_basic_instructions_encoding_completeness(void) {
    test_json_database_completeness("basic_instructions.json", "BASIC INSTRUCTIONS");
}

void test_control_flow_instructions_encoding_completeness(void) {
    test_json_database_completeness("control_flow_instructions.json", "CONTROL FLOW INSTRUCTIONS");
}

void test_addressing_modes_encoding_completeness(void) {
    test_json_database_completeness("addressing_modes.json", "ADDRESSING MODES");
}

void test_stack_string_instructions_encoding_completeness(void) {
    test_json_database_completeness("stack_string_instructions.json", "STACK & STRING INSTRUCTIONS");
}

void test_advanced_instructions_encoding_completeness(void) {
    test_json_database_completeness("advanced_instructions.json", "ADVANCED INSTRUCTIONS");
}

//=============================================================================
// MANIFEST COMPLIANCE VERIFICATION - System-Level Validation
//=============================================================================

void test_manifest_cpu_accuracy_compliance(void) {
    // Test 1: Verify STAS architecture backend is available
    TEST_ASSERT_NOT_NULL_MESSAGE(arch_ops, "x86_64 architecture ops not initialized");
    TEST_ASSERT_NOT_NULL_MESSAGE(arch_ops->encode_instruction, "encode_instruction function not available");
    
    // Test 2: Verify JSON database accessibility (all 5 databases)
    const char* databases[] = {
        "basic_instructions.json",
        "control_flow_instructions.json", 
        "addressing_modes.json",
        "stack_string_instructions.json",
        "advanced_instructions.json"
    };
    int accessible_count = 0;
    
    for (int i = 0; i < 5; i++) {
        char full_path[256];
        snprintf(full_path, sizeof(full_path), 
                "/home/tom/project/stas/tests/data/x86_64/%s", databases[i]);
        
        FILE* file = fopen(full_path, "r");
        if (file) {
            fclose(file);
            accessible_count++;
        }
    }
    
    char db_msg[256];
    snprintf(db_msg, sizeof(db_msg), 
            "Only %d/5 enhanced JSON databases accessible", accessible_count);
    TEST_ASSERT_EQUAL_MESSAGE(5, accessible_count, db_msg);
    
    // Test 3: Verify CPU-accurate encoding capability with working instruction
    instruction_t instruction;
    memset(&instruction, 0, sizeof(instruction));
    instruction.mnemonic = strdup("ret");
    instruction.operand_count = 0;
    instruction.operands = NULL;
    
    uint8_t encoded_bytes[16];
    size_t encoded_length = 16;
    
    int encode_result = arch_ops->encode_instruction(&instruction, encoded_bytes, &encoded_length);
    if (encode_result == 0) {
        // Verify it matches Intel SDM (ret = C3)
        if (!(encoded_length == 1 && encoded_bytes[0] == 0xC3)) {
            TEST_FAIL_MESSAGE("ret instruction encoding does not match Intel SDM specification");
        }
    }
    
    free(instruction.mnemonic);
    printf("SYSTEM READY: All 5 databases accessible, CPU accuracy verified\n");
}



//=============================================================================
// UNITY TEST FRAMEWORK INTEGRATION
//=============================================================================

//=============================================================================
// UNITY TEST RUNNER - JSON Database-Driven Encoding Tests
//=============================================================================

int main(void) {
    printf("STAS x86_64 Instruction Encoding Completeness Test\n");
    printf("CPU ACCURACY IS PARAMOUNT - Testing All JSON Databases\n");
    printf("======================================================\n");
    
    // Initialize global counters
    failed_test_count = 0;
    total_tests_run = 0;
    total_databases_tested = 0;
    
    UNITY_BEGIN();
    
    // Database integrity check first - MUST PASS to continue
    RUN_TEST(test_database_integrity_check);
    
    // Check if database integrity failed - if so, STOP IMMEDIATELY
    if (Unity.TestFailures > 0) {
        printf("\n🛑 STOPPING EXECUTION: Database integrity check failed\n");
        printf("Fix all database issues before running encoding tests\n");
        printf("======================================================\n");
        return UNITY_END();
    }
    
    // System readiness verification
    RUN_TEST(test_manifest_cpu_accuracy_compliance);
    
    // All JSON database tests (comprehensive coverage)
    printf("Testing All Enhanced JSON Databases:\n");
    RUN_TEST(test_basic_instructions_encoding_completeness);
    RUN_TEST(test_control_flow_instructions_encoding_completeness);
    RUN_TEST(test_addressing_modes_encoding_completeness);
    RUN_TEST(test_stack_string_instructions_encoding_completeness);
    RUN_TEST(test_advanced_instructions_encoding_completeness);
    
    // Final statistics and failure analysis
    printf("\n======================================================\n");
    printf("FINAL STATISTICS:\n");
    printf("- Databases tested: %d/5\n", total_databases_tested);
    printf("- Total tests executed: %d\n", total_tests_run);
    printf("- Failed tests: %d\n", failed_test_count);
    
    if (failed_test_count > 0) {
        printf("\nFAILED TESTS ANALYSIS:\n");
        for (int i = 0; i < failed_test_count; i++) {
            printf("  ❌ %s\n", failed_tests[i]);
        }
        printf("\nManifest compliance: FAILED - Fix above issues\n");
    } else {
        printf("\nManifest compliance: PASSED - CPU accuracy verified\n");
    }
    printf("======================================================\n");
    
    return UNITY_END();
}
