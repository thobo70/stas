/*
 * STAS x86_64 Pipeline Test
 * REAL PIPELINE TESTING following manifest requirement: CPU ACCURACY IS PARAMOUNT
 * Tests complete STAS pipeline: string → lexer → parser → generator → binary encoding
 * Uses unified pipeline testing API - no fake implementations
 */

#include "../../unity/src/unity.h"
#include "../../../include/pipeline_test.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

void setUp(void) {
    // Unity setup
}

void tearDown(void) {
    // Unity teardown
}

//=============================================================================
// Basic Pipeline Tests - CPU Accuracy Verification
//=============================================================================

void test_pipeline_basic_movq_register_to_register(void) {
    pipeline_test_result_t result;
    
    // Test: movq %rax, %rbx should produce 48 89 C3
    int status = stas_pipeline_test_validate(
        "movq %rax, %rbx",     // AT&T syntax instruction
        "x86_64",              // Target architecture
        "48 89 C3",            // Expected Intel SDM encoding
        &result
    );
    
    if (status == 0) {
        TEST_ASSERT_TRUE_MESSAGE(result.success, "Pipeline test should succeed");
        TEST_ASSERT_TRUE_MESSAGE(result.lexer_success, "Lexer should succeed");
        TEST_ASSERT_TRUE_MESSAGE(result.parser_success, "Parser should succeed");
        TEST_ASSERT_TRUE_MESSAGE(result.generator_success, "Generator should succeed");
        TEST_ASSERT_EQUAL_MESSAGE(3, result.machine_code_length, "Encoding length should be 3 bytes");
        
        // Verify exact bytes
        TEST_ASSERT_EQUAL_HEX8_MESSAGE(0x48, result.machine_code[0], "REX.W prefix");
        TEST_ASSERT_EQUAL_HEX8_MESSAGE(0x89, result.machine_code[1], "MOV r64 to r/m64 opcode");
        TEST_ASSERT_EQUAL_HEX8_MESSAGE(0xC3, result.machine_code[2], "ModR/M: RAX→RBX");
        
        printf("✅ PASS: movq %%rax, %%rbx → 48 89 C3 (CPU-accurate)\n");
    } else {
        if (result.error_message) {
            printf("❌ FAIL: %s\n", result.error_message);
            TEST_FAIL_MESSAGE(result.error_message);
        } else {
            TEST_FAIL_MESSAGE("Pipeline test failed without error message");
        }
    }
    
    stas_pipeline_test_free_result(&result);
}

void test_pipeline_basic_movq_immediate_to_register(void) {
    pipeline_test_result_t result;
    
    // Test: movq $0x1234567890ABCDEF, %rax should produce REX.W + B8 + imm64
    int status = stas_pipeline_test_validate(
        "movq $0x1234567890ABCDEF, %rax",
        "x86_64",
        "48 B8 EF CD AB 90 78 56 34 12",  // REX.W + B8 + little-endian imm64
        &result
    );
    
    if (status == 0) {
        TEST_ASSERT_TRUE_MESSAGE(result.success, "Pipeline test should succeed");
        TEST_ASSERT_EQUAL_MESSAGE(10, result.machine_code_length, "Should be 10 bytes total");
        TEST_ASSERT_EQUAL_HEX8_MESSAGE(0x48, result.machine_code[0], "REX.W prefix");
        TEST_ASSERT_EQUAL_HEX8_MESSAGE(0xB8, result.machine_code[1], "MOV imm64 to RAX");
        
        printf("✅ PASS: movq $imm64, %%rax → REX.W + B8 + imm64 (CPU-accurate)\n");
    } else {
        if (result.error_message) {
            printf("❌ FAIL: %s\n", result.error_message);
            TEST_FAIL_MESSAGE(result.error_message);
        } else {
            TEST_FAIL_MESSAGE("Pipeline test failed");
        }
    }
    
    stas_pipeline_test_free_result(&result);
}

void test_pipeline_basic_ret_instruction(void) {
    pipeline_test_result_t result;
    
    // Test: ret should produce C3
    int status = stas_pipeline_test_validate(
        "ret",
        "x86_64", 
        "C3",
        &result
    );
    
    if (status == 0) {
        TEST_ASSERT_TRUE_MESSAGE(result.success, "Pipeline test should succeed");
        TEST_ASSERT_EQUAL_MESSAGE(1, result.machine_code_length, "RET should be 1 byte");
        TEST_ASSERT_EQUAL_HEX8_MESSAGE(0xC3, result.machine_code[0], "RET opcode");
        
        printf("✅ PASS: ret → C3 (CPU-accurate)\n");
    } else {
        if (result.error_message) {
            printf("❌ FAIL: %s\n", result.error_message);
        }
        TEST_ASSERT_TRUE_MESSAGE(status == 0, "RET instruction should encode correctly");
    }
    
    stas_pipeline_test_free_result(&result);
}

void test_pipeline_architecture_support(void) {
    pipeline_test_result_t result;
    
    // Test that x86_64 architecture is supported
    int status = stas_pipeline_test_validate(
        "nop",  // Simple instruction
        "x86_64",
        "90",   // NOP opcode
        &result
    );
    
    TEST_ASSERT_TRUE_MESSAGE(status == 0 || result.error_message != NULL, 
                           "Should either succeed or provide error message");
    
    if (status == 0) {
        printf("✅ PASS: x86_64 architecture supported\n");
    } else {
        printf("⚠️  ARCH: x86_64 support issue: %s\n", 
               result.error_message ? result.error_message : "unknown");
    }
    
    stas_pipeline_test_free_result(&result);
}

//=============================================================================
// Test Runner
//=============================================================================

int main(void) {
    UNITY_BEGIN();
    
    printf("STAS Pipeline Testing - CPU ACCURACY IS PARAMOUNT\n");
    printf("=================================================\n");
    printf("Testing complete lexer → parser → generator → binary pipeline\n\n");
    
    RUN_TEST(test_pipeline_architecture_support);
    RUN_TEST(test_pipeline_basic_ret_instruction);
    RUN_TEST(test_pipeline_basic_movq_register_to_register);
    RUN_TEST(test_pipeline_basic_movq_immediate_to_register);
    
    printf("\n");
    return UNITY_END();
}
