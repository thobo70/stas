/*
 * STAS Core Pipeline Testing API
 * Architecture-independent pipeline testing following manifest requirements
 * CPU ACCURACY IS PARAMOUNT - Complete string → lexer → parser → generator → binary
 */

#ifndef STAS_PIPELINE_H
#define STAS_PIPELINE_H

#include "arch_interface.h"
#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>

//=============================================================================
// Pipeline Test Result Structure
//=============================================================================

typedef struct {
    bool success;                    // Overall pipeline success
    char *error_message;            // Error description if failed
    
    // Generated binary encoding
    uint8_t *machine_code;          // Generated binary encoding
    size_t machine_code_length;     // Length of generated code
    
    // Stage success indicators
    bool lexer_success;
    bool parser_success;
    bool generator_success;
} stas_pipeline_result_t;

//=============================================================================
// Core Pipeline Testing API
//=============================================================================

/**
 * Execute complete STAS pipeline test
 * Input: Assembly instruction string
 * Output: Binary machine code
 * 
 * Following manifest: CPU ACCURACY IS PARAMOUNT
 * Uses existing STAS lexer → parser → architecture encoder pipeline
 * 
 * @param instruction_str   AT&T syntax assembly instruction
 * @param architecture     Target architecture name (x86_64, arm64, etc.)
 * @param result           Pipeline test results (caller must free)
 * @return 0 on success, -1 on failure
 */
int stas_pipeline_test(const char *instruction_str, 
                      const char *architecture,
                      stas_pipeline_result_t *result);

/**
 * Execute pipeline test with validation against expected encoding
 * 
 * @param instruction_str   AT&T syntax assembly instruction  
 * @param architecture     Target architecture name
 * @param expected_hex     Expected encoding as hex string ("48 89 C3")
 * @param result           Pipeline test results (caller must free)
 * @return 0 on success, -1 on failure
 */
int stas_pipeline_test_validate(const char *instruction_str,
                               const char *architecture,
                               const char *expected_hex,
                               stas_pipeline_result_t *result);

/**
 * Free pipeline test result resources
 * Must be called for every stas_pipeline_result_t
 * 
 * @param result Pipeline test result to free
 */
void stas_pipeline_free_result(stas_pipeline_result_t *result);

/**
 * Convert hex string to byte array
 * Handles formats: "48 89 C3", "4889C3"
 * 
 * @param hex_str    Hex string input
 * @param bytes      Output byte array (caller allocates)
 * @param length     Input: max bytes, Output: actual bytes
 * @return 0 on success, -1 on failure
 */
int stas_hex_to_bytes(const char *hex_str, uint8_t *bytes, size_t *length);

/**
 * Convert byte array to hex string
 * Output format: "48 89 C3"
 * 
 * @param bytes      Input byte array
 * @param length     Number of bytes
 * @param hex_str    Output hex string (caller allocates)
 * @param max_len    Maximum hex string length
 * @return 0 on success, -1 on failure
 */
int stas_bytes_to_hex(const uint8_t *bytes, size_t length, 
                     char *hex_str, size_t max_len);

#endif // STAS_PIPELINE_H
