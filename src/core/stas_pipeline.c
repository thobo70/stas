/*
 * STAS Core Pipeline Testing Implementation
 * Architecture-independent pipeline testing using existing STAS infrastructure
 * CPU ACCURACY IS PARAMOUNT - Complete integration with lexer/parser/generator
 */

#define _GNU_SOURCE
#include "stas_pipeline.h"
#include "lexer.h"
#include "parser.h"
#include "codegen.h"
#include "utils.h"
#include "arch_interface.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>

//=============================================================================
// External function declarations and implementations
//=============================================================================

// Forward declarations for specific architecture functions
extern arch_ops_t *get_arch_ops_x86_64(void);

// Implementation of get_architecture for pipeline testing (simplified for testing)
arch_ops_t *get_architecture(const char *arch_name) {
    if (!arch_name) {
        return NULL;
    }
    
    if (strcmp(arch_name, "x86_64") == 0) {
        return get_arch_ops_x86_64();
    }
    
    // For testing, we only support x86_64 for now
    return NULL;
}

//=============================================================================
// Pipeline Test Implementation
//=============================================================================

int stas_pipeline_test(const char *instruction_str, 
                      const char *architecture,
                      stas_pipeline_result_t *result) {
    
    if (!instruction_str || !architecture || !result) {
        return -1;
    }
    
    // Initialize result structure
    memset(result, 0, sizeof(stas_pipeline_result_t));
    result->success = false;
    result->lexer_success = false;
    result->parser_success = false;
    result->generator_success = false;
    
    // Get architecture operations
    arch_ops_t *arch_ops = get_architecture(architecture);
    if (!arch_ops) {
        result->error_message = strdup("Unsupported architecture");
        return -1;
    }
    
    //=========================================================================
    // STAGE 1: LEXER - Tokenize assembly instruction
    //=========================================================================
    
    lexer_t *lexer = lexer_create(instruction_str, "pipeline_test");
    if (!lexer) {
        result->error_message = strdup("Lexer initialization failed");
        return -1;
    }
    
    result->lexer_success = true;
    
    //=========================================================================
    // STAGE 2: PARSER - Parse tokens into instruction structure
    //=========================================================================
    
    parser_t *parser = parser_create(lexer, arch_ops);
    if (!parser) {
        result->error_message = strdup("Parser initialization failed");
        lexer_destroy(lexer);
        return -1;
    }
    
    // Parse instruction using STAS parser
    ast_node_t *ast = parser_parse(parser);
    
    if (parser_has_error(parser) || !ast) {
        const char *error = parser_get_error(parser);
        result->error_message = strdup(error ? error : "Parser failed to parse instruction");
        parser_destroy(parser);
        lexer_destroy(lexer);
        return -1;
    }
    
    result->parser_success = true;
    
    //=========================================================================
    // STAGE 3: GENERATOR - Generate machine code using architecture encoder
    //=========================================================================
    
    // Find the instruction node in the AST
    ast_node_t *inst_node = ast;
    while (inst_node && inst_node->type != AST_INSTRUCTION) {
        inst_node = inst_node->next;
    }
    
    if (!inst_node || !inst_node->data) {
        result->error_message = strdup("No instruction found in parsed AST");
        parser_destroy(parser);
        lexer_destroy(lexer);
        return -1;
    }
    
    // Extract instruction from AST
    ast_instruction_t *ast_inst = (ast_instruction_t*)inst_node->data;
    
    // Create instruction_t structure for encoder
    instruction_t instruction = {0};
    instruction.mnemonic = strdup(ast_inst->mnemonic);
    instruction.operands = ast_inst->operands;
    instruction.operand_count = ast_inst->operand_count;
    
    // Allocate output buffer
    uint8_t machine_code[16];  // Most instructions <= 16 bytes
    size_t code_length = sizeof(machine_code);
    
    // Use architecture-specific encoder
    if (arch_ops->encode_instruction) {
        int encode_result = arch_ops->encode_instruction(&instruction, 
                                                        machine_code, 
                                                        &code_length);
        
        if (encode_result != 0 || code_length == 0) {
            result->error_message = strdup("Code generation failed");
            free(instruction.mnemonic);
            parser_destroy(parser);
            lexer_destroy(lexer);
            return -1;
        }
    } else {
        result->error_message = strdup("Architecture encoder not implemented");
        free(instruction.mnemonic);
        parser_destroy(parser);
        lexer_destroy(lexer);
        return -1;
    }
    
    result->generator_success = true;
    
    //=========================================================================
    // FINALIZE - Copy results and cleanup
    //=========================================================================
    
    // Copy machine code to result
    result->machine_code = malloc(code_length);
    if (result->machine_code) {
        memcpy(result->machine_code, machine_code, code_length);
        result->machine_code_length = code_length;
    } else {
        result->error_message = strdup("Memory allocation failed");
        free(instruction.mnemonic);
        parser_destroy(parser);
        lexer_destroy(lexer);
        return -1;
    }
    
    // Cleanup STAS structures
    free(instruction.mnemonic);
    parser_destroy(parser);
    lexer_destroy(lexer);
    
    result->success = true;
    
    return 0;
}

int stas_pipeline_test_validate(const char *instruction_str,
                               const char *architecture,
                               const char *expected_hex,
                               stas_pipeline_result_t *result) {
    
    // Execute pipeline test
    int test_result = stas_pipeline_test(instruction_str, architecture, result);
    if (test_result != 0) {
        return test_result;
    }
    
    // Convert expected hex to bytes for comparison
    uint8_t expected_bytes[16];
    size_t expected_length = sizeof(expected_bytes);
    
    if (stas_hex_to_bytes(expected_hex, expected_bytes, &expected_length) != 0) {
        free(result->error_message);
        result->error_message = strdup("Invalid expected hex format");
        result->success = false;
        return -1;
    }
    
    // Compare generated vs expected
    bool match = (result->machine_code_length == expected_length) &&
                 (memcmp(result->machine_code, expected_bytes, expected_length) == 0);
    
    if (!match) {
        // Create detailed error message
        char error_msg[256];
        char actual_hex[64], expected_hex_clean[64];
        
        stas_bytes_to_hex(result->machine_code, result->machine_code_length, 
                         actual_hex, sizeof(actual_hex));
        stas_bytes_to_hex(expected_bytes, expected_length, 
                         expected_hex_clean, sizeof(expected_hex_clean));
        
        snprintf(error_msg, sizeof(error_msg), 
                "Encoding mismatch - Expected: %s, Got: %s", 
                expected_hex_clean, actual_hex);
        
        free(result->error_message);
        result->error_message = strdup(error_msg);
        result->success = false;
        return -1;
    }
    
    return 0;
}

void stas_pipeline_free_result(stas_pipeline_result_t *result) {
    if (!result) return;
    
    if (result->machine_code) {
        free(result->machine_code);
        result->machine_code = NULL;
    }
    
    if (result->error_message) {
        free(result->error_message);
        result->error_message = NULL;
    }
    
    memset(result, 0, sizeof(stas_pipeline_result_t));
}

//=============================================================================
// Utility Functions
//=============================================================================

int stas_hex_to_bytes(const char *hex_str, uint8_t *bytes, size_t *length) {
    if (!hex_str || !bytes || !length) {
        return -1;
    }
    
    size_t hex_len = strlen(hex_str);
    size_t byte_count = 0;
    size_t max_bytes = *length;
    
    for (size_t i = 0; i < hex_len && byte_count < max_bytes; ) {
        // Skip whitespace
        while (i < hex_len && isspace(hex_str[i])) {
            i++;
        }
        
        if (i >= hex_len) break;
        
        // Parse two hex digits
        char hex_byte[3] = {0};
        
        if (i + 1 < hex_len && isxdigit(hex_str[i]) && isxdigit(hex_str[i + 1])) {
            hex_byte[0] = hex_str[i];
            hex_byte[1] = hex_str[i + 1];
            
            bytes[byte_count] = (uint8_t)strtol(hex_byte, NULL, 16);
            byte_count++;
            i += 2;
        } else {
            return -1; // Invalid hex format
        }
    }
    
    *length = byte_count;
    return 0;
}

int stas_bytes_to_hex(const uint8_t *bytes, size_t length, 
                     char *hex_str, size_t max_len) {
    
    if (!bytes || !hex_str || length == 0) {
        return -1;
    }
    
    size_t required_len = length * 3; // "XX " per byte
    if (max_len < required_len) {
        return -1;
    }
    
    hex_str[0] = '\0';
    
    for (size_t i = 0; i < length; i++) {
        char byte_hex[4];
        snprintf(byte_hex, sizeof(byte_hex), "%02X", bytes[i]);
        
        strcat(hex_str, byte_hex);
        if (i < length - 1) {
            strcat(hex_str, " ");
        }
    }
    
    return 0;
}
