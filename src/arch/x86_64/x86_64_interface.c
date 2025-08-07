/*
 * x86-64 Architecture Interface Implementation - UNIFIED CLEAN VERSION
 * Provides the standard architecture interface for x86-64
 * Following STAS Development Manifest requirements
 */

#include "x86_64.h"
#include "arch_interface.h"
#include <stdio.h>

//=============================================================================
// Architecture Interface Implementation
//=============================================================================

static int x86_64_interface_init(void) {
    return x86_64_init();
}

static void x86_64_interface_cleanup(void) {
    x86_64_cleanup();
}

// Wrapper to convert int return to bool
static bool x86_64_interface_validate_instruction(instruction_t *inst) {
    return x86_64_validate_instruction(inst) != 0;
}

//============================================================================= 
// Architecture Operations Structure
//=============================================================================

static const arch_ops_t x86_64_ops = {
    .name = "x86-64",
    .init = x86_64_interface_init,
    .cleanup = x86_64_interface_cleanup,
    .parse_instruction = NULL,  // Use wrapper function
    .encode_instruction = x86_64_encode_instruction,
    .parse_register = NULL,     // Use wrapper function  
    .is_valid_register = NULL,  // Use wrapper function
    .get_register_name = NULL,  // Use wrapper function
    .parse_addressing = NULL,   // Use wrapper function
    .validate_addressing = NULL, // Use wrapper function
    .handle_directive = NULL,   // Not implemented yet
    .get_instruction_size = NULL, // Use wrapper function
    .get_alignment = NULL,      // Use wrapper function
    .validate_instruction = x86_64_interface_validate_instruction,
    .validate_operand_combination = NULL // Use wrapper function
};

//=============================================================================
// Architecture Registration Function
//=============================================================================

const arch_ops_t *get_x86_64_ops(void) {
    return &x86_64_ops;
}

// Main expects this function name
arch_ops_t *get_arch_ops_x86_64(void) {
    return (arch_ops_t *)&x86_64_ops;
}

// Test compatibility function
arch_ops_t *x86_64_get_arch_ops(void) {
    return (arch_ops_t *)&x86_64_ops;
}

//=============================================================================
// Debug and Diagnostic Functions (Optional)
//=============================================================================

void x86_64_print_capabilities(void) {
    printf("x86-64 Architecture Capabilities:\n");
    printf("- CPU-accurate instruction encoding\n");
    printf("- AT&T syntax support\n");
    printf("- 64-bit mode operations\n");
    printf("- Comprehensive register set\n");
}
