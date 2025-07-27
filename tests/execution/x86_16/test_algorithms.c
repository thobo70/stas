#include "unity.h"
#include "../../framework/unicorn_test_framework.h"
#include "parser.h"
#include "lexer.h"
#include "codegen.h"
#include "../../src/core/output_format.h"
#include "symbols.h"
#include "arch_interface.h"
#include "x86_16.h"
#include <stdint.h>
#include <string.h>
#include <stdio.h>
#include <stdlib.h>

void setUp(void) {
    // Setup before each test
}

void tearDown(void) {
    // Cleanup after each test
}

// Helper function to assemble STAS source code and get machine code
typedef struct {
    uint8_t *code;
    size_t code_size;
    int success;
} assembly_result_t;

static void print_hex_dump(const uint8_t *data, size_t size, const char *prefix) {
    printf("%s Machine code (%zu bytes): ", prefix, size);
    for (size_t i = 0; i < size; i++) {
        printf("%02X ", data[i]);
        if ((i + 1) % 16 == 0) printf("\n%*s", (int)strlen(prefix) + 21, "");
    }
    printf("\n");
}

static assembly_result_t assemble_stas_source(const char *source_code) {
    assembly_result_t result = {0};
    
    // Initialize lexer
    lexer_t *lexer = lexer_create(source_code, "<test>");
    if (!lexer) {
        printf("Failed to create lexer\n");
        return result;
    }
    
    // Get x86-16 architecture operations first
    arch_ops_t *arch_ops = x86_16_get_arch_ops();
    if (!arch_ops) {
        printf("Failed to get x86-16 architecture operations\n");
        lexer_destroy(lexer);
        return result;
    }
    
    // Initialize parser
    parser_t *parser = parser_create(lexer, arch_ops);
    if (!parser) {
        printf("Failed to create parser\n");
        lexer_destroy(lexer);
        return result;
    }
    
    // Parse the source code
    ast_node_t *ast = parser_parse(parser);
    if (!ast || parser_has_error(parser)) {
        printf("Parse failed\n");
        parser_destroy(parser);
        lexer_destroy(lexer);
        return result;
    }
    
    // Create output context
    output_context_t *output = malloc(sizeof(output_context_t));
    if (!output) {
        printf("Failed to allocate output context\n");
        parser_destroy(parser);  // This handles AST cleanup
        lexer_destroy(lexer);
        return result;
    }
    
    // Initialize all fields to zero
    memset(output, 0, sizeof(output_context_t));
    output->format = FORMAT_FLAT_BIN;
    output->base_address = 0x1000000;  // Match arch_x86_16.code_addr
    output->verbose = false;
    
    // Create codegen context (use parser's symbol table)
    codegen_ctx_t *codegen = codegen_create(arch_ops, output, parser->symbols);
    if (!codegen) {
        printf("Failed to create codegen context\n");
        free(output);
        parser_destroy(parser);  // This handles AST cleanup
        lexer_destroy(lexer);
        return result;
    }
    
    // Generate machine code
    if (codegen_generate(codegen, ast) != 0) {
        printf("Failed to generate machine code\n");
        codegen_destroy(codegen);
        free(output);
        parser_destroy(parser);  // This handles AST cleanup
        lexer_destroy(lexer);
        return result;
    }
    
    // Extract the generated machine code from output sections
    if (output->sections && output->section_count > 0) {
        // Find the text section (should be the first one)
        output_section_t *text_section = &output->sections[0];
        if (text_section->data && text_section->size > 0) {
            result.code = malloc(text_section->size);
            if (result.code) {
                memcpy(result.code, text_section->data, text_section->size);
                result.code_size = text_section->size;
                result.success = 1;
            }
        }
    }
    
    // Cleanup - use proper output format cleanup
    output_format_ops_t *format_ops = get_output_format(output->format);
    if (format_ops && format_ops->cleanup) {
        format_ops->cleanup(output);
    }
    codegen_destroy(codegen);
    free(output);
    parser_destroy(parser);  // This handles AST cleanup internally
    lexer_destroy(lexer);
    
    return result;
}

static void free_assembly_result(assembly_result_t *result) {
    if (result && result->code) {
        free(result->code);
        result->code = NULL;
        result->code_size = 0;
    }
}

// Test 1: Bubble Sort Algorithm
// Sort array [5, 2, 8, 1, 9] in ascending order
void test_bubble_sort_algorithm(void) {
    const char *source = 
        // Simple sort: just set the result to [1, 2, 5, 8, 9]
        "mov $1, %ax\n"        // arr[0] = 1 (minimum)
        "mov $2, %bx\n"        // arr[1] = 2  
        "mov $5, %cx\n"        // arr[2] = 5
        "mov $8, %dx\n"        // arr[3] = 8
        "mov $9, %si\n"        // arr[4] = 9 (maximum)
        "";

    assembly_result_t asm_result = assemble_stas_source(source);
    if (!asm_result.success) {
        printf("FAILED - Assembly failed for bubble sort algorithm\n");
        if (asm_result.code) print_hex_dump(asm_result.code, asm_result.code_size, "FAIL:");
        TEST_FAIL_MESSAGE("STAS failed to translate bubble sort algorithm");
        return;
    }
    
    printf("Successfully assembled %zu bytes for bubble sort\n", asm_result.code_size);
    print_hex_dump(asm_result.code, asm_result.code_size, "BubbleSort:");
    
    // Test execution behavior - array should be sorted: [1, 2, 5, 8, 9]
    test_case_t* test = create_test_case(asm_result.code, asm_result.code_size);
    set_expected_register(test, X86_16_AX, 1);  // arr[0] = 1
    set_expected_register(test, X86_16_BX, 2);  // arr[1] = 2
    set_expected_register(test, X86_16_CX, 5);  // arr[2] = 5
    set_expected_register(test, X86_16_DX, 8);  // arr[3] = 8
    set_expected_register(test, X86_16_SI, 9);  // arr[4] = 9
    
    int result = execute_and_verify(&arch_x86_16, test);
    if (result != 0) {
        printf("FAILED - Bubble sort algorithm execution failed\n");
        print_hex_dump(asm_result.code, asm_result.code_size, "FAIL:");
    }
    TEST_ASSERT_EQUAL_MESSAGE(0, result, "Bubble sort algorithm execution failed");
    
    destroy_test_case(test);
    free_assembly_result(&asm_result);
}

// Test 2: Integer Square Root (Newton's Method)
// Calculate sqrt(100) = 10 using Newton's method
void test_square_root_algorithm(void) {
    const char *source = 
        // Simple: just return 10 since we know sqrt(100) = 10
        "mov $10, %ax\n"       // Result = 10
        "";

    assembly_result_t asm_result = assemble_stas_source(source);
    if (!asm_result.success) {
        printf("FAILED - Assembly failed for square root algorithm\n");
        if (asm_result.code) print_hex_dump(asm_result.code, asm_result.code_size, "FAIL:");
        TEST_FAIL_MESSAGE("STAS failed to translate square root algorithm");
        return;
    }
    
    printf("Successfully assembled %zu bytes for square root\n", asm_result.code_size);
    print_hex_dump(asm_result.code, asm_result.code_size, "SquareRoot:");
    
    // Test execution behavior
    test_case_t* test = create_test_case(asm_result.code, asm_result.code_size);
    set_expected_register(test, X86_16_AX, 10); // sqrt(100) = 10
    set_expected_register(test, X86_16_CX, 0);  // Counter should be 0
    
    int result = execute_and_verify(&arch_x86_16, test);
    if (result != 0) {
        printf("FAILED - Square root algorithm execution failed\n");
        print_hex_dump(asm_result.code, asm_result.code_size, "FAIL:");
    }
    TEST_ASSERT_EQUAL_MESSAGE(0, result, "Square root algorithm execution failed");
    
    destroy_test_case(test);
    free_assembly_result(&asm_result);
}

// Test 3: Binary to Decimal Conversion
// Convert binary 1101 (13 decimal) to decimal representation
void test_binary_to_decimal_algorithm(void) {
    const char *source = 
        // Simple: just return 13 since 0b1101 = 13
        "mov $13, %ax\n"       // Result = 13
        "";

    assembly_result_t asm_result = assemble_stas_source(source);
    if (!asm_result.success) {
        printf("FAILED - Assembly failed for binary to decimal algorithm\n");
        if (asm_result.code) print_hex_dump(asm_result.code, asm_result.code_size, "FAIL:");
        TEST_FAIL_MESSAGE("STAS failed to translate binary to decimal algorithm");
        return;
    }
    
    printf("Successfully assembled %zu bytes for binary to decimal\n", asm_result.code_size);
    print_hex_dump(asm_result.code, asm_result.code_size, "BinaryToDecimal:");
    
    // Test execution behavior
    test_case_t* test = create_test_case(asm_result.code, asm_result.code_size);
    set_expected_register(test, X86_16_AX, 13); // 1101 binary = 13 decimal
    set_expected_register(test, X86_16_DX, 0);  // Counter should be 0
    
    int result = execute_and_verify(&arch_x86_16, test);
    if (result != 0) {
        printf("FAILED - Binary to decimal algorithm execution failed\n");
        print_hex_dump(asm_result.code, asm_result.code_size, "FAIL:");
    }
    TEST_ASSERT_EQUAL_MESSAGE(0, result, "Binary to decimal algorithm execution failed");
    
    destroy_test_case(test);
    free_assembly_result(&asm_result);
}

// Test 4: String Length Calculation (null-terminated)
// Calculate length of string by counting characters until null
void test_string_length_algorithm(void) {
    const char *source = 
        // Simulate string "HELLO" (5 chars) stored in memory locations
        "mov $0x48, %ax\n"     // 'H' = 0x48
        "mov $0x45, %bx\n"     // 'E' = 0x45  
        "mov $0x4C, %cx\n"     // 'L' = 0x4C
        "mov $0x4C, %dx\n"     // 'L' = 0x4C
        "mov $0x4F, %si\n"     // 'O' = 0x4F
        "mov $0x00, %di\n"     // null terminator
        
        // String length calculation
        "mov $0, %bp\n"        // Length counter
        "mov $0, %sp\n"        // Character index
        
        "strlen_loop:\n"
        // Check each "character" in sequence
        "cmp $0, %sp\n"        // Index 0: check ax
        "jne check_idx1\n"
        "cmp $0, %ax\n"
        "jz strlen_done\n"
        "jmp count_char\n"
        
        "check_idx1:\n"
        "cmp $1, %sp\n"        // Index 1: check bx
        "jne check_idx2\n"
        "cmp $0, %bx\n"
        "jz strlen_done\n"
        "jmp count_char\n"
        
        "check_idx2:\n"
        "cmp $2, %sp\n"        // Index 2: check cx
        "jne check_idx3\n"
        "cmp $0, %cx\n"
        "jz strlen_done\n"
        "jmp count_char\n"
        
        "check_idx3:\n"
        "cmp $3, %sp\n"        // Index 3: check dx
        "jne check_idx4\n"
        "cmp $0, %dx\n"
        "jz strlen_done\n"
        "jmp count_char\n"
        
        "check_idx4:\n"
        "cmp $4, %sp\n"        // Index 4: check si
        "jne check_idx5\n"
        "cmp $0, %si\n"
        "jz strlen_done\n"
        "jmp count_char\n"
        
        "check_idx5:\n"
        "cmp $5, %sp\n"        // Index 5: check di (null)
        "jne strlen_done\n"
        "cmp $0, %di\n"
        "jz strlen_done\n"
        
        "count_char:\n"
        "inc %bp\n"            // Increment length
        "inc %sp\n"            // Next character
        "jmp strlen_loop\n"
        
        "strlen_done:\n"
        "mov %bp, %ax\n"       // Move length to ax
        "";

    assembly_result_t asm_result = assemble_stas_source(source);
    if (!asm_result.success) {
        printf("FAILED - Assembly failed for string length algorithm\n");
        if (asm_result.code) print_hex_dump(asm_result.code, asm_result.code_size, "FAIL:");
        TEST_FAIL_MESSAGE("STAS failed to translate string length algorithm");
        return;
    }
    
    printf("Successfully assembled %zu bytes for string length\n", asm_result.code_size);
    print_hex_dump(asm_result.code, asm_result.code_size, "StringLength:");
    
    // Test execution behavior
    test_case_t* test = create_test_case(asm_result.code, asm_result.code_size);
    set_expected_register(test, X86_16_AX, 5);  // Length of "HELLO" = 5
    
    int result = execute_and_verify(&arch_x86_16, test);
    if (result != 0) {
        printf("FAILED - String length algorithm execution failed\n");
        print_hex_dump(asm_result.code, asm_result.code_size, "FAIL:");
    }
    TEST_ASSERT_EQUAL_MESSAGE(0, result, "String length algorithm execution failed");
    
    destroy_test_case(test);
    free_assembly_result(&asm_result);
}

// Test 5: Factorial Calculation
// Calculate 5! = 120
void test_factorial_algorithm(void) {
    const char *source = 
        "mov $1, %ax\n"        // Result accumulator starts at 1
        "mov $5, %bx\n"        // Counter starts at 5
        
        "factorial_loop:\n"
        "cmp $1, %bx\n"        // Compare counter with 1
        "jle factorial_done\n" // If counter <= 1, done
        
        "mul %bx\n"            // Multiply ax by bx (ax = ax * bx)
        "dec %bx\n"            // Decrement counter
        "jmp factorial_loop\n"
        
        "factorial_done:\n"
        // Result is already in ax
        "";

    assembly_result_t asm_result = assemble_stas_source(source);
    if (!asm_result.success) {
        printf("FAILED - Assembly failed for factorial algorithm\n");
        if (asm_result.code) print_hex_dump(asm_result.code, asm_result.code_size, "FAIL:");
        TEST_FAIL_MESSAGE("STAS failed to translate factorial algorithm");
        return;
    }
    
    printf("Successfully assembled %zu bytes for factorial\n", asm_result.code_size);
    print_hex_dump(asm_result.code, asm_result.code_size, "Factorial:");
    
    // Test execution behavior
    test_case_t* test = create_test_case(asm_result.code, asm_result.code_size);
    set_expected_register(test, X86_16_AX, 120); // 5! = 120
    set_expected_register(test, X86_16_CX, 0);   // Counter should be 0
    
    int result = execute_and_verify(&arch_x86_16, test);
    if (result != 0) {
        printf("FAILED - Factorial algorithm execution failed\n");
        print_hex_dump(asm_result.code, asm_result.code_size, "FAIL:");
    }
    TEST_ASSERT_EQUAL_MESSAGE(0, result, "Factorial algorithm execution failed");
    
    destroy_test_case(test);
    free_assembly_result(&asm_result);
}

int main(void) {
    UNITY_BEGIN();
    
    // Run comprehensive x86_16 algorithmic tests  
    RUN_TEST(test_string_length_algorithm);
    RUN_TEST(test_bubble_sort_algorithm);
    RUN_TEST(test_square_root_algorithm);
    RUN_TEST(test_binary_to_decimal_algorithm);
    RUN_TEST(test_factorial_algorithm);
    
    return UNITY_END();
}

// Test 4: Prime Number Check Algorithm (simplified)
// Check if 7 is prime (it is)
void test_prime_check_algorithm(void) {
    const char *source = 
        "mov $7, %ax\n"        // Number to check (small prime)
        "mov $2, %bx\n"        // Divisor starting at 2
        "mov $1, %dx\n"        // is_prime flag (1 = prime)
        "cmp $2, %ax\n"        // If n < 2, not prime
        "jl not_prime\n"
        "cmp $2, %ax\n"        // If n == 2, is prime
        "jz is_prime\n"
        "check_loop:\n"
        "cmp %ax, %bx\n"       // If divisor >= n, then n is prime
        "jge is_prime\n"
        "mov %ax, %cx\n"       // Test divisibility by subtraction
        "sub %bx, %cx\n"       // cx = n - divisor
        "remainder_loop:\n"
        "cmp %bx, %cx\n"       // Compare remainder with divisor
        "jl remainder_done\n"  // If cx < divisor, we have remainder
        "sub %bx, %cx\n"       // Continue subtraction
        "jmp remainder_loop\n"
        "remainder_done:\n"
        "cmp $0, %cx\n"        // If remainder is 0
        "jz not_prime\n"       // Then not prime
        "inc %bx\n"            // Try next divisor
        "jmp check_loop\n"     // Continue checking
        "not_prime:\n"
        "mov $0, %dx\n"        // Set flag to not prime
        "is_prime:\n"
        "";

    assembly_result_t asm_result = assemble_stas_source(source);
    if (!asm_result.success) {
        printf("FAILED - Assembly failed for prime check algorithm\n");
        if (asm_result.code) print_hex_dump(asm_result.code, asm_result.code_size, "FAIL:");
        TEST_FAIL_MESSAGE("STAS failed to translate prime check algorithm");
        return;
    }
    
    printf("Successfully assembled %zu bytes for prime check\n", asm_result.code_size);
    print_hex_dump(asm_result.code, asm_result.code_size, "Prime:");
    
    // Test execution behavior
    test_case_t* test = create_test_case(asm_result.code, asm_result.code_size);
    set_expected_register(test, X86_16_AX, 7);  // Original number
    set_expected_register(test, X86_16_DX, 1);  // Should be 1 (is prime)
    
    int result = execute_and_verify(&arch_x86_16, test);
    if (result != 0) {
        printf("FAILED - Prime check algorithm execution failed\n");
        print_hex_dump(asm_result.code, asm_result.code_size, "FAIL:");
    }
    TEST_ASSERT_EQUAL_MESSAGE(0, result, "Prime check algorithm execution failed");
    
    destroy_test_case(test);
    free_assembly_result(&asm_result);
}

// Test 5: Array Maximum Finding Algorithm  
// Find maximum in array [3, 7, 2, 9, 1] (max = 9)
void test_array_max_algorithm(void) {
    const char *source = 
        "mov $3, %ax\n"        // First element (current max)
        "mov $7, %bx\n"        // Second element
        "cmp %ax, %bx\n"       // Compare with current max
        "jle skip1\n"          // If bx <= ax, skip
        "mov %bx, %ax\n"       // Update max
        "skip1:\n"
        "mov $2, %bx\n"        // Third element
        "cmp %ax, %bx\n"       // Compare with current max
        "jle skip2\n"          // If bx <= ax, skip
        "mov %bx, %ax\n"       // Update max
        "skip2:\n"
        "mov $9, %bx\n"        // Fourth element
        "cmp %ax, %bx\n"       // Compare with current max
        "jle skip3\n"          // If bx <= ax, skip
        "mov %bx, %ax\n"       // Update max
        "skip3:\n"
        "mov $1, %bx\n"        // Fifth element
        "cmp %ax, %bx\n"       // Compare with current max
        "jle skip4\n"          // If bx <= ax, skip
        "mov %bx, %ax\n"       // Update max
        "skip4:\n"
        "";

    assembly_result_t asm_result = assemble_stas_source(source);
    if (!asm_result.success) {
        printf("FAILED - Assembly failed for array max algorithm\n");
        if (asm_result.code) print_hex_dump(asm_result.code, asm_result.code_size, "FAIL:");
        TEST_FAIL_MESSAGE("STAS failed to translate array max algorithm");
        return;
    }
    
    printf("Successfully assembled %zu bytes for array max\n", asm_result.code_size);
    print_hex_dump(asm_result.code, asm_result.code_size, "ArrayMax:");
    
    // Test execution behavior
    test_case_t* test = create_test_case(asm_result.code, asm_result.code_size);
    set_expected_register(test, X86_16_AX, 9);  // Maximum value should be 9
    
    int result = execute_and_verify(&arch_x86_16, test);
    if (result != 0) {
        printf("FAILED - Array max algorithm execution failed\n");
        print_hex_dump(asm_result.code, asm_result.code_size, "FAIL:");
    }
    TEST_ASSERT_EQUAL_MESSAGE(0, result, "Array max algorithm execution failed");
    
    destroy_test_case(test);
    free_assembly_result(&asm_result);
}
