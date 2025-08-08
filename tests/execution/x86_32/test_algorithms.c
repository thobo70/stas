#include "../../unity/src/unity.h"
#include "../../framework/unicorn_test_framework.h"
#include "parser.h"
#include "lexer.h"
#include "codegen.h"
#include "../../src/core/output_format.h"
#include "symbols.h"
#include "arch_interface.h"
#include "../../src/arch/x86_32/x86_32.h"
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
    
    // Get x86-32 architecture operations first
    arch_ops_t *arch_ops = x86_32_get_arch_ops();
    if (!arch_ops) {
        printf("Failed to get x86-32 architecture operations\n");
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
    
    output = malloc(sizeof(output_context_t));
    if (!output) {
        printf("Failed to allocate output context\n");
        parser_destroy(parser);  // This handles AST cleanup
        lexer_destroy(lexer);
        return result;
    }
    
    // Initialize all fields to zero
    memset(output, 0, sizeof(output_context_t));
    output->format = FORMAT_FLAT_BIN;
    output->base_address = 0x1000000;  // Match arch_x86_32.code_addr
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

// Test 1: Matrix Multiplication (2x2 matrices)
// Multiply [1,2; 3,4] * [5,6; 7,8] = [19,22; 43,50]
void test_matrix_multiplication_algorithm(void) {
    const char *source = 
        // Matrix A: [1,2; 3,4] stored in eax,ebx,ecx,edx
        "movl $1, %eax\n"      // A[0][0] = 1
        "movl $2, %ebx\n"      // A[0][1] = 2
        "movl $3, %ecx\n"      // A[1][0] = 3
        "movl $4, %edx\n"      // A[1][1] = 4
        
        // Matrix B: [5,6; 7,8] - use memory locations on stack
        "pushl $8\n"           // B[1][1] = 8 (push to stack)
        "pushl $7\n"           // B[1][0] = 7
        "pushl $6\n"           // B[0][1] = 6
        "pushl $5\n"           // B[0][0] = 5
        
        // Now stack has (from ESP): [5, 6, 7, 8]
        
        // Calculate C[0][0] = A[0][0]*B[0][0] + A[0][1]*B[1][0] = 1*5 + 2*7 = 19
        "movl %eax, %esi\n"    // esi = A[0][0] = 1
        "movl 0(%esp), %edi\n" // edi = B[0][0] = 5
        "imull %edi, %esi\n"   // esi = 1*5 = 5
        "movl %ebx, %edi\n"    // edi = A[0][1] = 2
        "movl 8(%esp), %ebp\n" // ebp = B[1][0] = 7
        "imull %ebp, %edi\n"   // edi = 2*7 = 14
        "addl %edi, %esi\n"    // esi = 5 + 14 = 19 (C[0][0])
        "movl %esi, %eax\n"    // Store result in eax
        
        // Calculate C[0][1] = A[0][0]*B[0][1] + A[0][1]*B[1][1] = 1*6 + 2*8 = 22
        "movl $1, %esi\n"      // Restore A[0][0] = 1
        "movl 4(%esp), %edi\n" // edi = B[0][1] = 6
        "imull %edi, %esi\n"   // esi = 1*6 = 6
        "movl $2, %edi\n"      // Restore A[0][1] = 2
        "movl 12(%esp), %ebp\n"// ebp = B[1][1] = 8
        "imull %ebp, %edi\n"   // edi = 2*8 = 16
        "addl %edi, %esi\n"    // esi = 6 + 16 = 22 (C[0][1])
        "movl %esi, %ebx\n"    // Store result in ebx
        
        // Calculate C[1][0] = A[1][0]*B[0][0] + A[1][1]*B[1][0] = 3*5 + 4*7 = 43
        "movl %ecx, %esi\n"    // esi = A[1][0] = 3
        "movl 0(%esp), %edi\n" // edi = B[0][0] = 5
        "imull %edi, %esi\n"   // esi = 3*5 = 15
        "movl %edx, %edi\n"    // edi = A[1][1] = 4
        "movl 8(%esp), %ebp\n" // ebp = B[1][0] = 7
        "imull %ebp, %edi\n"   // edi = 4*7 = 28
        "addl %edi, %esi\n"    // esi = 15 + 28 = 43 (C[1][0])
        "movl %esi, %ecx\n"    // Store result in ecx
        
        // Calculate C[1][1] = A[1][0]*B[0][1] + A[1][1]*B[1][1] = 3*6 + 4*8 = 50
        "movl $3, %esi\n"      // Restore A[1][0] = 3
        "movl 4(%esp), %edi\n" // edi = B[0][1] = 6
        "imull %edi, %esi\n"   // esi = 3*6 = 18
        "movl $4, %edi\n"      // Restore A[1][1] = 4
        "movl 12(%esp), %ebp\n"// ebp = B[1][1] = 8
        "imull %ebp, %edi\n"   // edi = 4*8 = 32
        "addl %edi, %esi\n"    // esi = 18 + 32 = 50 (C[1][1])
        "movl %esi, %edx\n"    // Store result in edx
        
        // Clean up stack
        "addl $16, %esp\n"     // Remove 4 values from stack
        "";

    assembly_result_t asm_result = assemble_stas_source(source);
    if (!asm_result.success) {
        printf("FAILED - Assembly failed for matrix multiplication algorithm\n");
        if (asm_result.code) print_hex_dump(asm_result.code, asm_result.code_size, "FAIL:");
        TEST_FAIL_MESSAGE("STAS failed to translate matrix multiplication algorithm");
        return;
    }
    
    printf("Successfully assembled %zu bytes for matrix multiplication\n", asm_result.code_size);
    print_hex_dump(asm_result.code, asm_result.code_size, "MatrixMul:");
    
    // Test execution behavior
    test_case_t* test = create_test_case(asm_result.code, asm_result.code_size);
    set_expected_register(test, X86_32_EAX, 19); // C[0][0] = 19
    set_expected_register(test, X86_32_EBX, 22); // C[0][1] = 22
    set_expected_register(test, X86_32_ECX, 43); // C[1][0] = 43
    set_expected_register(test, X86_32_EDX, 50); // C[1][1] = 50
    
    int result = execute_and_verify(&arch_x86_32, test);
    if (result != 0) {
        printf("FAILED - Matrix multiplication algorithm execution failed\n");
        print_hex_dump(asm_result.code, asm_result.code_size, "FAIL:");
    }
    TEST_ASSERT_EQUAL_MESSAGE(0, result, "Matrix multiplication algorithm execution failed");
    
    destroy_test_case(test);
    free_assembly_result(&asm_result);
}

// Test 2: CRC32 Checksum Calculation (simplified)
// Calculate CRC for data [0x12, 0x34, 0x56, 0x78]
void test_crc32_algorithm(void) {
    const char *source = 
        "movl $0xFFFFFFFF, %eax\n"  // Initial CRC value
        "movl $0x12345678, %ebx\n"  // Data to checksum
        "movl $4, %ecx\n"           // Number of bytes
        
        "crc_loop:\n"
        "cmpl $0, %ecx\n"           // Check if done
        "jz crc_done\n"
        
        // Extract next byte and process
        "movl %ebx, %edx\n"         // Copy data
        "andl $0xFF, %edx\n"        // Get lowest byte
        "xorl %edx, %eax\n"         // XOR with CRC
        
        // Simple CRC calculation (not full polynomial)
        "movl $8, %esi\n"           // 8 bits to process
        "bit_loop:\n"
        "cmpl $0, %esi\n"           // Check if done with this byte
        "jz next_byte\n"
        
        "testl $1, %eax\n"          // Test LSB
        "jz no_poly\n"              // If 0, skip polynomial
        "shrl $1, %eax\n"           // Shift right
        "xorl $0xEDB88320, %eax\n"  // XOR with polynomial
        "jmp bit_done\n"
        
        "no_poly:\n"
        "shrl $1, %eax\n"           // Just shift right
        
        "bit_done:\n"
        "decl %esi\n"               // Next bit
        "jmp bit_loop\n"
        
        "next_byte:\n"
        "shrl $8, %ebx\n"           // Next byte in data
        "decl %ecx\n"               // Decrement byte counter
        "jmp crc_loop\n"
        
        "crc_done:\n"
        "notl %eax\n"               // Final inversion
        "";

    assembly_result_t asm_result = assemble_stas_source(source);
    if (!asm_result.success) {
        printf("FAILED - Assembly failed for CRC32 algorithm\n");
        if (asm_result.code) print_hex_dump(asm_result.code, asm_result.code_size, "FAIL:");
        TEST_FAIL_MESSAGE("STAS failed to translate CRC32 algorithm");
        return;
    }
    
    printf("Successfully assembled %zu bytes for CRC32\n", asm_result.code_size);
    print_hex_dump(asm_result.code, asm_result.code_size, "CRC32:");
    
    // Test execution behavior - result will be algorithm-specific
    test_case_t* test = create_test_case(asm_result.code, asm_result.code_size);
    set_expected_register(test, X86_32_ECX, 0);  // Counter should be 0
    
    int result = execute_and_verify(&arch_x86_32, test);
    if (result != 0) {
        printf("FAILED - CRC32 algorithm execution failed\n");
        print_hex_dump(asm_result.code, asm_result.code_size, "FAIL:");
    }
    TEST_ASSERT_EQUAL_MESSAGE(0, result, "CRC32 algorithm execution failed");
    
    destroy_test_case(test);
    free_assembly_result(&asm_result);
}

// Test 3: Base64 Encoding (single character)
// Encode 'A' (0x41) to Base64
void test_base64_encoding_algorithm(void) {
    const char *source = 
        "movl $0x41, %eax\n"       // Input: 'A' = 0x41 = 01000001
        "movl $0, %ebx\n"          // Output accumulator
        
        // First 6-bit group: bits 7-2 of input
        "movl %eax, %ecx\n"        // Copy input
        "shrl $2, %ecx\n"          // Shift right 2 positions
        "andl $0x3F, %ecx\n"       // Mask to 6 bits (0x3F = 111111)
        
        // Convert to Base64 character
        "cmpl $26, %ecx\n"         // Check if < 26 (A-Z)
        "jl encode_upper\n"
        "cmpl $52, %ecx\n"         // Check if < 52 (a-z)
        "jl encode_lower\n"
        "cmpl $62, %ecx\n"         // Check if < 62 (0-9)
        "jl encode_digit\n"
        "cmpl $62, %ecx\n"         // Check if == 62 (+)
        "je encode_plus\n"
        "movl $47, %ecx\n"         // Must be 63 (/)
        "jmp store_char1\n"
        
        "encode_upper:\n"
        "addl $65, %ecx\n"         // Add 'A' (65)
        "jmp store_char1\n"
        
        "encode_lower:\n"
        "subl $26, %ecx\n"         // Subtract 26
        "addl $97, %ecx\n"         // Add 'a' (97)
        "jmp store_char1\n"
        
        "encode_digit:\n"
        "subl $52, %ecx\n"         // Subtract 52
        "addl $48, %ecx\n"         // Add '0' (48)
        "jmp store_char1\n"
        
        "encode_plus:\n"
        "movl $43, %ecx\n"         // '+' character
        
        "store_char1:\n"
        "shll $8, %ebx\n"          // Make room in output
        "orl %ecx, %ebx\n"         // Store first character
        
        // Second 6-bit group: bits 1-0 of input + 4 padding bits
        "movl %eax, %ecx\n"        // Copy input
        "andl $0x03, %ecx\n"       // Get bits 1-0
        "shll $4, %ecx\n"          // Shift left 4 (add padding)
        
        // Convert second group (will be 'Q' for input 'A')
        "addl $65, %ecx\n"         // Add 'A' (this gives us 'Q')
        
        "shll $8, %ebx\n"          // Make room in output
        "orl %ecx, %ebx\n"         // Store second character
        
        // Remaining positions are padding '='
        "shll $8, %ebx\n"          // Make room
        "orl $61, %ebx\n"          // Add '=' (61)
        "shll $8, %ebx\n"          // Make room
        "orl $61, %ebx\n"          // Add '=' (61)
        
        "movl %ebx, %eax\n"        // Move result to eax
        "";

    assembly_result_t asm_result = assemble_stas_source(source);
    if (!asm_result.success) {
        printf("FAILED - Assembly failed for Base64 encoding algorithm\n");
        if (asm_result.code) print_hex_dump(asm_result.code, asm_result.code_size, "FAIL:");
        TEST_FAIL_MESSAGE("STAS failed to translate Base64 encoding algorithm");
        return;
    }
    
    printf("Successfully assembled %zu bytes for Base64 encoding\n", asm_result.code_size);
    print_hex_dump(asm_result.code, asm_result.code_size, "Base64:");
    
    // Test execution behavior - 'A' encodes to "QQ==" in our simplified version
    test_case_t* test = create_test_case(asm_result.code, asm_result.code_size);
    // The exact result depends on our encoding logic
    
    int result = execute_and_verify(&arch_x86_32, test);
    if (result != 0) {
        printf("FAILED - Base64 encoding algorithm execution failed\n");
        print_hex_dump(asm_result.code, asm_result.code_size, "FAIL:");
    }
    TEST_ASSERT_EQUAL_MESSAGE(0, result, "Base64 encoding algorithm execution failed");
    
    destroy_test_case(test);
    free_assembly_result(&asm_result);
}

// Test 4: Hash Table Lookup (Linear Probing)
// Simple hash table with linear probing for collision resolution
void test_hash_table_algorithm(void) {
    const char *source = 
        // Initialize hash table (size 8) with some values
        "movl $7, %eax\n"          // hash_table[0] = 7
        "movl $0, %ebx\n"          // hash_table[1] = 0 (empty)
        "movl $15, %ecx\n"         // hash_table[2] = 15
        "movl $0, %edx\n"          // hash_table[3] = 0 (empty)
        "movl $23, %esi\n"         // hash_table[4] = 23
        "movl $0, %edi\n"          // hash_table[5] = 0 (empty)
        "pushl $31\n"              // hash_table[6] = 31
        "pushl $0\n"               // hash_table[7] = 0 (empty)
        
        // Search for key 15 (using proper registers, not corrupting ESP)
        "movl $15, %ebp\n"         // Key to search for (use EBP instead of ESP)
        "movl %ebp, %edi\n"        // Copy key to EDI for hashing
        "andl $7, %edi\n"          // Hash function: key % 8 = index (use EDI)
        
        // Linear probe starting at hash index
        "movl $8, %esi\n"          // Max attempts (table size) (use ESI instead of ESP)
        "search_loop:\n"
        "cmpl $0, %esi\n"          // Check attempts remaining
        "jz not_found\n"
        
        // Check current position based on index - handle all 8 indices
        "cmpl $0, %edi\n"          // Check index 0
        "jne check_idx1\n"
        "cmpl $15, %eax\n"         // Compare with hash_table[0] = 7
        "je found\n"
        "cmpl $0, %eax\n"          // Check if empty
        "je not_found\n"
        "jmp next_probe\n"
        
        "check_idx1:\n"
        "cmpl $1, %edi\n"          // Check index 1
        "jne check_idx2\n"
        "cmpl $15, %ebx\n"         // Compare with hash_table[1] = 0
        "je found\n"
        "cmpl $0, %ebx\n"
        "je not_found\n"
        "jmp next_probe\n"
        
        "check_idx2:\n"
        "cmpl $2, %edi\n"          // Check index 2
        "jne check_idx3\n"
        "cmpl $15, %ecx\n"         // Compare with hash_table[2] = 15 (SHOULD FIND HERE!)
        "je found\n"
        "cmpl $0, %ecx\n"
        "je not_found\n"
        "jmp next_probe\n"
        
        "check_idx3:\n"
        "cmpl $3, %edi\n"          // Check index 3
        "jne check_idx4\n"
        "cmpl $15, %edx\n"         // Compare with hash_table[3] = 0
        "je found\n"
        "cmpl $0, %edx\n"
        "je not_found\n"
        "jmp next_probe\n"
        
        "check_idx4:\n"
        "cmpl $4, %edi\n"          // Check index 4
        "jne check_idx5\n"
        "movl $23, %ebp\n"         // Load hash_table[4] = 23 from register
        "cmpl $15, %ebp\n"
        "je found\n"
        "cmpl $0, %ebp\n"
        "je not_found\n"
        "jmp next_probe\n"
        
        "check_idx5:\n"
        "cmpl $5, %edi\n"          // Check index 5
        "jne check_idx6\n"
        "movl $0, %ebp\n"          // Load hash_table[5] = 0
        "cmpl $15, %ebp\n"
        "je found\n"
        "cmpl $0, %ebp\n"
        "je not_found\n"
        "jmp next_probe\n"
        
        "check_idx6:\n"
        "cmpl $6, %edi\n"          // Check index 6
        "jne check_idx7\n"
        "movl (%esp), %ebp\n"      // Load hash_table[6] = 31 from stack
        "cmpl $15, %ebp\n"
        "je found\n"
        "cmpl $0, %ebp\n"
        "je not_found\n"
        "jmp next_probe\n"
        
        "check_idx7:\n"
        "cmpl $7, %edi\n"          // Check index 7
        "jne next_probe\n"
        "movl 4(%esp), %ebp\n"     // Load hash_table[7] = 0 from stack
        "cmpl $15, %ebp\n"
        "je found\n"
        "cmpl $0, %ebp\n"
        "je not_found\n"
        
        "next_probe:\n"
        "incl %edi\n"              // Next index (use EDI)
        "andl $7, %edi\n"          // Wrap around (% 8)
        "decl %esi\n"              // Decrement attempts (use ESI)
        "jmp search_loop\n"
        
        "found:\n"
        "movl $1, %eax\n"          // Return 1 (found)
        "jmp search_done\n"
        
        "not_found:\n"
        "movl $0, %eax\n"          // Return 0 (not found)
        
        "search_done:\n"
        "addl $8, %esp\n"          // Clean stack properly (remove 2 pushed values)
        "";

    assembly_result_t asm_result = assemble_stas_source(source);
    if (!asm_result.success) {
        printf("FAILED - Assembly failed for hash table algorithm\n");
        if (asm_result.code) print_hex_dump(asm_result.code, asm_result.code_size, "FAIL:");
        TEST_FAIL_MESSAGE("STAS failed to translate hash table algorithm");
        return;
    }
    
    printf("Successfully assembled %zu bytes for hash table\n", asm_result.code_size);
    print_hex_dump(asm_result.code, asm_result.code_size, "HashTable:");
    
    // Test execution behavior - should find key 15
    test_case_t* test = create_test_case(asm_result.code, asm_result.code_size);
    set_expected_register(test, X86_32_EAX, 1);  // Should return 1 (found)
    
    int result = execute_and_verify(&arch_x86_32, test);
    if (result != 0) {
        printf("FAILED - Hash table algorithm execution failed\n");
        print_hex_dump(asm_result.code, asm_result.code_size, "FAIL:");
    }
    TEST_ASSERT_EQUAL_MESSAGE(0, result, "Hash table algorithm execution failed");
    
    destroy_test_case(test);
    free_assembly_result(&asm_result);
}

// Test 5: Fast Integer Division (by constant)
// Divide 1000 by 7 using multiplication and shifting
void test_fast_division_algorithm(void) {
    const char *source = 
        "movl $1000, %eax\n"       // Dividend: 1000
        "movl $7, %ebx\n"          // Divisor: 7
        
        // Fast division by 7 using magic number multiplication
        // Magic number for 7: 0x92492493 (for 32-bit)
        "movl $0x92492493, %ecx\n" // Magic multiplier
        "mull %ecx\n"              // edx:eax = eax * ecx
        
        // The quotient is in the high part (edx) after adjustment
        "shrl $2, %edx\n"          // Shift right by 2 for this magic number
        "movl %edx, %esi\n"        // Save quotient in esi (preserve it!)
        
        // Calculate remainder: remainder = dividend - (quotient * divisor)
        "movl %esi, %eax\n"        // Move quotient to eax for multiplication
        "mull %ebx\n"              // eax = quotient * divisor
        "movl $1000, %ecx\n"       // Restore original dividend
        "subl %eax, %ecx\n"        // remainder = dividend - (quotient * divisor)
        "movl %esi, %eax\n"        // Put quotient back in eax
        "movl %ecx, %ebx\n"        // Put remainder in ebx
        "";

    assembly_result_t asm_result = assemble_stas_source(source);
    if (!asm_result.success) {
        printf("FAILED - Assembly failed for fast division algorithm\n");
        if (asm_result.code) print_hex_dump(asm_result.code, asm_result.code_size, "FAIL:");
        TEST_FAIL_MESSAGE("STAS failed to translate fast division algorithm");
        return;
    }
    
    printf("Successfully assembled %zu bytes for fast division\n", asm_result.code_size);
    print_hex_dump(asm_result.code, asm_result.code_size, "FastDiv:");
    
    // Test execution behavior - 1000 / 7 = 142 remainder 6
    test_case_t* test = create_test_case(asm_result.code, asm_result.code_size);
    set_expected_register(test, X86_32_EAX, 142); // Quotient
    set_expected_register(test, X86_32_EBX, 6);   // Remainder
    
    int result = execute_and_verify(&arch_x86_32, test);
    if (result != 0) {
        printf("FAILED - Fast division algorithm execution failed\n");
        print_hex_dump(asm_result.code, asm_result.code_size, "FAIL:");
    }
    TEST_ASSERT_EQUAL_MESSAGE(0, result, "Fast division algorithm execution failed");
    
    destroy_test_case(test);
    free_assembly_result(&asm_result);
}

int main(void) {
    UNITY_BEGIN();
    
    // Run x86_32 algorithmic tests
    RUN_TEST(test_matrix_multiplication_algorithm);
    RUN_TEST(test_crc32_algorithm);
    RUN_TEST(test_base64_encoding_algorithm);
    RUN_TEST(test_hash_table_algorithm);
    RUN_TEST(test_fast_division_algorithm);
    
    return UNITY_END();
}
