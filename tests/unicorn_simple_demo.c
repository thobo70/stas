/*
 * STAS Unicorn Engine Simple Test
 * Basic functionality test with simpler instruction sequences
 */

#include <stdio.h>
#include <stdlib.h>
#include <unicorn/unicorn.h>

#define GREEN "\033[0;32m"
#define RED "\033[0;31m"
#define BLUE "\033[0;34m"
#define NC "\033[0m"

void print_result(const char* test, int success) {
    if (success) {
        printf(GREEN "[PASS]" NC " %s\n", test);
    } else {
        printf(RED "[FAIL]" NC " %s\n", test);
    }
}

int test_x86_64_simple() {
    uc_engine *uc;
    uc_err err;
    
    // Initialize x86-64 emulator
    err = uc_open(UC_ARCH_X86, UC_MODE_64, &uc);
    if (err != UC_ERR_OK) {
        printf("Failed to initialize Unicorn Engine: %s\n", uc_strerror(err));
        return 0;
    }
    
    // Simple code: mov rax, 42; nop
    unsigned char code[] = {
        0x48, 0xc7, 0xc0, 0x2a, 0x00, 0x00, 0x00,  // mov rax, 42
        0x90                                         // nop
    };
    
    uint64_t address = 0x1000000;
    uint64_t rax_value = 0;
    
    // Map memory
    err = uc_mem_map(uc, address, 0x2000, UC_PROT_ALL);
    if (err != UC_ERR_OK) {
        printf("Failed to map memory: %s\n", uc_strerror(err));
        uc_close(uc);
        return 0;
    }
    
    // Write code
    err = uc_mem_write(uc, address, code, sizeof(code));
    if (err != UC_ERR_OK) {
        printf("Failed to write code: %s\n", uc_strerror(err));
        uc_close(uc);
        return 0;
    }
    
    // Execute exactly the number of instructions we have
    err = uc_emu_start(uc, address, address + sizeof(code), 0, 2);
    if (err != UC_ERR_OK) {
        printf("Failed to execute code: %s\n", uc_strerror(err));
        uc_close(uc);
        return 0;
    }
    
    // Check result
    err = uc_reg_read(uc, UC_X86_REG_RAX, &rax_value);
    if (err != UC_ERR_OK) {
        printf("Failed to read register: %s\n", uc_strerror(err));
        uc_close(uc);
        return 0;
    }
    
    uc_close(uc);
    
    if (rax_value == 42) {
        return 1;
    } else {
        printf("Expected RAX=42, got RAX=%lu\n", rax_value);
        return 0;
    }
}

int main() {
    printf(BLUE "=== STAS Unicorn Engine Simple Test ===" NC "\n\n");
    
    int total_tests = 0;
    int passed_tests = 0;
    
    // Test x86-64
    total_tests++;
    if (test_x86_64_simple()) {
        passed_tests++;
        print_result("x86-64 basic instruction execution", 1);
    } else {
        print_result("x86-64 basic instruction execution", 0);
    }
    
    printf("\n=== Test Summary ===\n");
    printf("Total tests: %d\n", total_tests);
    printf("Passed: %d\n", passed_tests);
    printf("Failed: %d\n", total_tests - passed_tests);
    
    if (passed_tests == total_tests) {
        printf(GREEN "All tests passed!" NC "\n");
        return 0;
    } else {
        printf(RED "Some tests failed!" NC "\n");
        return 1;
    }
}
