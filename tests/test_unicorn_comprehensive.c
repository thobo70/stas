/*
 * STAS Unicorn Engine Test Program
 * Comprehensive testing of multi-architecture instruction emulation
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unicorn/unicorn.h>

// Test result tracking
static int tests_run = 0;
static int tests_passed = 0;

// Colors for output
#define GREEN "\033[0;32m"
#define RED "\033[0;31m"
#define BLUE "\033[0;34m"
#define YELLOW "\033[1;33m"
#define NC "\033[0m" // No Color

void print_status(const char* status, const char* message) {
    if (strcmp(status, "PASS") == 0) {
        printf(GREEN "[PASS]" NC " %s\n", message);
        tests_passed++;
    } else if (strcmp(status, "FAIL") == 0) {
        printf(RED "[FAIL]" NC " %s\n", message);
    } else if (strcmp(status, "INFO") == 0) {
        printf(BLUE "[INFO]" NC " %s\n", message);
    }
}

// Test x86-64 instruction execution
int test_x86_64() {
    uc_engine *uc;
    uc_err err;
    
    tests_run++;
    
    // Initialize x86-64 emulator
    err = uc_open(UC_ARCH_X86, UC_MODE_64, &uc);
    if (err != UC_ERR_OK) {
        print_status("FAIL", "x86-64: Failed to initialize Unicorn Engine");
        return 0;
    }
    
    // Simple x86-64 code: mov rax, 42; ret
    unsigned char x86_64_code[] = {
        0x48, 0xc7, 0xc0, 0x2a, 0x00, 0x00, 0x00,  // mov rax, 42
        0xc3                                         // ret
    };
    
    uint64_t address = 0x1000000;
    uint64_t rax_value = 0;
    
    // Map memory for execution
    err = uc_mem_map(uc, address, 2 * 1024 * 1024, UC_PROT_ALL);
    if (err != UC_ERR_OK) {
        print_status("FAIL", "x86-64: Failed to map memory");
        uc_close(uc);
        return 0;
    }
    
    // Write code to memory
    err = uc_mem_write(uc, address, x86_64_code, sizeof(x86_64_code));
    if (err != UC_ERR_OK) {
        print_status("FAIL", "x86-64: Failed to write code to memory");
        uc_close(uc);
        return 0;
    }
    
    // Execute the code
    err = uc_emu_start(uc, address, address + sizeof(x86_64_code), 0, 0);
    if (err != UC_ERR_OK) {
        print_status("FAIL", "x86-64: Failed to execute code");
        uc_close(uc);
        return 0;
    }
    
    // Check RAX register value
    err = uc_reg_read(uc, UC_X86_REG_RAX, &rax_value);
    if (err != UC_ERR_OK || rax_value != 42) {
        print_status("FAIL", "x86-64: Incorrect register value after execution");
        uc_close(uc);
        return 0;
    }
    
    uc_close(uc);
    print_status("PASS", "x86-64: MOV instruction executed correctly");
    return 1;
}

// Test x86-32 instruction execution
int test_x86_32() {
    uc_engine *uc;
    uc_err err;
    
    tests_run++;
    
    // Initialize x86-32 emulator
    err = uc_open(UC_ARCH_X86, UC_MODE_32, &uc);
    if (err != UC_ERR_OK) {
        print_status("FAIL", "x86-32: Failed to initialize Unicorn Engine");
        return 0;
    }
    
    // Simple x86-32 code: mov eax, 0x1337; ret
    unsigned char x86_32_code[] = {
        0xb8, 0x37, 0x13, 0x00, 0x00,  // mov eax, 0x1337
        0xc3                            // ret
    };
    
    uint32_t address = 0x1000000;
    uint32_t eax_value = 0;
    
    // Map memory for execution
    err = uc_mem_map(uc, address, 2 * 1024 * 1024, UC_PROT_ALL);
    if (err != UC_ERR_OK) {
        print_status("FAIL", "x86-32: Failed to map memory");
        uc_close(uc);
        return 0;
    }
    
    // Write code to memory
    err = uc_mem_write(uc, address, x86_32_code, sizeof(x86_32_code));
    if (err != UC_ERR_OK) {
        print_status("FAIL", "x86-32: Failed to write code to memory");
        uc_close(uc);
        return 0;
    }
    
    // Execute the code
    err = uc_emu_start(uc, address, address + sizeof(x86_32_code), 0, 0);
    if (err != UC_ERR_OK) {
        print_status("FAIL", "x86-32: Failed to execute code");
        uc_close(uc);
        return 0;
    }
    
    // Check EAX register value
    err = uc_reg_read(uc, UC_X86_REG_EAX, &eax_value);
    if (err != UC_ERR_OK || eax_value != 0x1337) {
        print_status("FAIL", "x86-32: Incorrect register value after execution");
        uc_close(uc);
        return 0;
    }
    
    uc_close(uc);
    print_status("PASS", "x86-32: MOV instruction executed correctly");
    return 1;
}

// Test x86-16 instruction execution
int test_x86_16() {
    uc_engine *uc;
    uc_err err;
    
    tests_run++;
    
    // Initialize x86-16 emulator
    err = uc_open(UC_ARCH_X86, UC_MODE_16, &uc);
    if (err != UC_ERR_OK) {
        print_status("FAIL", "x86-16: Failed to initialize Unicorn Engine");
        return 0;
    }
    
    // Simple x86-16 code: mov ax, 0x1234; ret
    unsigned char x86_16_code[] = {
        0xb8, 0x34, 0x12,  // mov ax, 0x1234
        0xc3               // ret
    };
    
    uint32_t address = 0x1000000;
    uint16_t ax_value = 0;
    
    // Map memory for execution
    err = uc_mem_map(uc, address, 2 * 1024 * 1024, UC_PROT_ALL);
    if (err != UC_ERR_OK) {
        print_status("FAIL", "x86-16: Failed to map memory");
        uc_close(uc);
        return 0;
    }
    
    // Write code to memory
    err = uc_mem_write(uc, address, x86_16_code, sizeof(x86_16_code));
    if (err != UC_ERR_OK) {
        print_status("FAIL", "x86-16: Failed to write code to memory");
        uc_close(uc);
        return 0;
    }
    
    // Execute the code
    err = uc_emu_start(uc, address, address + sizeof(x86_16_code), 0, 0);
    if (err != UC_ERR_OK) {
        print_status("FAIL", "x86-16: Failed to execute code");
        uc_close(uc);
        return 0;
    }
    
    // Check AX register value
    err = uc_reg_read(uc, UC_X86_REG_AX, &ax_value);
    if (err != UC_ERR_OK || ax_value != 0x1234) {
        print_status("FAIL", "x86-16: Incorrect register value after execution");
        uc_close(uc);
        return 0;
    }
    
    uc_close(uc);
    print_status("PASS", "x86-16: MOV instruction executed correctly");
    return 1;
}

// Test ARM64 instruction execution
int test_arm64() {
    uc_engine *uc;
    uc_err err;
    
    tests_run++;
    
    // Initialize ARM64 emulator
    err = uc_open(UC_ARCH_ARM64, UC_MODE_ARM, &uc);
    if (err != UC_ERR_OK) {
        print_status("FAIL", "ARM64: Failed to initialize Unicorn Engine");
        return 0;
    }
    
    // Simple ARM64 code: mov x0, 0x12345678; ret
    unsigned char arm64_code[] = {
        0xf0, 0xac, 0x8a, 0x52,  // mov w0, #0x5678
        0xe0, 0x46, 0xa2, 0x72,  // movk w0, #0x1234, lsl #16
        0xc0, 0x03, 0x5f, 0xd6   // ret
    };
    
    uint64_t address = 0x1000000;
    uint64_t x0_value = 0;
    
    // Map memory for execution
    err = uc_mem_map(uc, address, 2 * 1024 * 1024, UC_PROT_ALL);
    if (err != UC_ERR_OK) {
        print_status("FAIL", "ARM64: Failed to map memory");
        uc_close(uc);
        return 0;
    }
    
    // Write code to memory
    err = uc_mem_write(uc, address, arm64_code, sizeof(arm64_code));
    if (err != UC_ERR_OK) {
        print_status("FAIL", "ARM64: Failed to write code to memory");
        uc_close(uc);
        return 0;
    }
    
    // Execute the code
    err = uc_emu_start(uc, address, address + sizeof(arm64_code), 0, 0);
    if (err != UC_ERR_OK) {
        print_status("FAIL", "ARM64: Failed to execute code");
        uc_close(uc);
        return 0;
    }
    
    // Check X0 register value
    err = uc_reg_read(uc, UC_ARM64_REG_X0, &x0_value);
    if (err != UC_ERR_OK || (x0_value & 0xFFFFFFFF) != 0x12345678) {
        print_status("FAIL", "ARM64: Incorrect register value after execution");
        uc_close(uc);
        return 0;
    }
    
    uc_close(uc);
    print_status("PASS", "ARM64: MOV instruction executed correctly");
    return 1;
}

// Test arithmetic operations across architectures
int test_arithmetic() {
    uc_engine *uc;
    uc_err err;
    
    tests_run++;
    
    // Test x86-64 addition
    err = uc_open(UC_ARCH_X86, UC_MODE_64, &uc);
    if (err != UC_ERR_OK) {
        print_status("FAIL", "Arithmetic: Failed to initialize x86-64 emulator");
        return 0;
    }
    
    // x86-64 code: mov rax, 10; add rax, 5; ret
    unsigned char add_code[] = {
        0x48, 0xc7, 0xc0, 0x0a, 0x00, 0x00, 0x00,  // mov rax, 10
        0x48, 0x83, 0xc0, 0x05,                     // add rax, 5
        0xc3                                         // ret
    };
    
    uint64_t address = 0x1000000;
    uint64_t result = 0;
    
    err = uc_mem_map(uc, address, 2 * 1024 * 1024, UC_PROT_ALL);
    if (err == UC_ERR_OK) {
        err = uc_mem_write(uc, address, add_code, sizeof(add_code));
        if (err == UC_ERR_OK) {
            err = uc_emu_start(uc, address, address + sizeof(add_code), 0, 0);
            if (err == UC_ERR_OK) {
                err = uc_reg_read(uc, UC_X86_REG_RAX, &result);
                if (err == UC_ERR_OK && result == 15) {
                    print_status("PASS", "Arithmetic: x86-64 ADD instruction (10+5=15)");
                    uc_close(uc);
                    return 1;
                }
            }
        }
    }
    
    print_status("FAIL", "Arithmetic: x86-64 ADD instruction failed");
    uc_close(uc);
    return 0;
}

int main() {
    printf("==========================================\n");
    printf("STAS Unicorn Engine Comprehensive Test\n");
    printf("==========================================\n\n");
    
    print_status("INFO", "Testing multi-architecture instruction emulation...");
    printf("\n");
    
    // Run all architecture tests
    test_x86_64();
    test_x86_32();
    test_x86_16();
    test_arm64();
    test_arithmetic();
    
    printf("\n==========================================\n");
    printf("Test Results Summary\n");
    printf("==========================================\n");
    printf("Tests run: %d\n", tests_run);
    printf("Tests passed: %d\n", tests_passed);
    printf("Tests failed: %d\n", tests_run - tests_passed);
    
    if (tests_passed == tests_run) {
        print_status("PASS", "All Unicorn Engine tests completed successfully!");
        printf("\n");
        print_status("INFO", "Multi-architecture emulation is working correctly");
        print_status("INFO", "STAS assembler testing infrastructure is ready");
        return 0;
    } else {
        print_status("FAIL", "Some tests failed");
        return 1;
    }
}
