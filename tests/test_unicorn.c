// Example Unicorn Engine integration for STAS instruction testing
// This demonstrates how to test assembled instructions with Unicorn

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#ifdef HAVE_UNICORN
#include <unicorn/unicorn.h>

// Test structure for instruction validation
typedef struct {
    const char *arch_name;
    uc_arch arch;
    uc_mode mode;
    const char *description;
    uint8_t *code;
    size_t code_size;
    uint64_t start_addr;
    uint64_t expected_result;
} instruction_test_t;

// Example x86-64 instruction tests
static uint8_t x86_64_mov_code[] = {
    0x48, 0xC7, 0xC0, 0x2A, 0x00, 0x00, 0x00  // movq $42, %rax
};

static uint8_t x86_64_add_code[] = {
    0x48, 0xC7, 0xC0, 0x05, 0x00, 0x00, 0x00,  // movq $5, %rax
    0x48, 0x83, 0xC0, 0x03                      // addq $3, %rax
};

// Example x86-32 instruction tests
static uint8_t x86_32_mov_code[] = {
    0xB8, 0x2A, 0x00, 0x00, 0x00  // movl $42, %eax
};

// Example instruction tests
static instruction_test_t test_cases[] = {
    {
        .arch_name = "x86_64",
        .arch = UC_ARCH_X86,
        .mode = UC_MODE_64,
        .description = "MOV immediate to RAX",
        .code = x86_64_mov_code,
        .code_size = sizeof(x86_64_mov_code),
        .start_addr = 0x1000000,
        .expected_result = 42
    },
    {
        .arch_name = "x86_64", 
        .arch = UC_ARCH_X86,
        .mode = UC_MODE_64,
        .description = "ADD immediate to RAX",
        .code = x86_64_add_code,
        .code_size = sizeof(x86_64_add_code),
        .start_addr = 0x1000000,
        .expected_result = 8
    },
    {
        .arch_name = "x86_32",
        .arch = UC_ARCH_X86, 
        .mode = UC_MODE_32,
        .description = "MOV immediate to EAX",
        .code = x86_32_mov_code,
        .code_size = sizeof(x86_32_mov_code),
        .start_addr = 0x1000000,
        .expected_result = 42
    }
};

// Test a single instruction sequence
int test_instruction(instruction_test_t *test) {
    uc_engine *uc;
    uc_err err;
    uint64_t result;
    
    printf("Testing %s: %s... ", test->arch_name, test->description);
    
    // Initialize engine
    err = uc_open(test->arch, test->mode, &uc);
    if (err != UC_ERR_OK) {
        printf("FAIL (open): %s\n", uc_strerror(err));
        return -1;
    }
    
    // Map memory
    err = uc_mem_map(uc, test->start_addr, 2 * 1024 * 1024, UC_PROT_ALL);
    if (err != UC_ERR_OK) {
        printf("FAIL (map): %s\n", uc_strerror(err));
        uc_close(uc);
        return -1;
    }
    
    // Write code to memory
    err = uc_mem_write(uc, test->start_addr, test->code, test->code_size);
    if (err != UC_ERR_OK) {
        printf("FAIL (write): %s\n", uc_strerror(err));
        uc_close(uc);
        return -1;
    }
    
    // Execute code
    err = uc_emu_start(uc, test->start_addr, 
                      test->start_addr + test->code_size, 0, 0);
    if (err != UC_ERR_OK) {
        printf("FAIL (execute): %s\n", uc_strerror(err));
        uc_close(uc);
        return -1;
    }
    
    // Read result from appropriate register
    if (test->mode == UC_MODE_64) {
        err = uc_reg_read(uc, UC_X86_REG_RAX, &result);
    } else if (test->mode == UC_MODE_32) {
        uint32_t result32;
        err = uc_reg_read(uc, UC_X86_REG_EAX, &result32);
        result = result32;
    } else {
        uint16_t result16;
        err = uc_reg_read(uc, UC_X86_REG_AX, &result16);
        result = result16;
    }
    
    if (err != UC_ERR_OK) {
        printf("FAIL (read): %s\n", uc_strerror(err));
        uc_close(uc);
        return -1;
    }
    
    // Check result
    if (result == test->expected_result) {
        printf("PASS (result: %lu)\n", result);
        uc_close(uc);
        return 0;
    } else {
        printf("FAIL (expected: %lu, got: %lu)\n", 
               test->expected_result, result);
        uc_close(uc);
        return -1;
    }
}

// Run all instruction tests
int run_unicorn_tests(void) {
    int total_tests = sizeof(test_cases) / sizeof(test_cases[0]);
    int passed = 0;
    int failed = 0;
    
    printf("Running Unicorn Engine Instruction Tests\n");
    printf("==========================================\n");
    
    for (int i = 0; i < total_tests; i++) {
        if (test_instruction(&test_cases[i]) == 0) {
            passed++;
        } else {
            failed++;
        }
    }
    
    printf("\nTest Results:\n");
    printf("=============\n");
    printf("Total tests: %d\n", total_tests);
    printf("Passed: %d\n", passed);
    printf("Failed: %d\n", failed);
    
    return failed == 0 ? 0 : 1;
}

#endif // HAVE_UNICORN

int main(void) {
#ifdef HAVE_UNICORN
    return run_unicorn_tests();
#else
    printf("Unicorn Engine not available.\n");
    printf("Install with: sudo apt-get install libunicorn-dev\n");
    printf("Then compile with: gcc -DHAVE_UNICORN -lunicorn test_unicorn.c\n");
    return 0;
#endif
}
