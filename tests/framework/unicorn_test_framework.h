#ifndef UNICORN_TEST_FRAMEWORK_H
#define UNICORN_TEST_FRAMEWORK_H

#include <unicorn/unicorn.h>
#include "unity.h"
#include <stdint.h>
#include <stdbool.h>

// Architecture definitions for testing
typedef struct {
    uc_arch arch;
    uc_mode mode;
    const char* name;
    uint64_t code_addr;
    uint64_t stack_addr;
    size_t code_size;
    size_t stack_size;
} execution_context_t;

// Test case definition
typedef struct {
    uint8_t* code;
    size_t code_size;
    
    // Expected register values (architecture-specific)
    uint64_t expected_regs[32];
    bool check_regs[32];
    
    // Expected memory contents
    struct {
        uint64_t addr;
        uint8_t* data;
        size_t size;
    } expected_memory[8];
    int memory_checks;
    
    // Execution parameters
    uint64_t timeout;
    uint64_t max_instructions;
    
    // Expected result
    bool should_succeed;
    uc_err expected_error;
} test_case_t;

// Architecture contexts
extern execution_context_t arch_x86_16;
extern execution_context_t arch_x86_32;
extern execution_context_t arch_x86_64;
extern execution_context_t arch_arm64;
extern execution_context_t arch_riscv;

// Main execution and verification functions
int execute_and_verify(execution_context_t* ctx, test_case_t* test);

// Setup functions
void setup_initial_state(uc_engine* uc, execution_context_t* ctx);
int verify_execution_results(uc_engine* uc, execution_context_t* ctx, test_case_t* test);

// Architecture-specific register verification
int verify_x86_registers(uc_engine* uc, execution_context_t* ctx, test_case_t* test);
int verify_arm64_registers(uc_engine* uc, test_case_t* test);
int verify_riscv_registers(uc_engine* uc, test_case_t* test);

// Memory verification
int verify_memory_contents(uc_engine* uc, test_case_t* test);

// Utility functions for test creation
test_case_t* create_test_case(uint8_t* code, size_t size);
void destroy_test_case(test_case_t* test);
void set_expected_register(test_case_t* test, int reg_index, uint64_t value);
void set_expected_memory(test_case_t* test, uint64_t addr, uint8_t* data, size_t size);

// Common test assertions
#define TEST_ASSERT_EXECUTION_SUCCESS(ctx, test) \
    TEST_ASSERT_EQUAL(0, execute_and_verify(ctx, test))

#define TEST_ASSERT_EXECUTION_FAILURE(ctx, test, expected_err) \
    do { \
        test->should_succeed = false; \
        test->expected_error = expected_err; \
        TEST_ASSERT_NOT_EQUAL(0, execute_and_verify(ctx, test)); \
    } while(0)

// Architecture-specific register constants
enum x86_64_registers {
    X86_64_RAX = 0, X86_64_RBX, X86_64_RCX, X86_64_RDX,
    X86_64_RSI, X86_64_RDI, X86_64_RSP, X86_64_RBP,
    X86_64_R8, X86_64_R9, X86_64_R10, X86_64_R11,
    X86_64_R12, X86_64_R13, X86_64_R14, X86_64_R15
};

enum x86_32_registers {
    X86_32_EAX = 0, X86_32_EBX, X86_32_ECX, X86_32_EDX,
    X86_32_ESI, X86_32_EDI, X86_32_ESP, X86_32_EBP
};

enum x86_16_registers {
    X86_16_AX = 0, X86_16_BX, X86_16_CX, X86_16_DX,
    X86_16_SI, X86_16_DI, X86_16_SP, X86_16_BP
};

enum arm64_registers {
    ARM64_X0 = 0, ARM64_X1, ARM64_X2, ARM64_X3,
    ARM64_X4, ARM64_X5, ARM64_X6, ARM64_X7,
    ARM64_X8, ARM64_X9, ARM64_X10, ARM64_X11,
    ARM64_X12, ARM64_X13, ARM64_X14, ARM64_X15,
    ARM64_X16, ARM64_X17, ARM64_X18, ARM64_X19,
    ARM64_X20, ARM64_X21, ARM64_X22, ARM64_X23,
    ARM64_X24, ARM64_X25, ARM64_X26, ARM64_X27,
    ARM64_X28, ARM64_X29, ARM64_X30, ARM64_SP
};

enum riscv_registers {
    RISCV_X0 = 0, RISCV_X1, RISCV_X2, RISCV_X3,
    RISCV_X4, RISCV_X5, RISCV_X6, RISCV_X7,
    RISCV_X8, RISCV_X9, RISCV_X10, RISCV_X11,
    RISCV_X12, RISCV_X13, RISCV_X14, RISCV_X15,
    RISCV_X16, RISCV_X17, RISCV_X18, RISCV_X19,
    RISCV_X20, RISCV_X21, RISCV_X22, RISCV_X23,
    RISCV_X24, RISCV_X25, RISCV_X26, RISCV_X27,
    RISCV_X28, RISCV_X29, RISCV_X30, RISCV_X31
};

#endif // UNICORN_TEST_FRAMEWORK_H
