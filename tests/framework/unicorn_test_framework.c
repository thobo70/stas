#include "unicorn_test_framework.h"
#include <stdlib.h>
#include <string.h>
#include <stdio.h>

// Architecture context definitions
execution_context_t arch_x86_16 = {
    .arch = UC_ARCH_X86,
    .mode = UC_MODE_16,
    .name = "x86_16",
    .code_addr = 0x1000,
    .stack_addr = 0x7000,
    .code_size = 4096,
    .stack_size = 4096
};

execution_context_t arch_x86_32 = {
    .arch = UC_ARCH_X86,
    .mode = UC_MODE_32,
    .name = "x86_32",
    .code_addr = 0x1000000,
    .stack_addr = 0x2000000,
    .code_size = 64 * 1024,
    .stack_size = 64 * 1024
};

execution_context_t arch_x86_64 = {
    .arch = UC_ARCH_X86,
    .mode = UC_MODE_64,
    .name = "x86_64",
    .code_addr = 0x1000000,
    .stack_addr = 0x2000000,
    .code_size = 64 * 1024,
    .stack_size = 64 * 1024
};

execution_context_t arch_arm64 = {
    .arch = UC_ARCH_ARM64,
    .mode = UC_MODE_ARM,
    .name = "arm64",
    .code_addr = 0x1000000,
    .stack_addr = 0x2000000,
    .code_size = 64 * 1024,
    .stack_size = 64 * 1024
};

execution_context_t arch_riscv = {
    .arch = UC_ARCH_RISCV,
    .mode = UC_MODE_RISCV64,
    .name = "riscv",
    .code_addr = 0x1000000,
    .stack_addr = 0x2000000,
    .code_size = 64 * 1024,
    .stack_size = 64 * 1024
};

int execute_and_verify(execution_context_t* ctx, test_case_t* test) {
    uc_engine* uc;
    uc_err err;
    
    // Initialize engine
    err = uc_open(ctx->arch, ctx->mode, &uc);
    if (err != UC_ERR_OK) {
        printf("Failed to initialize Unicorn for %s: %s\n", ctx->name, uc_strerror(err));
        return -1;
    }
    
    // Map memory regions
    err = uc_mem_map(uc, ctx->code_addr, ctx->code_size, UC_PROT_ALL);
    if (err != UC_ERR_OK) {
        printf("Failed to map code memory: %s\n", uc_strerror(err));
        uc_close(uc);
        return -1;
    }
    
    err = uc_mem_map(uc, ctx->stack_addr, ctx->stack_size, UC_PROT_READ | UC_PROT_WRITE);
    if (err != UC_ERR_OK) {
        printf("Failed to map stack memory: %s\n", uc_strerror(err));
        uc_close(uc);
        return -1;
    }
    
    // Write code to memory
    err = uc_mem_write(uc, ctx->code_addr, test->code, test->code_size);
    if (err != UC_ERR_OK) {
        printf("Failed to write code: %s\n", uc_strerror(err));
        uc_close(uc);
        return -1;
    }
    
    // Set up initial state
    setup_initial_state(uc, ctx);
    
    // Execute code
    uint64_t timeout = test->timeout ? test->timeout : 1000000; // 1 second default
    uint64_t count = test->max_instructions ? test->max_instructions : 1000; // 1000 instructions default
    
    err = uc_emu_start(uc, ctx->code_addr, ctx->code_addr + test->code_size, timeout, count);
    
    // Check execution result
    if (test->should_succeed) {
        if (err != UC_ERR_OK) {
            printf("Execution failed unexpectedly: %s\n", uc_strerror(err));
            uc_close(uc);
            return -1;
        }
    } else {
        if (err == UC_ERR_OK) {
            printf("Execution succeeded when it should have failed\n");
            uc_close(uc);
            return -1;
        }
        if (test->expected_error != UC_ERR_OK && err != test->expected_error) {
            printf("Got error %s, expected %s\n", uc_strerror(err), uc_strerror(test->expected_error));
            uc_close(uc);
            return -1;
        }
    }
    
    // Verify results if execution succeeded
    int result = 0;
    if (test->should_succeed && err == UC_ERR_OK) {
        result = verify_execution_results(uc, ctx, test);
    }
    
    uc_close(uc);
    return result;
}

void setup_initial_state(uc_engine* uc, execution_context_t* ctx) {
    switch (ctx->arch) {
        case UC_ARCH_X86:
            if (ctx->mode == UC_MODE_64) {
                uint64_t stack_ptr = ctx->stack_addr + ctx->stack_size - 8; 
                uc_reg_write(uc, UC_X86_REG_RSP, &stack_ptr);
                // Clear general purpose registers
                uint64_t zero = 0;
                uc_reg_write(uc, UC_X86_REG_RAX, &zero);
                uc_reg_write(uc, UC_X86_REG_RBX, &zero);
                uc_reg_write(uc, UC_X86_REG_RCX, &zero);
                uc_reg_write(uc, UC_X86_REG_RDX, &zero);
            } else if (ctx->mode == UC_MODE_32) {
                uint32_t esp = (uint32_t)(ctx->stack_addr + ctx->stack_size - 4);
                uc_reg_write(uc, UC_X86_REG_ESP, &esp);
                // Clear general purpose registers
                uint32_t zero = 0;
                uc_reg_write(uc, UC_X86_REG_EAX, &zero);
                uc_reg_write(uc, UC_X86_REG_EBX, &zero);
                uc_reg_write(uc, UC_X86_REG_ECX, &zero);
                uc_reg_write(uc, UC_X86_REG_EDX, &zero);
            } else { // 16-bit mode
                uint16_t sp = (uint16_t)((ctx->stack_addr + ctx->stack_size - 2) & 0xFFFF);
                uc_reg_write(uc, UC_X86_REG_SP, &sp);
                // Clear general purpose registers
                uint16_t zero = 0;
                uc_reg_write(uc, UC_X86_REG_AX, &zero);
                uc_reg_write(uc, UC_X86_REG_BX, &zero);
                uc_reg_write(uc, UC_X86_REG_CX, &zero);
                uc_reg_write(uc, UC_X86_REG_DX, &zero);
            }
            break;
            
        case UC_ARCH_ARM64: {
            uint64_t stack_ptr = ctx->stack_addr + ctx->stack_size - 8;
            uc_reg_write(uc, UC_ARM64_REG_SP, &stack_ptr);
            // Clear some general purpose registers
            uint64_t zero_val = 0;
            for (int i = UC_ARM64_REG_X0; i <= UC_ARM64_REG_X7; i++) {
                uc_reg_write(uc, i, &zero_val);
            }
            break;
        }
            
        case UC_ARCH_RISCV: {
            uint64_t stack_ptr = ctx->stack_addr + ctx->stack_size - 8;
            uc_reg_write(uc, UC_RISCV_REG_SP, &stack_ptr);
            // Clear some general purpose registers
            uint64_t zero_riscv = 0;
            for (int i = UC_RISCV_REG_X1; i <= UC_RISCV_REG_X7; i++) {
                uc_reg_write(uc, i, &zero_riscv);
            }
            break;
        }
            
        default:
            // Unsupported architectures - no setup needed
            break;
    }
}

int verify_execution_results(uc_engine* uc, execution_context_t* ctx, test_case_t* test) {
    int result = 0;
    
    // Verify registers
    switch (ctx->arch) {
        case UC_ARCH_X86:
            result = verify_x86_registers(uc, ctx, test);
            break;
        case UC_ARCH_ARM64:
            result = verify_arm64_registers(uc, test);
            break;
        case UC_ARCH_RISCV:
            result = verify_riscv_registers(uc, test);
            break;
        default:
            // Unsupported architectures - skip register verification
            result = 0;
            break;
    }
    
    if (result != 0) return result;
    
    // Verify memory
    return verify_memory_contents(uc, test);
}

int verify_x86_registers(uc_engine* uc, execution_context_t* ctx, test_case_t* test) {
    for (int i = 0; i < 16; i++) {
        if (!test->check_regs[i]) continue;
        
        uint64_t actual_value = 0;
        uc_err err;
        
        // Map test register index to Unicorn register constant based on mode
        int uc_reg = -1;
        
        if (ctx->mode == UC_MODE_64) {
            // 64-bit mode
            switch (i) {
                case X86_64_RAX: uc_reg = UC_X86_REG_RAX; break;
                case X86_64_RBX: uc_reg = UC_X86_REG_RBX; break;
                case X86_64_RCX: uc_reg = UC_X86_REG_RCX; break;
                case X86_64_RDX: uc_reg = UC_X86_REG_RDX; break;
                case X86_64_RSI: uc_reg = UC_X86_REG_RSI; break;
                case X86_64_RDI: uc_reg = UC_X86_REG_RDI; break;
                case X86_64_RSP: uc_reg = UC_X86_REG_RSP; break;
                case X86_64_RBP: uc_reg = UC_X86_REG_RBP; break;
                case X86_64_R8:  uc_reg = UC_X86_REG_R8;  break;
                case X86_64_R9:  uc_reg = UC_X86_REG_R9;  break;
                case X86_64_R10: uc_reg = UC_X86_REG_R10; break;
                case X86_64_R11: uc_reg = UC_X86_REG_R11; break;
                case X86_64_R12: uc_reg = UC_X86_REG_R12; break;
                case X86_64_R13: uc_reg = UC_X86_REG_R13; break;
                case X86_64_R14: uc_reg = UC_X86_REG_R14; break;
                case X86_64_R15: uc_reg = UC_X86_REG_R15; break;
                default: continue;
            }
        } else if (ctx->mode == UC_MODE_32) {
            // 32-bit mode
            switch (i) {
                case X86_32_EAX: uc_reg = UC_X86_REG_EAX; break;
                case X86_32_EBX: uc_reg = UC_X86_REG_EBX; break;
                case X86_32_ECX: uc_reg = UC_X86_REG_ECX; break;
                case X86_32_EDX: uc_reg = UC_X86_REG_EDX; break;
                case X86_32_ESI: uc_reg = UC_X86_REG_ESI; break;
                case X86_32_EDI: uc_reg = UC_X86_REG_EDI; break;
                case X86_32_ESP: uc_reg = UC_X86_REG_ESP; break;
                case X86_32_EBP: uc_reg = UC_X86_REG_EBP; break;
                default: continue;
            }
        } else {
            // 16-bit mode
            switch (i) {
                case X86_16_AX: uc_reg = UC_X86_REG_AX; break;
                case X86_16_BX: uc_reg = UC_X86_REG_BX; break;
                case X86_16_CX: uc_reg = UC_X86_REG_CX; break;
                case X86_16_DX: uc_reg = UC_X86_REG_DX; break;
                case X86_16_SI: uc_reg = UC_X86_REG_SI; break;
                case X86_16_DI: uc_reg = UC_X86_REG_DI; break;
                case X86_16_SP: uc_reg = UC_X86_REG_SP; break;
                case X86_16_BP: uc_reg = UC_X86_REG_BP; break;
                default: continue;
            }
        }
        
        if (uc_reg == -1) continue;
        
        err = uc_reg_read(uc, uc_reg, &actual_value);
        if (err != UC_ERR_OK) {
            printf("Failed to read register %d: %s\n", i, uc_strerror(err));
            return -1;
        }
        
        // For 16-bit and 32-bit modes, mask the value appropriately
        if (ctx->mode == UC_MODE_16) {
            actual_value &= 0xFFFF;
        } else if (ctx->mode == UC_MODE_32) {
            actual_value &= 0xFFFFFFFF;
        }
        
        if (actual_value != test->expected_regs[i]) {
            printf("Register %d mismatch: expected 0x%lx, got 0x%lx\n", 
                   i, test->expected_regs[i], actual_value);
            return -1;
        }
    }
    
    return 0;
}

int verify_arm64_registers(uc_engine* uc, test_case_t* test) {
    for (int i = 0; i < 32; i++) {
        if (!test->check_regs[i]) continue;
        
        uint64_t actual_value;
        uc_err err;
        
        int uc_reg = UC_ARM64_REG_X0 + i;
        if (i == 31) uc_reg = UC_ARM64_REG_SP;
        
        err = uc_reg_read(uc, uc_reg, &actual_value);
        if (err != UC_ERR_OK) {
            printf("Failed to read ARM64 register %d: %s\n", i, uc_strerror(err));
            return -1;
        }
        
        if (actual_value != test->expected_regs[i]) {
            printf("ARM64 register %d mismatch: expected 0x%lx, got 0x%lx\n", 
                   i, test->expected_regs[i], actual_value);
            return -1;
        }
    }
    
    return 0;
}

int verify_riscv_registers(uc_engine* uc, test_case_t* test) {
    for (int i = 0; i < 32; i++) {
        if (!test->check_regs[i]) continue;
        
        uint64_t actual_value;
        uc_err err;
        
        int uc_reg = UC_RISCV_REG_X0 + i;
        
        err = uc_reg_read(uc, uc_reg, &actual_value);
        if (err != UC_ERR_OK) {
            printf("Failed to read RISC-V register %d: %s\n", i, uc_strerror(err));
            return -1;
        }
        
        if (actual_value != test->expected_regs[i]) {
            printf("RISC-V register %d mismatch: expected 0x%lx, got 0x%lx\n", 
                   i, test->expected_regs[i], actual_value);
            return -1;
        }
    }
    
    return 0;
}

int verify_memory_contents(uc_engine* uc, test_case_t* test) {
    for (int i = 0; i < test->memory_checks; i++) {
        uint8_t* actual_data = malloc(test->expected_memory[i].size);
        if (!actual_data) {
            printf("Failed to allocate memory for verification\n");
            return -1;
        }
        
        uc_err err = uc_mem_read(uc, test->expected_memory[i].addr, 
                                actual_data, test->expected_memory[i].size);
        if (err != UC_ERR_OK) {
            printf("Failed to read memory at 0x%lx: %s\n", 
                   test->expected_memory[i].addr, uc_strerror(err));
            free(actual_data);
            return -1;
        }
        
        if (memcmp(actual_data, test->expected_memory[i].data, test->expected_memory[i].size) != 0) {
            printf("Memory mismatch at 0x%lx\n", test->expected_memory[i].addr);
            printf("Expected: ");
            for (size_t j = 0; j < test->expected_memory[i].size; j++) {
                printf("%02X ", test->expected_memory[i].data[j]);
            }
            printf("\nActual:   ");
            for (size_t j = 0; j < test->expected_memory[i].size; j++) {
                printf("%02X ", actual_data[j]);
            }
            printf("\n");
            free(actual_data);
            return -1;
        }
        
        free(actual_data);
    }
    
    return 0;
}

test_case_t* create_test_case(uint8_t* code, size_t size) {
    test_case_t* test = calloc(1, sizeof(test_case_t));
    if (!test) return NULL;
    
    test->code = malloc(size);
    if (!test->code) {
        free(test);
        return NULL;
    }
    
    memcpy(test->code, code, size);
    test->code_size = size;
    test->should_succeed = true;
    test->expected_error = UC_ERR_OK;
    
    return test;
}

void destroy_test_case(test_case_t* test) {
    if (!test) return;
    
    if (test->code) {
        free(test->code);
    }
    
    for (int i = 0; i < test->memory_checks; i++) {
        if (test->expected_memory[i].data) {
            free(test->expected_memory[i].data);
        }
    }
    
    free(test);
}

void set_expected_register(test_case_t* test, int reg_index, uint64_t value) {
    if (!test || reg_index < 0 || reg_index >= 32) return;
    
    test->expected_regs[reg_index] = value;
    test->check_regs[reg_index] = true;
}

void set_expected_memory(test_case_t* test, uint64_t addr, uint8_t* data, size_t size) {
    if (!test || test->memory_checks >= 8) return;
    
    int index = test->memory_checks++;
    test->expected_memory[index].addr = addr;
    test->expected_memory[index].size = size;
    test->expected_memory[index].data = malloc(size);
    
    if (test->expected_memory[index].data) {
        memcpy(test->expected_memory[index].data, data, size);
    }
}
