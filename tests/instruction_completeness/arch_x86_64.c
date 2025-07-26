#include "arch_x86_64.h"

// ========================================
// x86_64 INSTRUCTION SET DEFINITIONS
// ========================================

static const instruction_def_t x86_64_arithmetic[] = {
    {"add", "Arithmetic", 2, false},
    {"addq", "Arithmetic", 2, false},
    {"sub", "Arithmetic", 2, false},
    {"subq", "Arithmetic", 2, false},
    {"mul", "Arithmetic", 1, false},
    {"div", "Arithmetic", 1, false},
    {"inc", "Arithmetic", 1, false},
    {"dec", "Arithmetic", 1, false},
    {"neg", "Arithmetic", 1, false},
    {"cmp", "Arithmetic", 2, false},
    {"cmpq", "Arithmetic", 2, false},
    {"adc", "Arithmetic", 2, false},
    {"sbb", "Arithmetic", 2, false},
    {"imul", "Arithmetic", 2, false},
    {"idiv", "Arithmetic", 1, false},
    {"bsf", "Arithmetic", 2, true},
    {"bsr", "Arithmetic", 2, true},
    {"bt", "Arithmetic", 2, true},
    {"btc", "Arithmetic", 2, true},
    {"btr", "Arithmetic", 2, true},
    {"bts", "Arithmetic", 2, true},
    {"popcnt", "Arithmetic", 2, true},
    {"lzcnt", "Arithmetic", 2, true}
};

static const instruction_def_t x86_64_data_movement[] = {
    {"mov", "Data Movement", 2, false},
    {"movq", "Data Movement", 2, false},
    {"push", "Data Movement", 1, false},
    {"pushq", "Data Movement", 1, false},
    {"pop", "Data Movement", 1, false},
    {"popq", "Data Movement", 1, false},
    {"xchg", "Data Movement", 2, false},
    {"lea", "Data Movement", 2, false},
    {"leaq", "Data Movement", 2, false},
    {"movzx", "Data Movement", 2, true},
    {"movsx", "Data Movement", 2, true},
    {"movsxd", "Data Movement", 2, false},
    {"bswap", "Data Movement", 1, true},
    {"xadd", "Data Movement", 2, true},
    {"cmpxchg", "Data Movement", 2, true},
    {"cmpxchg16b", "Data Movement", 1, true}
};

static const instruction_def_t x86_64_system[] = {
    {"syscall", "System", 0, false},
    {"sysret", "System", 0, false},
    {"int", "System", 1, false},
    {"iretq", "System", 0, false},
    {"cli", "System", 0, false},
    {"sti", "System", 0, false},
    {"clc", "System", 0, false},
    {"stc", "System", 0, false},
    {"cld", "System", 0, false},
    {"std", "System", 0, false},
    {"nop", "System", 0, false},
    {"hlt", "System", 0, false},
    {"cpuid", "System", 0, true},
    {"rdtsc", "System", 0, true},
    {"rdtscp", "System", 0, true},
    {"wrmsr", "System", 0, true},
    {"rdmsr", "System", 0, true},
    {"swapgs", "System", 0, true}
};

static const instruction_category_t x86_64_categories[] = {
    {"Arithmetic", x86_64_arithmetic, sizeof(x86_64_arithmetic)/sizeof(instruction_def_t)},
    {"Data Movement", x86_64_data_movement, sizeof(x86_64_data_movement)/sizeof(instruction_def_t)},
    {"System", x86_64_system, sizeof(x86_64_system)/sizeof(instruction_def_t)}
};

const arch_instruction_set_t* get_x86_64_instruction_set(void) {
    static const arch_instruction_set_t x86_64_set = {
        "x86_64", 
        x86_64_categories, 
        sizeof(x86_64_categories)/sizeof(instruction_category_t)
    };
    return &x86_64_set;
}
