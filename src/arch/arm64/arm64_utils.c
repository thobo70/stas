/*
 * ARM64 Instruction Category Detection and Utilities
 * Phase 6.2: ARM64 Architecture Implementation
 */

#define _GNU_SOURCE  // Enable GNU extensions for strcasecmp
#include "arm64.h"
#include <string.h>
#include <ctype.h>
#include <stdlib.h>  // For strtol

//=============================================================================
// ARM64 Instruction Category Detection
//=============================================================================

bool is_arm64_data_processing_instruction(const char *mnemonic) {
    if (!mnemonic) return false;
    
    // Data processing instruction patterns
    const char *data_processing[] = {
        "add", "sub", "and", "orr", "eor", "mov", "mvn",
        "adc", "sbc", "bic", "orn", "lsl", "lsr", "asr",
        "ror", "mul", "div", "udiv", "sdiv", "madd", "msub",
        "smull", "umull", "smulh", "umulh",
        NULL
    };
    
    for (int i = 0; data_processing[i] != NULL; i++) {
        if (strcmp(mnemonic, data_processing[i]) == 0) {
            return true;
        }
    }
    
    return false;
}

bool is_arm64_load_store_instruction(const char *mnemonic) {
    if (!mnemonic) return false;
    
    // Load/store instruction patterns
    const char *load_store[] = {
        "ldr", "str", "ldrb", "strb", "ldrh", "strh",
        "ldp", "stp", "ldur", "stur", "ldar", "stlr",
        "ldxr", "stxr", "ldaxr", "stlxr",
        NULL
    };
    
    for (int i = 0; load_store[i] != NULL; i++) {
        if (strcmp(mnemonic, load_store[i]) == 0) {
            return true;
        }
    }
    
    return false;
}

bool is_arm64_branch_instruction(const char *mnemonic) {
    if (!mnemonic) return false;
    
    // Branch instruction patterns
    const char *branch[] = {
        "b", "bl", "br", "blr", "ret", "eret",
        "cbz", "cbnz", "tbz", "tbnz",
        NULL
    };
    
    for (int i = 0; branch[i] != NULL; i++) {
        if (strcmp(mnemonic, branch[i]) == 0) {
            return true;
        }
    }
    
    // Conditional branches (b.eq, b.ne, etc.)
    if (strncmp(mnemonic, "b.", 2) == 0) {
        return true;
    }
    
    return false;
}

bool is_arm64_simd_fp_instruction(const char *mnemonic) {
    if (!mnemonic) return false;
    
    // SIMD and floating-point instruction patterns
    const char *simd_fp[] = {
        "fadd", "fsub", "fmul", "fdiv", "fabs", "fneg",
        "fmov", "fcmp", "fcvt", "scvtf", "ucvtf", "fcvtzs", "fcvtzu",
        "vadd", "vsub", "vmul", "vdiv", "vabs", "vneg",
        "vld1", "vst1", "vld2", "vst2", "vld3", "vst3", "vld4", "vst4",
        NULL
    };
    
    for (int i = 0; simd_fp[i] != NULL; i++) {
        if (strcmp(mnemonic, simd_fp[i]) == 0) {
            return true;
        }
    }
    
    return false;
}

bool is_arm64_system_instruction(const char *mnemonic) {
    if (!mnemonic) return false;
    
    // System instruction patterns
    const char *system[] = {
        "nop", "svc", "hvc", "smc", "brk", "hlt",
        "isb", "dsb", "dmb", "mrs", "msr",
        "sys", "sysl", "ic", "dc", "at", "tlbi",
        NULL
    };
    
    for (int i = 0; system[i] != NULL; i++) {
        if (strcmp(mnemonic, system[i]) == 0) {
            return true;
        }
    }
    
    return false;
}

//=============================================================================
// ARM64 Register Type Checking
//=============================================================================

bool is_arm64_x_register(const char *reg_name) {
    if (!reg_name) return false;
    
    // Remove % prefix if present
    const char *name = (reg_name[0] == '%') ? reg_name + 1 : reg_name;
    
    // Check if it's an X register (x0-x31, xzr)
    if (name[0] == 'x' || name[0] == 'X') {
        // Handle xzr specially
        if (strcasecmp(name, "xzr") == 0) return true;
        
        // Check x0-x31
        if (strlen(name) >= 2) {
            char *endptr;
            long reg_num = strtol(name + 1, &endptr, 10);
            return (*endptr == '\0' && reg_num >= 0 && reg_num <= 30);
        }
    }
    
    return false;
}

bool is_arm64_w_register(const char *reg_name) {
    if (!reg_name) return false;
    
    // Remove % prefix if present
    const char *name = (reg_name[0] == '%') ? reg_name + 1 : reg_name;
    
    // Check if it's a W register (w0-w31, wzr)
    if (name[0] == 'w' || name[0] == 'W') {
        // Handle wzr specially
        if (strcasecmp(name, "wzr") == 0) return true;
        
        // Check w0-w31
        if (strlen(name) >= 2) {
            char *endptr;
            long reg_num = strtol(name + 1, &endptr, 10);
            return (*endptr == '\0' && reg_num >= 0 && reg_num <= 30);
        }
    }
    
    return false;
}

bool is_arm64_v_register(const char *reg_name) {
    if (!reg_name) return false;
    
    // Remove % prefix if present
    const char *name = (reg_name[0] == '%') ? reg_name + 1 : reg_name;
    
    // Check if it's a V register (v0-v31)
    if (name[0] == 'v' || name[0] == 'V') {
        if (strlen(name) >= 2) {
            char *endptr;
            long reg_num = strtol(name + 1, &endptr, 10);
            return (*endptr == '\0' && reg_num >= 0 && reg_num <= 31);
        }
    }
    
    return false;
}

bool is_arm64_s_register(const char *reg_name) {
    if (!reg_name) return false;
    
    // Remove % prefix if present
    const char *name = (reg_name[0] == '%') ? reg_name + 1 : reg_name;
    
    // Check if it's an S register (s0-s31) - 32-bit float view
    if (name[0] == 's' || name[0] == 'S') {
        if (strlen(name) >= 2) {
            char *endptr;
            long reg_num = strtol(name + 1, &endptr, 10);
            return (*endptr == '\0' && reg_num >= 0 && reg_num <= 31);
        }
    }
    
    return false;
}

bool is_arm64_d_register(const char *reg_name) {
    if (!reg_name) return false;
    
    // Remove % prefix if present
    const char *name = (reg_name[0] == '%') ? reg_name + 1 : reg_name;
    
    // Check if it's a D register (d0-d31) - 64-bit double view
    if (name[0] == 'd' || name[0] == 'D') {
        if (strlen(name) >= 2) {
            char *endptr;
            long reg_num = strtol(name + 1, &endptr, 10);
            return (*endptr == '\0' && reg_num >= 0 && reg_num <= 31);
        }
    }
    
    return false;
}

bool is_arm64_q_register(const char *reg_name) {
    if (!reg_name) return false;
    
    // Remove % prefix if present
    const char *name = (reg_name[0] == '%') ? reg_name + 1 : reg_name;
    
    // Check if it's a Q register (q0-q31) - 128-bit quad view
    if (name[0] == 'q' || name[0] == 'Q') {
        if (strlen(name) >= 2) {
            char *endptr;
            long reg_num = strtol(name + 1, &endptr, 10);
            return (*endptr == '\0' && reg_num >= 0 && reg_num <= 31);
        }
    }
    
    return false;
}

bool is_arm64_stack_pointer(const char *reg_name) {
    if (!reg_name) return false;
    
    // Remove % prefix if present
    const char *name = (reg_name[0] == '%') ? reg_name + 1 : reg_name;
    
    return (strcasecmp(name, "sp") == 0);
}

bool is_arm64_zero_register(const char *reg_name) {
    if (!reg_name) return false;
    
    // Remove % prefix if present
    const char *name = (reg_name[0] == '%') ? reg_name + 1 : reg_name;
    
    return (strcasecmp(name, "xzr") == 0 || strcasecmp(name, "wzr") == 0);
}

//=============================================================================
// ARM64 Instruction Family Detection
//=============================================================================

bool is_arm64_arithmetic_instruction(const char *mnemonic) {
    if (!mnemonic) return false;
    
    const char *arithmetic[] = {
        "add", "sub", "adc", "sbc", "mul", "div", "udiv", "sdiv",
        "madd", "msub", "smull", "umull", "smulh", "umulh",
        NULL
    };
    
    for (int i = 0; arithmetic[i] != NULL; i++) {
        if (strcmp(mnemonic, arithmetic[i]) == 0) {
            return true;
        }
    }
    
    return false;
}

bool is_arm64_logical_instruction(const char *mnemonic) {
    if (!mnemonic) return false;
    
    const char *logical[] = {
        "and", "orr", "eor", "bic", "orn", "mvn",
        NULL
    };
    
    for (int i = 0; logical[i] != NULL; i++) {
        if (strcmp(mnemonic, logical[i]) == 0) {
            return true;
        }
    }
    
    return false;
}

bool is_arm64_shift_instruction(const char *mnemonic) {
    if (!mnemonic) return false;
    
    const char *shift[] = {
        "lsl", "lsr", "asr", "ror",
        NULL
    };
    
    for (int i = 0; shift[i] != NULL; i++) {
        if (strcmp(mnemonic, shift[i]) == 0) {
            return true;
        }
    }
    
    return false;
}

bool is_arm64_move_instruction(const char *mnemonic) {
    if (!mnemonic) return false;
    
    const char *move[] = {
        "mov", "movk", "movz", "movn",
        NULL
    };
    
    for (int i = 0; move[i] != NULL; i++) {
        if (strcmp(mnemonic, move[i]) == 0) {
            return true;
        }
    }
    
    return false;
}

bool is_arm64_load_instruction(const char *mnemonic) {
    if (!mnemonic) return false;
    
    const char *load[] = {
        "ldr", "ldrb", "ldrh", "ldp", "ldur", "ldar", "ldxr", "ldaxr",
        NULL
    };
    
    for (int i = 0; load[i] != NULL; i++) {
        if (strcmp(mnemonic, load[i]) == 0) {
            return true;
        }
    }
    
    return false;
}

bool is_arm64_store_instruction(const char *mnemonic) {
    if (!mnemonic) return false;
    
    const char *store[] = {
        "str", "strb", "strh", "stp", "stur", "stlr", "stxr", "stlxr",
        NULL
    };
    
    for (int i = 0; store[i] != NULL; i++) {
        if (strcmp(mnemonic, store[i]) == 0) {
            return true;
        }
    }
    
    return false;
}

bool is_arm64_load_pair_instruction(const char *mnemonic) {
    if (!mnemonic) return false;
    return strcmp(mnemonic, "ldp") == 0;
}

bool is_arm64_store_pair_instruction(const char *mnemonic) {
    if (!mnemonic) return false;
    return strcmp(mnemonic, "stp") == 0;
}

bool is_arm64_unconditional_branch(const char *mnemonic) {
    if (!mnemonic) return false;
    
    const char *unconditional[] = {
        "b", "br", "bl", "blr", "ret", "eret",
        NULL
    };
    
    for (int i = 0; unconditional[i] != NULL; i++) {
        if (strcmp(mnemonic, unconditional[i]) == 0) {
            return true;
        }
    }
    
    return false;
}

bool is_arm64_conditional_branch(const char *mnemonic) {
    if (!mnemonic) return false;
    
    // Conditional branches start with "b."
    return (strncmp(mnemonic, "b.", 2) == 0);
}

bool is_arm64_compare_branch(const char *mnemonic) {
    if (!mnemonic) return false;
    
    const char *compare_branch[] = {
        "cbz", "cbnz", "tbz", "tbnz",
        NULL
    };
    
    for (int i = 0; compare_branch[i] != NULL; i++) {
        if (strcmp(mnemonic, compare_branch[i]) == 0) {
            return true;
        }
    }
    
    return false;
}
