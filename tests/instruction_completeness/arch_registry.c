#include "arch_registry.h"
#include "arch_x86_16.h"
#include "arch_x86_32.h"
#include "arch_x86_64.h"
#include "arch_arm64.h"
#include "arch_riscv.h"

// ========================================
// ARCHITECTURE REGISTRY
// ========================================

static const arch_instruction_set_t* all_architectures[] = {
    NULL,  // Will be populated by get_all_architectures()
    NULL,
    NULL,
    NULL,
    NULL
};

static bool architectures_initialized = false;

const arch_instruction_set_t** get_all_architectures(size_t* count) {
    if (!architectures_initialized) {
        all_architectures[0] = get_x86_16_instruction_set();
        all_architectures[1] = get_x86_32_instruction_set();
        all_architectures[2] = get_x86_64_instruction_set();
        all_architectures[3] = get_arm64_instruction_set();
        all_architectures[4] = get_riscv_instruction_set();
        architectures_initialized = true;
    }
    
    if (count) {
        *count = 5;
    }
    return all_architectures;
}

const arch_instruction_set_t* get_architecture_by_name(const char* arch_name) {
    size_t count;
    const arch_instruction_set_t** architectures = get_all_architectures(&count);
    
    for (size_t i = 0; i < count; i++) {
        if (strcmp(architectures[i]->arch_name, arch_name) == 0) {
            return architectures[i];
        }
    }
    
    return NULL;
}
