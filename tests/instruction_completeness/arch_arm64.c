#include "arch_arm64.h"

// ========================================
// ARM64 INSTRUCTION SET DEFINITIONS
// ========================================

static const instruction_def_t arm64_arithmetic[] = {
    {"add", "Arithmetic", 3, false},
    {"sub", "Arithmetic", 3, false},
    {"mul", "Arithmetic", 3, false},
    {"div", "Arithmetic", 3, false},
    {"udiv", "Arithmetic", 3, false},
    {"madd", "Arithmetic", 4, false},
    {"msub", "Arithmetic", 4, false},
    {"neg", "Arithmetic", 2, false},
    {"cmp", "Arithmetic", 2, false},
    {"cmn", "Arithmetic", 2, false},
    {"adc", "Arithmetic", 3, false},
    {"sbc", "Arithmetic", 3, false},
    {"abs", "Arithmetic", 2, false}
};

static const instruction_def_t arm64_logical[] = {
    {"and", "Logical", 3, false},
    {"orr", "Logical", 3, false},
    {"eor", "Logical", 3, false},
    {"orn", "Logical", 3, false},
    {"bic", "Logical", 3, false},
    {"tst", "Logical", 2, false},
    {"lsl", "Logical", 3, false},
    {"lsr", "Logical", 3, false},
    {"asr", "Logical", 3, false},
    {"ror", "Logical", 3, false},
    {"clz", "Logical", 2, false},
    {"rbit", "Logical", 2, false},
    {"rev", "Logical", 2, false}
};

static const instruction_def_t arm64_data_movement[] = {
    {"mov", "Data Movement", 2, false},
    {"mvn", "Data Movement", 2, false},
    {"ldr", "Data Movement", 2, false},
    {"str", "Data Movement", 2, false},
    {"ldp", "Data Movement", 3, false},
    {"stp", "Data Movement", 3, false},
    {"ldrb", "Data Movement", 2, false},
    {"strb", "Data Movement", 2, false},
    {"ldrh", "Data Movement", 2, false},
    {"strh", "Data Movement", 2, false},
    {"ldrsb", "Data Movement", 2, false},
    {"ldrsh", "Data Movement", 2, false},
    {"ldrsw", "Data Movement", 2, false}
};

static const instruction_def_t arm64_control_flow[] = {
    {"b", "Control Flow", 1, false},
    {"bl", "Control Flow", 1, false},
    {"br", "Control Flow", 1, false},
    {"blr", "Control Flow", 1, false},
    {"ret", "Control Flow", 0, false},
    {"beq", "Control Flow", 1, false},
    {"bne", "Control Flow", 1, false},
    {"blt", "Control Flow", 1, false},
    {"ble", "Control Flow", 1, false},
    {"bgt", "Control Flow", 1, false},
    {"bge", "Control Flow", 1, false},
    {"blo", "Control Flow", 1, false},
    {"bls", "Control Flow", 1, false},
    {"bhi", "Control Flow", 1, false},
    {"bhs", "Control Flow", 1, false},
    {"cbz", "Control Flow", 2, false},
    {"cbnz", "Control Flow", 2, false},
    {"tbz", "Control Flow", 3, false},
    {"tbnz", "Control Flow", 3, false}
};

static const instruction_category_t arm64_categories[] = {
    {"Arithmetic", arm64_arithmetic, sizeof(arm64_arithmetic)/sizeof(instruction_def_t)},
    {"Logical", arm64_logical, sizeof(arm64_logical)/sizeof(instruction_def_t)},
    {"Data Movement", arm64_data_movement, sizeof(arm64_data_movement)/sizeof(instruction_def_t)},
    {"Control Flow", arm64_control_flow, sizeof(arm64_control_flow)/sizeof(instruction_def_t)}
};

const arch_instruction_set_t* get_arm64_instruction_set(void) {
    static const arch_instruction_set_t arm64_set = {
        "arm64", 
        arm64_categories, 
        sizeof(arm64_categories)/sizeof(instruction_category_t)
    };
    return &arm64_set;
}
