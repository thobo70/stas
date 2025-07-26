#include "arch_x86_16.h"

// ========================================
// x86_16 INSTRUCTION SET DEFINITIONS
// ========================================

static const instruction_def_t x86_16_arithmetic[] = {
    {"add", "Arithmetic", 2, false},
    {"sub", "Arithmetic", 2, false},
    {"mul", "Arithmetic", 1, false},
    {"div", "Arithmetic", 1, false},
    {"inc", "Arithmetic", 1, false},
    {"dec", "Arithmetic", 1, false},
    {"neg", "Arithmetic", 1, false},
    {"cmp", "Arithmetic", 2, false},
    {"adc", "Arithmetic", 2, false},
    {"sbb", "Arithmetic", 2, false},
    {"imul", "Arithmetic", 1, false},
    {"idiv", "Arithmetic", 1, false}
};

static const instruction_def_t x86_16_logical[] = {
    {"and", "Logical", 2, false},
    {"or", "Logical", 2, false},
    {"xor", "Logical", 2, false},
    {"not", "Logical", 1, false},
    {"test", "Logical", 2, false},
    {"shl", "Logical", 2, false},
    {"shr", "Logical", 2, false},
    {"sal", "Logical", 2, false},
    {"sar", "Logical", 2, false},
    {"rol", "Logical", 2, false},
    {"ror", "Logical", 2, false},
    {"rcl", "Logical", 2, false},
    {"rcr", "Logical", 2, false}
};

static const instruction_def_t x86_16_data_movement[] = {
    {"mov", "Data Movement", 2, false},
    {"push", "Data Movement", 1, false},
    {"pop", "Data Movement", 1, false},
    {"xchg", "Data Movement", 2, false},
    {"lea", "Data Movement", 2, false},
    {"lds", "Data Movement", 2, false},
    {"les", "Data Movement", 2, false},
    {"lahf", "Data Movement", 0, false},
    {"sahf", "Data Movement", 0, false},
    {"pushf", "Data Movement", 0, false},
    {"popf", "Data Movement", 0, false}
};

static const instruction_def_t x86_16_control_flow[] = {
    {"jmp", "Control Flow", 1, false},
    {"call", "Control Flow", 1, false},
    {"ret", "Control Flow", 0, false},
    {"retf", "Control Flow", 0, false},
    {"je", "Control Flow", 1, false},
    {"jne", "Control Flow", 1, false},
    {"jz", "Control Flow", 1, false},
    {"jnz", "Control Flow", 1, false},
    {"jl", "Control Flow", 1, false},
    {"jle", "Control Flow", 1, false},
    {"jg", "Control Flow", 1, false},
    {"jge", "Control Flow", 1, false},
    {"ja", "Control Flow", 1, false},
    {"jae", "Control Flow", 1, false},
    {"jb", "Control Flow", 1, false},
    {"jbe", "Control Flow", 1, false},
    {"jc", "Control Flow", 1, false},
    {"jnc", "Control Flow", 1, false},
    {"jo", "Control Flow", 1, false},
    {"jno", "Control Flow", 1, false},
    {"js", "Control Flow", 1, false},
    {"jns", "Control Flow", 1, false},
    {"loop", "Control Flow", 1, false},
    {"loope", "Control Flow", 1, false},
    {"loopne", "Control Flow", 1, false}
};

static const instruction_def_t x86_16_system[] = {
    {"int", "System", 1, false},
    {"iret", "System", 0, false},
    {"cli", "System", 0, false},
    {"sti", "System", 0, false},
    {"clc", "System", 0, false},
    {"stc", "System", 0, false},
    {"cld", "System", 0, false},
    {"std", "System", 0, false},
    {"nop", "System", 0, false},
    {"hlt", "System", 0, false},
    {"wait", "System", 0, false}
};

static const instruction_def_t x86_16_string[] = {
    {"movs", "String", 0, false},
    {"movsb", "String", 0, false},
    {"movsw", "String", 0, false},
    {"cmps", "String", 0, false},
    {"cmpsb", "String", 0, false},
    {"cmpsw", "String", 0, false},
    {"scas", "String", 0, false},
    {"scasb", "String", 0, false},
    {"scasw", "String", 0, false},
    {"lods", "String", 0, false},
    {"lodsb", "String", 0, false},
    {"lodsw", "String", 0, false},
    {"stos", "String", 0, false},
    {"stosb", "String", 0, false},
    {"stosw", "String", 0, false},
    {"rep", "String", 0, false},
    {"repe", "String", 0, false},
    {"repne", "String", 0, false}
};

static const instruction_category_t x86_16_categories[] = {
    {"Arithmetic", x86_16_arithmetic, sizeof(x86_16_arithmetic)/sizeof(instruction_def_t)},
    {"Logical", x86_16_logical, sizeof(x86_16_logical)/sizeof(instruction_def_t)},
    {"Data Movement", x86_16_data_movement, sizeof(x86_16_data_movement)/sizeof(instruction_def_t)},
    {"Control Flow", x86_16_control_flow, sizeof(x86_16_control_flow)/sizeof(instruction_def_t)},
    {"System", x86_16_system, sizeof(x86_16_system)/sizeof(instruction_def_t)},
    {"String", x86_16_string, sizeof(x86_16_string)/sizeof(instruction_def_t)}
};

const arch_instruction_set_t* get_x86_16_instruction_set(void) {
    static const arch_instruction_set_t x86_16_set = {
        "x86_16", 
        x86_16_categories, 
        sizeof(x86_16_categories)/sizeof(instruction_category_t)
    };
    return &x86_16_set;
}
