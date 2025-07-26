#include "arch_riscv.h"

// ========================================
// RISC-V INSTRUCTION SET DEFINITIONS
// ========================================

static const instruction_def_t riscv_arithmetic[] = {
    {"add", "Arithmetic", 3, false},
    {"sub", "Arithmetic", 3, false},
    {"addi", "Arithmetic", 3, false},
    {"mul", "Arithmetic", 3, true},
    {"div", "Arithmetic", 3, true},
    {"rem", "Arithmetic", 3, true},
    {"neg", "Arithmetic", 2, false},
    {"lui", "Arithmetic", 2, false},
    {"auipc", "Arithmetic", 2, false}
};

static const instruction_def_t riscv_logical[] = {
    {"and", "Logical", 3, false},
    {"or", "Logical", 3, false},
    {"xor", "Logical", 3, false},
    {"andi", "Logical", 3, false},
    {"ori", "Logical", 3, false},
    {"xori", "Logical", 3, false},
    {"sll", "Logical", 3, false},
    {"srl", "Logical", 3, false},
    {"sra", "Logical", 3, false},
    {"slli", "Logical", 3, false},
    {"srli", "Logical", 3, false},
    {"srai", "Logical", 3, false}
};

static const instruction_def_t riscv_data_movement[] = {
    {"mv", "Data Movement", 2, false},
    {"li", "Data Movement", 2, false},
    {"lw", "Data Movement", 2, false},
    {"sw", "Data Movement", 2, false},
    {"lb", "Data Movement", 2, false},
    {"sb", "Data Movement", 2, false},
    {"lh", "Data Movement", 2, false},
    {"sh", "Data Movement", 2, false},
    {"lbu", "Data Movement", 2, false},
    {"lhu", "Data Movement", 2, false}
};

static const instruction_def_t riscv_control_flow[] = {
    {"jal", "Control Flow", 2, false},
    {"jalr", "Control Flow", 3, false},
    {"j", "Control Flow", 1, false},
    {"jr", "Control Flow", 1, false},
    {"ret", "Control Flow", 0, false},
    {"beq", "Control Flow", 3, false},
    {"bne", "Control Flow", 3, false},
    {"blt", "Control Flow", 3, false},
    {"ble", "Control Flow", 3, false},
    {"bgt", "Control Flow", 3, false},
    {"bge", "Control Flow", 3, false},
    {"bltu", "Control Flow", 3, false},
    {"bgeu", "Control Flow", 3, false}
};

static const instruction_def_t riscv_system[] = {
    {"ecall", "System", 0, false},
    {"ebreak", "System", 0, false},
    {"fence", "System", 0, false},
    {"fence.i", "System", 0, false},
    {"csrrw", "System", 3, true},
    {"csrrs", "System", 3, true},
    {"csrrc", "System", 3, true}
};

static const instruction_category_t riscv_categories[] = {
    {"Arithmetic", riscv_arithmetic, sizeof(riscv_arithmetic)/sizeof(instruction_def_t)},
    {"Logical", riscv_logical, sizeof(riscv_logical)/sizeof(instruction_def_t)},
    {"Data Movement", riscv_data_movement, sizeof(riscv_data_movement)/sizeof(instruction_def_t)},
    {"Control Flow", riscv_control_flow, sizeof(riscv_control_flow)/sizeof(instruction_def_t)},
    {"System", riscv_system, sizeof(riscv_system)/sizeof(instruction_def_t)}
};

const arch_instruction_set_t* get_riscv_instruction_set(void) {
    static const arch_instruction_set_t riscv_set = {
        "riscv", 
        riscv_categories, 
        sizeof(riscv_categories)/sizeof(instruction_category_t)
    };
    return &riscv_set;
}
