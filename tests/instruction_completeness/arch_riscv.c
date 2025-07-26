#include "arch_riscv.h"

// ========================================
// RISC-V INSTRUCTION SET DEFINITIONS
// Based on RISC-V Instruction Set Manual, Volume I: User-Level ISA
// ========================================

// Arithmetic Instructions (comprehensive operand support)
static const instruction_def_t riscv_arithmetic[] = {
    // RV32I/RV64I Base Integer Instructions
    {"add", "Arithmetic", 3, false},           // rd,rs1,rs2 (add)
    {"sub", "Arithmetic", 3, false},           // rd,rs1,rs2 (subtract)
    {"addi", "Arithmetic", 3, false},          // rd,rs1,imm (add immediate)
    {"lui", "Arithmetic", 2, false},           // rd,imm (load upper immediate)
    {"auipc", "Arithmetic", 2, false},         // rd,imm (add upper immediate to PC)
    
    // Set less than
    {"slt", "Arithmetic", 3, false},           // rd,rs1,rs2 (set less than)
    {"sltu", "Arithmetic", 3, false},          // rd,rs1,rs2 (set less than unsigned)
    {"slti", "Arithmetic", 3, false},          // rd,rs1,imm (set less than immediate)
    {"sltiu", "Arithmetic", 3, false},         // rd,rs1,imm (set less than immediate unsigned)
    
    // RV64I additional instructions
    {"addiw", "Arithmetic", 3, false},         // rd,rs1,imm (add immediate word, RV64I only)
    {"addw", "Arithmetic", 3, false},          // rd,rs1,rs2 (add word, RV64I only)
    {"subw", "Arithmetic", 3, false},          // rd,rs1,rs2 (subtract word, RV64I only)
    
    // RV32M/RV64M Standard Extension for Integer Multiplication and Division
    {"mul", "Arithmetic", 3, true},            // rd,rs1,rs2 (multiply)
    {"mulh", "Arithmetic", 3, true},           // rd,rs1,rs2 (multiply high signed signed)
    {"mulhsu", "Arithmetic", 3, true},         // rd,rs1,rs2 (multiply high signed unsigned)
    {"mulhu", "Arithmetic", 3, true},          // rd,rs1,rs2 (multiply high unsigned unsigned)
    {"div", "Arithmetic", 3, true},            // rd,rs1,rs2 (divide signed)
    {"divu", "Arithmetic", 3, true},           // rd,rs1,rs2 (divide unsigned)
    {"rem", "Arithmetic", 3, true},            // rd,rs1,rs2 (remainder signed)
    {"remu", "Arithmetic", 3, true},           // rd,rs1,rs2 (remainder unsigned)
    
    // RV64M additional instructions
    {"mulw", "Arithmetic", 3, true},           // rd,rs1,rs2 (multiply word, RV64M only)
    {"divw", "Arithmetic", 3, true},           // rd,rs1,rs2 (divide word signed, RV64M only)
    {"divuw", "Arithmetic", 3, true},          // rd,rs1,rs2 (divide word unsigned, RV64M only)
    {"remw", "Arithmetic", 3, true},           // rd,rs1,rs2 (remainder word signed, RV64M only)
    {"remuw", "Arithmetic", 3, true},          // rd,rs1,rs2 (remainder word unsigned, RV64M only)
    
    // Pseudoinstructions (common assembler aliases)
    {"neg", "Arithmetic", 2, false},           // rd,rs (alias for sub rd,x0,rs)
    {"negw", "Arithmetic", 2, false},          // rd,rs (alias for subw rd,x0,rs, RV64I)
    {"sext.w", "Arithmetic", 2, false},        // rd,rs (alias for addiw rd,rs,0, RV64I)
    {"seqz", "Arithmetic", 2, false},          // rd,rs (alias for sltiu rd,rs,1)
    {"snez", "Arithmetic", 2, false},          // rd,rs (alias for sltu rd,x0,rs)
    {"sltz", "Arithmetic", 2, false},          // rd,rs (alias for slt rd,rs,x0)
    {"sgtz", "Arithmetic", 2, false}           // rd,rs (alias for slt rd,x0,rs)
};

// Logical Instructions (comprehensive operand support)
static const instruction_def_t riscv_logical[] = {
    // Bitwise logical operations
    {"and", "Logical", 3, false},              // rd,rs1,rs2 (bitwise AND)
    {"or", "Logical", 3, false},               // rd,rs1,rs2 (bitwise OR)
    {"xor", "Logical", 3, false},              // rd,rs1,rs2 (bitwise XOR)
    {"andi", "Logical", 3, false},             // rd,rs1,imm (bitwise AND immediate)
    {"ori", "Logical", 3, false},              // rd,rs1,imm (bitwise OR immediate)
    {"xori", "Logical", 3, false},             // rd,rs1,imm (bitwise XOR immediate)
    
    // Shift operations
    {"sll", "Logical", 3, false},              // rd,rs1,rs2 (shift left logical)
    {"srl", "Logical", 3, false},              // rd,rs1,rs2 (shift right logical)
    {"sra", "Logical", 3, false},              // rd,rs1,rs2 (shift right arithmetic)
    {"slli", "Logical", 3, false},             // rd,rs1,shamt (shift left logical immediate)
    {"srli", "Logical", 3, false},             // rd,rs1,shamt (shift right logical immediate)
    {"srai", "Logical", 3, false},             // rd,rs1,shamt (shift right arithmetic immediate)
    
    // RV64I additional shift operations
    {"sllw", "Logical", 3, false},             // rd,rs1,rs2 (shift left logical word, RV64I only)
    {"srlw", "Logical", 3, false},             // rd,rs1,rs2 (shift right logical word, RV64I only)
    {"sraw", "Logical", 3, false},             // rd,rs1,rs2 (shift right arithmetic word, RV64I only)
    {"slliw", "Logical", 3, false},            // rd,rs1,shamt (shift left logical immediate word, RV64I only)
    {"srliw", "Logical", 3, false},            // rd,rs1,shamt (shift right logical immediate word, RV64I only)
    {"sraiw", "Logical", 3, false},            // rd,rs1,shamt (shift right arithmetic immediate word, RV64I only)
    
    // Pseudoinstructions
    {"not", "Logical", 2, false},              // rd,rs (alias for xori rd,rs,-1)
    
    // RV32B/RV64B Bit Manipulation Extension (optional)
    {"andn", "Logical", 3, true},              // rd,rs1,rs2 (AND with complement)
    {"orn", "Logical", 3, true},               // rd,rs1,rs2 (OR with complement)
    {"xnor", "Logical", 3, true},              // rd,rs1,rs2 (XOR with complement)
    {"clz", "Logical", 2, true},               // rd,rs (count leading zeros)
    {"ctz", "Logical", 2, true},               // rd,rs (count trailing zeros)
    {"cpop", "Logical", 2, true},              // rd,rs (count population/set bits)
    {"max", "Logical", 3, true},               // rd,rs1,rs2 (maximum)
    {"maxu", "Logical", 3, true},              // rd,rs1,rs2 (maximum unsigned)
    {"min", "Logical", 3, true},               // rd,rs1,rs2 (minimum)
    {"minu", "Logical", 3, true},              // rd,rs1,rs2 (minimum unsigned)
    {"sext.b", "Logical", 2, true},            // rd,rs (sign extend byte)
    {"sext.h", "Logical", 2, true},            // rd,rs (sign extend halfword)
    {"zext.h", "Logical", 2, true},            // rd,rs (zero extend halfword)
    {"rol", "Logical", 3, true},               // rd,rs1,rs2 (rotate left)
    {"ror", "Logical", 3, true},               // rd,rs1,rs2 (rotate right)
    {"rori", "Logical", 3, true},              // rd,rs1,shamt (rotate right immediate)
    {"rev8", "Logical", 2, true},              // rd,rs (reverse bytes)
    {"orc.b", "Logical", 2, true},             // rd,rs (bitwise OR-combine byte)
    
    // RV64B additional instructions
    {"clzw", "Logical", 2, true},              // rd,rs (count leading zeros word, RV64B only)
    {"ctzw", "Logical", 2, true},              // rd,rs (count trailing zeros word, RV64B only)
    {"cpopw", "Logical", 2, true},             // rd,rs (count population word, RV64B only)
    {"rolw", "Logical", 3, true},              // rd,rs1,rs2 (rotate left word, RV64B only)
    {"rorw", "Logical", 3, true},              // rd,rs1,rs2 (rotate right word, RV64B only)
    {"roriw", "Logical", 3, true}              // rd,rs1,shamt (rotate right immediate word, RV64B only)
};

// Data Movement Instructions (comprehensive operand support)
static const instruction_def_t riscv_data_movement[] = {
    // Load instructions
    {"lb", "Data Movement", 2, false},         // rd,offset(rs1) (load byte)
    {"lh", "Data Movement", 2, false},         // rd,offset(rs1) (load halfword)
    {"lw", "Data Movement", 2, false},         // rd,offset(rs1) (load word)
    {"lbu", "Data Movement", 2, false},        // rd,offset(rs1) (load byte unsigned)
    {"lhu", "Data Movement", 2, false},        // rd,offset(rs1) (load halfword unsigned)
    
    // Store instructions
    {"sb", "Data Movement", 2, false},         // rs2,offset(rs1) (store byte)
    {"sh", "Data Movement", 2, false},         // rs2,offset(rs1) (store halfword)
    {"sw", "Data Movement", 2, false},         // rs2,offset(rs1) (store word)
    
    // RV64I additional load/store
    {"ld", "Data Movement", 2, false},         // rd,offset(rs1) (load doubleword, RV64I only)
    {"lwu", "Data Movement", 2, false},        // rd,offset(rs1) (load word unsigned, RV64I only)
    {"sd", "Data Movement", 2, false},         // rs2,offset(rs1) (store doubleword, RV64I only)
    
    // Pseudoinstructions for data movement
    {"mv", "Data Movement", 2, false},         // rd,rs (alias for addi rd,rs,0)
    {"li", "Data Movement", 2, false},         // rd,imm (load immediate, may expand to multiple instructions)
    {"la", "Data Movement", 2, false},         // rd,symbol (load address)
    
    // RV32A/RV64A Atomic Instructions
    {"lr.w", "Data Movement", 2, true},        // rd,(rs1) (load reserved word)
    {"sc.w", "Data Movement", 3, true},        // rd,rs2,(rs1) (store conditional word)
    {"amoswap.w", "Data Movement", 3, true},   // rd,rs2,(rs1) (atomic swap word)
    {"amoadd.w", "Data Movement", 3, true},    // rd,rs2,(rs1) (atomic add word)
    {"amoxor.w", "Data Movement", 3, true},    // rd,rs2,(rs1) (atomic XOR word)
    {"amoand.w", "Data Movement", 3, true},    // rd,rs2,(rs1) (atomic AND word)
    {"amoor.w", "Data Movement", 3, true},     // rd,rs2,(rs1) (atomic OR word)
    {"amomin.w", "Data Movement", 3, true},    // rd,rs2,(rs1) (atomic minimum word)
    {"amomax.w", "Data Movement", 3, true},    // rd,rs2,(rs1) (atomic maximum word)
    {"amominu.w", "Data Movement", 3, true},   // rd,rs2,(rs1) (atomic minimum unsigned word)
    {"amomaxu.w", "Data Movement", 3, true},   // rd,rs2,(rs1) (atomic maximum unsigned word)
    
    // RV64A additional atomic instructions
    {"lr.d", "Data Movement", 2, true},        // rd,(rs1) (load reserved doubleword, RV64A only)
    {"sc.d", "Data Movement", 3, true},        // rd,rs2,(rs1) (store conditional doubleword, RV64A only)
    {"amoswap.d", "Data Movement", 3, true},   // rd,rs2,(rs1) (atomic swap doubleword, RV64A only)
    {"amoadd.d", "Data Movement", 3, true},    // rd,rs2,(rs1) (atomic add doubleword, RV64A only)
    {"amoxor.d", "Data Movement", 3, true},    // rd,rs2,(rs1) (atomic XOR doubleword, RV64A only)
    {"amoand.d", "Data Movement", 3, true},    // rd,rs2,(rs1) (atomic AND doubleword, RV64A only)
    {"amoor.d", "Data Movement", 3, true},     // rd,rs2,(rs1) (atomic OR doubleword, RV64A only)
    {"amomin.d", "Data Movement", 3, true},    // rd,rs2,(rs1) (atomic minimum doubleword, RV64A only)
    {"amomax.d", "Data Movement", 3, true},    // rd,rs2,(rs1) (atomic maximum doubleword, RV64A only)
    {"amominu.d", "Data Movement", 3, true},   // rd,rs2,(rs1) (atomic minimum unsigned doubleword, RV64A only)
    {"amomaxu.d", "Data Movement", 3, true}    // rd,rs2,(rs1) (atomic maximum unsigned doubleword, RV64A only)
};

// Control Flow Instructions (comprehensive operand support)
static const instruction_def_t riscv_control_flow[] = {
    // Unconditional jumps
    {"jal", "Control Flow", 2, false},         // rd,offset (jump and link)
    {"jalr", "Control Flow", 3, false},        // rd,offset(rs1) (jump and link register)
    
    // Conditional branches
    {"beq", "Control Flow", 3, false},         // rs1,rs2,offset (branch if equal)
    {"bne", "Control Flow", 3, false},         // rs1,rs2,offset (branch if not equal)
    {"blt", "Control Flow", 3, false},         // rs1,rs2,offset (branch if less than)
    {"bge", "Control Flow", 3, false},         // rs1,rs2,offset (branch if greater or equal)
    {"bltu", "Control Flow", 3, false},        // rs1,rs2,offset (branch if less than unsigned)
    {"bgeu", "Control Flow", 3, false},        // rs1,rs2,offset (branch if greater or equal unsigned)
    
    // Pseudoinstructions for control flow
    {"j", "Control Flow", 1, false},           // offset (alias for jal x0,offset)
    {"jr", "Control Flow", 1, false},          // rs (alias for jalr x0,0(rs))
    {"ret", "Control Flow", 0, false},         // (alias for jalr x0,0(ra))
    {"call", "Control Flow", 1, false},        // offset (call subroutine, may expand to multiple instructions)
    {"tail", "Control Flow", 1, false},        // offset (tail call, may expand to multiple instructions)
    
    // Conditional branch pseudoinstructions
    {"beqz", "Control Flow", 2, false},        // rs,offset (alias for beq rs,x0,offset)
    {"bnez", "Control Flow", 2, false},        // rs,offset (alias for bne rs,x0,offset)
    {"blez", "Control Flow", 2, false},        // rs,offset (alias for bge x0,rs,offset)
    {"bgez", "Control Flow", 2, false},        // rs,offset (alias for bge rs,x0,offset)
    {"bltz", "Control Flow", 2, false},        // rs,offset (alias for blt rs,x0,offset)
    {"bgtz", "Control Flow", 2, false},        // rs,offset (alias for blt x0,rs,offset)
    {"bgt", "Control Flow", 3, false},         // rs1,rs2,offset (alias for blt rs2,rs1,offset)
    {"ble", "Control Flow", 3, false},         // rs1,rs2,offset (alias for bge rs2,rs1,offset)
    {"bgtu", "Control Flow", 3, false},        // rs1,rs2,offset (alias for bltu rs2,rs1,offset)
    {"bleu", "Control Flow", 3, false}         // rs1,rs2,offset (alias for bgeu rs2,rs1,offset)
};

// System Instructions (comprehensive system-level operations)
static const instruction_def_t riscv_system[] = {
    // Environment call and breakpoint
    {"ecall", "System", 0, false},             // (environment call)
    {"ebreak", "System", 0, false},            // (environment breakpoint)
    
    // Memory ordering
    {"fence", "System", 2, false},             // pred,succ (memory fence)
    {"fence.i", "System", 0, false},           // (instruction fence)
    
    // Control and Status Register (CSR) Instructions
    {"csrrw", "System", 3, true},              // rd,csr,rs1 (CSR read/write)
    {"csrrs", "System", 3, true},              // rd,csr,rs1 (CSR read and set bits)
    {"csrrc", "System", 3, true},              // rd,csr,rs1 (CSR read and clear bits)
    {"csrrwi", "System", 3, true},             // rd,csr,zimm (CSR read/write immediate)
    {"csrrsi", "System", 3, true},             // rd,csr,zimm (CSR read and set bits immediate)
    {"csrrci", "System", 3, true},             // rd,csr,zimm (CSR read and clear bits immediate)
    
    // CSR pseudoinstructions
    {"csrr", "System", 2, true},               // rd,csr (alias for csrrs rd,csr,x0)
    {"csrw", "System", 2, true},               // csr,rs (alias for csrrw x0,csr,rs)
    {"csrs", "System", 2, true},               // csr,rs (alias for csrrs x0,csr,rs)
    {"csrc", "System", 2, true},               // csr,rs (alias for csrrc x0,csr,rs)
    {"csrwi", "System", 2, true},              // csr,zimm (alias for csrrwi x0,csr,zimm)
    {"csrsi", "System", 2, true},              // csr,zimm (alias for csrrsi x0,csr,zimm)
    {"csrci", "System", 2, true},              // csr,zimm (alias for csrrci x0,csr,zimm)
    
    // Privileged instructions (machine mode)
    {"mret", "System", 0, true},               // (machine-mode exception return)
    {"sret", "System", 0, true},               // (supervisor-mode exception return)
    {"uret", "System", 0, true},               // (user-mode exception return)
    {"wfi", "System", 0, true},                // (wait for interrupt)
    
    // Supervisor memory management
    {"sfence.vma", "System", 2, true},         // rs1,rs2 (supervisor fence virtual memory)
    
    // Hypervisor extension
    {"hfence.vvma", "System", 2, true},        // rs1,rs2 (hypervisor fence virtual virtual memory)
    {"hfence.gvma", "System", 2, true},        // rs1,rs2 (hypervisor fence guest virtual memory)
    {"hlv.b", "System", 2, true},              // rd,(rs1) (hypervisor load virtual byte)
    {"hlv.bu", "System", 2, true},             // rd,(rs1) (hypervisor load virtual byte unsigned)
    {"hlv.h", "System", 2, true},              // rd,(rs1) (hypervisor load virtual halfword)
    {"hlv.hu", "System", 2, true},             // rd,(rs1) (hypervisor load virtual halfword unsigned)
    {"hlv.w", "System", 2, true},              // rd,(rs1) (hypervisor load virtual word)
    {"hlv.wu", "System", 2, true},             // rd,(rs1) (hypervisor load virtual word unsigned, RV64 only)
    {"hlv.d", "System", 2, true},              // rd,(rs1) (hypervisor load virtual doubleword, RV64 only)
    {"hsv.b", "System", 2, true},              // rs2,(rs1) (hypervisor store virtual byte)
    {"hsv.h", "System", 2, true},              // rs2,(rs1) (hypervisor store virtual halfword)
    {"hsv.w", "System", 2, true},              // rs2,(rs1) (hypervisor store virtual word)
    {"hsv.d", "System", 2, true},              // rs2,(rs1) (hypervisor store virtual doubleword, RV64 only)
    
    // Debug extension
    {"dret", "System", 0, true}                // (debug-mode exception return)
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
