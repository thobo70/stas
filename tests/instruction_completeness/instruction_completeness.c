#include "instruction_completeness.h"
#include "../../include/arch_interface.h"
#include "../../src/arch/x86_16/x86_16.h"
#include "../../include/x86_32.h"
#include "../../include/x86_64.h"
#include <stdio.h>
#include <string.h>
#include <stdlib.h>

// Forward declarations for architecture operations
extern arch_ops_t *get_arch_ops_x86_16(void);
extern arch_ops_t *get_arch_ops_x86_32(void);
extern arch_ops_t *get_arch_ops_x86_64(void);
extern arch_ops_t *get_arch_ops_arm64(void);
extern arch_ops_t *get_riscv_arch_ops(void);

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

// ========================================
// x86_32 INSTRUCTION SET DEFINITIONS
// ========================================

static const instruction_def_t x86_32_arithmetic[] = {
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
    {"imul", "Arithmetic", 2, false},
    {"idiv", "Arithmetic", 1, false},
    {"bsf", "Arithmetic", 2, true},
    {"bsr", "Arithmetic", 2, true},
    {"bt", "Arithmetic", 2, true},
    {"btc", "Arithmetic", 2, true},
    {"btr", "Arithmetic", 2, true},
    {"bts", "Arithmetic", 2, true},
    {"daa", "Arithmetic", 0, true},
    {"das", "Arithmetic", 0, true},
    {"aaa", "Arithmetic", 0, true},
    {"aas", "Arithmetic", 0, true},
    {"aam", "Arithmetic", 0, true},
    {"aad", "Arithmetic", 0, true}
};

static const instruction_def_t x86_32_logical[] = {
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
    {"rcr", "Logical", 2, false},
    {"shld", "Logical", 3, true},
    {"shrd", "Logical", 3, true},
    {"cmc", "Logical", 0, true}
};

static const instruction_def_t x86_32_data_movement[] = {
    {"mov", "Data Movement", 2, false},
    {"push", "Data Movement", 1, false},
    {"pop", "Data Movement", 1, false},
    {"xchg", "Data Movement", 2, false},
    {"lea", "Data Movement", 2, false},
    {"pushad", "Data Movement", 0, false},
    {"popad", "Data Movement", 0, false},
    {"pushfd", "Data Movement", 0, false},
    {"popfd", "Data Movement", 0, false},
    {"movzx", "Data Movement", 2, true},
    {"movsx", "Data Movement", 2, true},
    {"bswap", "Data Movement", 1, true},
    {"xadd", "Data Movement", 2, true},
    {"cmpxchg", "Data Movement", 2, true},
    {"lahf", "Data Movement", 0, true},
    {"sahf", "Data Movement", 0, true},
    {"cbw", "Data Movement", 0, true},
    {"cwde", "Data Movement", 0, true},
    {"cwd", "Data Movement", 0, true},
    {"cdq", "Data Movement", 0, true},
    {"lds", "Data Movement", 2, true},
    {"les", "Data Movement", 2, true},
    {"lfs", "Data Movement", 2, true},
    {"lgs", "Data Movement", 2, true},
    {"lss", "Data Movement", 2, true},
    {"pushf", "Data Movement", 0, true},
    {"popf", "Data Movement", 0, true}
};

static const instruction_def_t x86_32_control_flow[] = {
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
    {"loopne", "Control Flow", 1, false},
    {"jecxz", "Control Flow", 1, false},
    {"jcxz", "Control Flow", 1, true},
    {"jna", "Control Flow", 1, true},
    {"jnae", "Control Flow", 1, true},
    {"jnb", "Control Flow", 1, true},
    {"jnbe", "Control Flow", 1, true},
    {"jng", "Control Flow", 1, true},
    {"jnge", "Control Flow", 1, true},
    {"jnl", "Control Flow", 1, true},
    {"jnle", "Control Flow", 1, true},
    {"jnp", "Control Flow", 1, true},
    {"jp", "Control Flow", 1, true},
    {"jpe", "Control Flow", 1, true},
    {"jpo", "Control Flow", 1, true},
    {"loopz", "Control Flow", 1, true},
    {"loopnz", "Control Flow", 1, true},
    {"sete", "Control Flow", 1, true},
    {"setne", "Control Flow", 1, true},
    {"setl", "Control Flow", 1, true},
    {"setg", "Control Flow", 1, true},
    {"seta", "Control Flow", 1, true},
    {"setae", "Control Flow", 1, true},
    {"setb", "Control Flow", 1, true},
    {"setbe", "Control Flow", 1, true},
    {"setc", "Control Flow", 1, true},
    {"setge", "Control Flow", 1, true},
    {"setle", "Control Flow", 1, true},
    {"setna", "Control Flow", 1, true},
    {"setnae", "Control Flow", 1, true},
    {"setnb", "Control Flow", 1, true},
    {"setnbe", "Control Flow", 1, true},
    {"setnc", "Control Flow", 1, true},
    {"setng", "Control Flow", 1, true},
    {"setnge", "Control Flow", 1, true},
    {"setnl", "Control Flow", 1, true},
    {"setnle", "Control Flow", 1, true},
    {"setno", "Control Flow", 1, true},
    {"setnp", "Control Flow", 1, true},
    {"setns", "Control Flow", 1, true},
    {"setnz", "Control Flow", 1, true},
    {"seto", "Control Flow", 1, true},
    {"setp", "Control Flow", 1, true},
    {"setpe", "Control Flow", 1, true},
    {"setpo", "Control Flow", 1, true},
    {"sets", "Control Flow", 1, true},
    {"setz", "Control Flow", 1, true}
};

static const instruction_def_t x86_32_system[] = {
    {"int", "System", 1, false},
    {"iret", "System", 0, false},
    {"iretd", "System", 0, false},
    {"cli", "System", 0, false},
    {"sti", "System", 0, false},
    {"clc", "System", 0, false},
    {"stc", "System", 0, false},
    {"cld", "System", 0, false},
    {"std", "System", 0, false},
    {"nop", "System", 0, false},
    {"hlt", "System", 0, false},
    {"wait", "System", 0, false},
    {"cpuid", "System", 0, true},
    {"rdtsc", "System", 0, true},
    {"wrmsr", "System", 0, true},
    {"rdmsr", "System", 0, true},
    {"into", "System", 0, true},
    {"bound", "System", 2, true},
    {"enter", "System", 2, true},
    {"leave", "System", 0, true},
    {"pusha", "System", 0, true},
    {"popa", "System", 0, true},
    {"arpl", "System", 2, true},
    {"verr", "System", 1, true},
    {"verw", "System", 1, true},
    {"clts", "System", 0, true},
    {"lmsw", "System", 1, true},
    {"smsw", "System", 1, true},
    {"lgdt", "System", 1, true},
    {"sgdt", "System", 1, true},
    {"lidt", "System", 1, true},
    {"sidt", "System", 1, true},
    {"lldt", "System", 1, true},
    {"sldt", "System", 1, true},
    {"ltr", "System", 1, true},
    {"str", "System", 1, true},
    {"lar", "System", 2, true},
    {"lsl", "System", 2, true},
    {"lock", "System", 0, true},
    {"in", "System", 2, true},
    {"out", "System", 2, true},
    {"ins", "System", 0, true},
    {"insb", "System", 0, true},
    {"insw", "System", 0, true},
    {"insd", "System", 0, true},
    {"outs", "System", 0, true},
    {"outsb", "System", 0, true},
    {"outsw", "System", 0, true},
    {"outsd", "System", 0, true},
    {"esc", "System", 1, true}
};

static const instruction_def_t x86_32_string[] = {
    {"movs", "String", 0, true},
    {"movsb", "String", 0, true},
    {"movsw", "String", 0, true},
    {"movsd", "String", 0, true},
    {"lods", "String", 0, true},
    {"lodsb", "String", 0, true},
    {"lodsw", "String", 0, true},
    {"lodsd", "String", 0, true},
    {"stos", "String", 0, true},
    {"stosb", "String", 0, true},
    {"stosw", "String", 0, true},
    {"stosd", "String", 0, true},
    {"scas", "String", 0, true},
    {"scasb", "String", 0, true},
    {"scasw", "String", 0, true},
    {"scasd", "String", 0, true},
    {"cmps", "String", 0, true},
    {"cmpsb", "String", 0, true},
    {"cmpsw", "String", 0, true},
    {"cmpsd", "String", 0, true},
    {"rep", "String", 0, true},
    {"repe", "String", 0, true},
    {"repne", "String", 0, true},
    {"repz", "String", 0, true},
    {"repnz", "String", 0, true},
    {"xlat", "String", 0, true},
    {"xlatb", "String", 0, true}
};

static const instruction_category_t x86_32_categories[] = {
    {"Arithmetic", x86_32_arithmetic, sizeof(x86_32_arithmetic)/sizeof(instruction_def_t)},
    {"Logical", x86_32_logical, sizeof(x86_32_logical)/sizeof(instruction_def_t)},
    {"Data Movement", x86_32_data_movement, sizeof(x86_32_data_movement)/sizeof(instruction_def_t)},
    {"Control Flow", x86_32_control_flow, sizeof(x86_32_control_flow)/sizeof(instruction_def_t)},
    {"System", x86_32_system, sizeof(x86_32_system)/sizeof(instruction_def_t)},
    {"String", x86_32_string, sizeof(x86_32_string)/sizeof(instruction_def_t)}
};

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

// ========================================
// ARCHITECTURE DEFINITIONS
// ========================================

static const arch_instruction_set_t architectures[] = {
    {"x86_16", x86_16_categories, sizeof(x86_16_categories)/sizeof(instruction_category_t)},
    {"x86_32", x86_32_categories, sizeof(x86_32_categories)/sizeof(instruction_category_t)},
    {"x86_64", x86_64_categories, sizeof(x86_64_categories)/sizeof(instruction_category_t)},
    {"arm64", arm64_categories, sizeof(arm64_categories)/sizeof(instruction_category_t)},
    {"riscv", riscv_categories, sizeof(riscv_categories)/sizeof(instruction_category_t)}
};

static const size_t architecture_count = sizeof(architectures)/sizeof(arch_instruction_set_t);

// ========================================
// HELPER FUNCTIONS
// ========================================

static arch_ops_t* get_arch_ops_by_name(const char* arch_name) {
    if (strcmp(arch_name, "x86_16") == 0) return get_arch_ops_x86_16();
    if (strcmp(arch_name, "x86_32") == 0) return get_arch_ops_x86_32();
    if (strcmp(arch_name, "x86_64") == 0) return get_arch_ops_x86_64();
    if (strcmp(arch_name, "arm64") == 0) return get_arch_ops_arm64();
    if (strcmp(arch_name, "riscv") == 0) return get_riscv_arch_ops();
    return NULL;
}

static bool test_instruction_recognition(arch_ops_t* arch_ops, const instruction_def_t* instr) {
    if (!arch_ops || !arch_ops->parse_instruction || !instr) return false;
    
    operand_t dummy_operands[4] = {0};
    instruction_t test_instr = {0};
    
    int result = arch_ops->parse_instruction(instr->mnemonic, dummy_operands, 
                                           instr->operand_count, &test_instr);
    
    // Note: Don't free the instruction fields as they may not be heap-allocated
    
    return result == 0;
}

static void setup_dummy_operands(operand_t* operands, size_t operand_count, const char* arch_name, const char* mnemonic) {
    // Initialize all operands to zero
    memset(operands, 0, sizeof(operand_t) * operand_count);
    
    // Check if this is a shift operation that needs special operand handling
    bool is_shift_op = (strcmp(mnemonic, "shl") == 0 || strcmp(mnemonic, "shr") == 0 ||
                       strcmp(mnemonic, "sal") == 0 || strcmp(mnemonic, "sar") == 0 ||
                       strcmp(mnemonic, "rol") == 0 || strcmp(mnemonic, "ror") == 0 ||
                       strcmp(mnemonic, "rcl") == 0 || strcmp(mnemonic, "rcr") == 0);
    
    bool is_3op_shift = (strcmp(mnemonic, "shld") == 0 || strcmp(mnemonic, "shrd") == 0);
    
    // Check if this is a control flow instruction that needs immediate operands
    bool is_control_flow = (strcmp(mnemonic, "jmp") == 0 || strcmp(mnemonic, "call") == 0 ||
                           strcmp(mnemonic, "je") == 0 || strcmp(mnemonic, "jne") == 0 ||
                           strcmp(mnemonic, "jz") == 0 || strcmp(mnemonic, "jnz") == 0 ||
                           strcmp(mnemonic, "jl") == 0 || strcmp(mnemonic, "jle") == 0 ||
                           strcmp(mnemonic, "jg") == 0 || strcmp(mnemonic, "jge") == 0 ||
                           strcmp(mnemonic, "ja") == 0 || strcmp(mnemonic, "jae") == 0 ||
                           strcmp(mnemonic, "jb") == 0 || strcmp(mnemonic, "jbe") == 0 ||
                           strcmp(mnemonic, "jc") == 0 || strcmp(mnemonic, "jnc") == 0 ||
                           strcmp(mnemonic, "jo") == 0 || strcmp(mnemonic, "jno") == 0 ||
                           strcmp(mnemonic, "js") == 0 || strcmp(mnemonic, "jns") == 0 ||
                           strcmp(mnemonic, "loop") == 0 || strcmp(mnemonic, "loope") == 0 ||
                           strcmp(mnemonic, "loopne") == 0 || strcmp(mnemonic, "jecxz") == 0 ||
                           // Jump aliases
                           strcmp(mnemonic, "jna") == 0 || strcmp(mnemonic, "jnae") == 0 ||
                           strcmp(mnemonic, "jnb") == 0 || strcmp(mnemonic, "jnbe") == 0 ||
                           strcmp(mnemonic, "jng") == 0 || strcmp(mnemonic, "jnge") == 0 ||
                           strcmp(mnemonic, "jnl") == 0 || strcmp(mnemonic, "jnle") == 0 ||
                           strcmp(mnemonic, "jnp") == 0 || strcmp(mnemonic, "jp") == 0 ||
                           strcmp(mnemonic, "jpe") == 0 || strcmp(mnemonic, "jpo") == 0);
    
    // Check if this is a set instruction that needs 8-bit register
    bool is_set_instr = (strncmp(mnemonic, "set", 3) == 0);
    
    // Check if this is a bit manipulation instruction needing immediate + register
    bool is_bit_manip = (strcmp(mnemonic, "bt") == 0 || strcmp(mnemonic, "btc") == 0 ||
                        strcmp(mnemonic, "btr") == 0 || strcmp(mnemonic, "bts") == 0);
    
    // Check if this is LEA instruction that needs memory operand
    bool is_lea = (strcmp(mnemonic, "lea") == 0 || strcmp(mnemonic, "leal") == 0 ||
                   strcmp(mnemonic, "leaw") == 0 || strcmp(mnemonic, "leaq") == 0);
    
    // Check if this is MOVZX/MOVSX instruction that needs different sized operands
    bool is_extend = (strcmp(mnemonic, "movzx") == 0 || strcmp(mnemonic, "movsx") == 0);
    
    // Check if this is a segment load instruction (LDS, LES, LFS, LGS, LSS)
    bool is_segment_load = (strcmp(mnemonic, "lds") == 0 || strcmp(mnemonic, "les") == 0 ||
                           strcmp(mnemonic, "lfs") == 0 || strcmp(mnemonic, "lgs") == 0 ||
                           strcmp(mnemonic, "lss") == 0);
    
    // Check if this is ENTER instruction that needs two immediate operands
    bool is_enter = (strcmp(mnemonic, "enter") == 0);
    
    // Check if this is a descriptor table instruction (LGDT, SGDT, LIDT, SIDT)
    bool is_descriptor_table = (strcmp(mnemonic, "lgdt") == 0 || strcmp(mnemonic, "sgdt") == 0 ||
                               strcmp(mnemonic, "lidt") == 0 || strcmp(mnemonic, "sidt") == 0);
    
    // Set up appropriate dummy operands based on architecture
    for (size_t i = 0; i < operand_count && i < 4; i++) {
        if (strcmp(arch_name, "x86_32") == 0) {
            // Special handling for control flow instructions
            if (is_control_flow && operand_count == 1) {
                // Control flow instructions need immediate relative offsets
                operands[i].type = OPERAND_IMMEDIATE;
                operands[i].value.immediate = 10; // Short relative jump
                operands[i].size = 1;
            }
            // Special handling for set instructions
            else if (is_set_instr && operand_count == 1) {
                // Set instructions need 8-bit register
                operands[i].type = OPERAND_REGISTER;
                operands[i].value.reg.name = "al";
                operands[i].value.reg.size = 1;
                operands[i].value.reg.encoding = 0;
                operands[i].size = 1;
            }
            // Special handling for bit manipulation instructions
            else if (is_bit_manip && operand_count == 2) {
                if (i == 0) {
                    // First operand: immediate bit index (AT&T: source comes first)
                    operands[i].type = OPERAND_IMMEDIATE;
                    operands[i].value.immediate = 5;
                    operands[i].size = 1;
                } else {
                    // Second operand: register
                    operands[i].type = OPERAND_REGISTER;
                    operands[i].value.reg.name = "eax";
                    operands[i].value.reg.size = 4;
                    operands[i].value.reg.encoding = 0;
                    operands[i].size = 4;
                }
            }
            // Special handling for LEA instruction
            else if (is_lea && operand_count == 2) {
                if (i == 0) {
                    // First operand: memory address (AT&T: source memory comes first)
                    operands[i].type = OPERAND_MEMORY;
                    operands[i].value.memory.base.name = "ebx";
                    operands[i].value.memory.base.size = 4;
                    operands[i].value.memory.base.encoding = 3;
                    operands[i].value.memory.offset = 8;  // 8(%ebx)
                    operands[i].size = 4;
                } else {
                    // Second operand: destination register
                    operands[i].type = OPERAND_REGISTER;
                    operands[i].value.reg.name = "eax";
                    operands[i].value.reg.size = 4;
                    operands[i].value.reg.encoding = 0;
                    operands[i].size = 4;
                }
            }
            // Special handling for MOVZX/MOVSX extension instructions
            else if (is_extend && operand_count == 2) {
                if (i == 0) {
                    // First operand: smaller source register (AT&T: source comes first)
                    operands[i].type = OPERAND_REGISTER;
                    operands[i].value.reg.name = "bl";
                    operands[i].value.reg.size = 1;
                    operands[i].value.reg.encoding = 3;
                    operands[i].size = 1;
                } else {
                    // Second operand: larger destination register
                    operands[i].type = OPERAND_REGISTER;
                    operands[i].value.reg.name = "eax";
                    operands[i].value.reg.size = 4;
                    operands[i].value.reg.encoding = 0;
                    operands[i].size = 4;
                }
            }
            // Special handling for segment load instructions (LDS, LES, LFS, LGS, LSS)
            else if (is_segment_load && operand_count == 2) {
                if (i == 0) {
                    // First operand: memory address for segment:offset (AT&T: source memory comes first)
                    operands[i].type = OPERAND_MEMORY;
                    operands[i].value.memory.base.name = "ebx";
                    operands[i].value.memory.base.size = 4;
                    operands[i].value.memory.base.encoding = 3;
                    operands[i].value.memory.offset = 0;  // (%ebx)
                    operands[i].size = 6; // 6 bytes: 4-byte offset + 2-byte segment
                } else {
                    // Second operand: destination register
                    operands[i].type = OPERAND_REGISTER;
                    operands[i].value.reg.name = "eax";
                    operands[i].value.reg.size = 4;
                    operands[i].value.reg.encoding = 0;
                    operands[i].size = 4;
                }
            }
            // Special handling for ENTER instruction
            else if (is_enter && operand_count == 2) {
                if (i == 0) {
                    // First operand: frame size (16-bit immediate)
                    operands[i].type = OPERAND_IMMEDIATE;
                    operands[i].value.immediate = 16; // 16 bytes frame size
                    operands[i].size = 2;
                } else {
                    // Second operand: nesting level (8-bit immediate)
                    operands[i].type = OPERAND_IMMEDIATE;
                    operands[i].value.immediate = 0; // nesting level 0
                    operands[i].size = 1;
                }
            }
            // Special handling for descriptor table instructions (LGDT, SGDT, LIDT, SIDT)
            else if (is_descriptor_table && operand_count == 1) {
                // Single operand: memory address for descriptor table
                operands[i].type = OPERAND_MEMORY;
                operands[i].value.memory.base.name = "ebx";
                operands[i].value.memory.base.size = 4;
                operands[i].value.memory.base.encoding = 3;
                operands[i].value.memory.offset = 0;  // (%ebx)
                operands[i].size = 6; // 6 bytes: base + limit
            }
            // Special handling for shift operations with AT&T syntax
            else if (is_shift_op && operand_count == 2) {
                if (i == 0) {
                    // First operand: immediate count (AT&T: source comes first)
                    operands[i].type = OPERAND_IMMEDIATE;
                    operands[i].value.immediate = 1;
                    operands[i].size = 1;
                } else {
                    // Second operand: destination register
                    operands[i].type = OPERAND_REGISTER;
                    operands[i].value.reg.name = "eax";
                    operands[i].value.reg.size = 4;
                    operands[i].value.reg.encoding = 0;
                    operands[i].size = 4;
                }
            } else if (is_3op_shift && operand_count == 3) {
                if (i == 0) {
                    // First operand: immediate count (AT&T: count comes first)
                    operands[i].type = OPERAND_IMMEDIATE;
                    operands[i].value.immediate = 1;
                    operands[i].size = 1;
                } else if (i == 1) {
                    // Second operand: source register
                    operands[i].type = OPERAND_REGISTER;
                    operands[i].value.reg.name = "ebx";
                    operands[i].value.reg.size = 4;
                    operands[i].value.reg.encoding = 3;
                    operands[i].size = 4;
                } else {
                    // Third operand: destination register
                    operands[i].type = OPERAND_REGISTER;
                    operands[i].value.reg.name = "eax";
                    operands[i].value.reg.size = 4;
                    operands[i].value.reg.encoding = 0;
                    operands[i].size = 4;
                }
            } else {
                // Default register operands
                operands[i].type = OPERAND_REGISTER;
                operands[i].value.reg.name = (i == 0) ? "eax" : "ebx";
                operands[i].value.reg.size = 4;
                operands[i].value.reg.encoding = (i == 0) ? 0 : 3;
                operands[i].size = 4;
            }
        } else if (strcmp(arch_name, "x86_16") == 0) {
            // Special handling for control flow instructions
            if (is_control_flow && operand_count == 1) {
                // Control flow instructions need immediate relative offsets
                operands[i].type = OPERAND_IMMEDIATE;
                operands[i].value.immediate = 10; // Short relative jump
                operands[i].size = 1;
            }
            // Special handling for set instructions (not available in x86_16, but keeping structure)
            else if (is_set_instr && operand_count == 1) {
                // Set instructions need 8-bit register
                operands[i].type = OPERAND_REGISTER;
                operands[i].value.reg.name = "al";
                operands[i].value.reg.size = 1;
                operands[i].value.reg.encoding = 0;
                operands[i].size = 1;
            }
            // Special handling for shift operations with AT&T syntax
            else if (is_shift_op && operand_count == 2) {
                if (i == 0) {
                    // First operand: immediate count (AT&T: source comes first)
                    operands[i].type = OPERAND_IMMEDIATE;
                    operands[i].value.immediate = 1;
                    operands[i].size = 1;
                } else {
                    // Second operand: destination register
                    operands[i].type = OPERAND_REGISTER;
                    operands[i].value.reg.name = "ax";
                    operands[i].value.reg.size = 2;
                    operands[i].value.reg.encoding = 0;
                    operands[i].size = 2;
                }
            } else if (is_3op_shift && operand_count == 3) {
                if (i == 0) {
                    // First operand: immediate count (AT&T: count comes first)
                    operands[i].type = OPERAND_IMMEDIATE;
                    operands[i].value.immediate = 1;
                    operands[i].size = 1;
                } else if (i == 1) {
                    // Second operand: source register
                    operands[i].type = OPERAND_REGISTER;
                    operands[i].value.reg.name = "bx";
                    operands[i].value.reg.size = 2;
                    operands[i].value.reg.encoding = 3;
                    operands[i].size = 2;
                } else {
                    // Third operand: destination register
                    operands[i].type = OPERAND_REGISTER;
                    operands[i].value.reg.name = "ax";
                    operands[i].value.reg.size = 2;
                    operands[i].value.reg.encoding = 0;
                    operands[i].size = 2;
                }
            } else {
                // Default register operands
                operands[i].type = OPERAND_REGISTER;
                operands[i].value.reg.name = (i == 0) ? "ax" : "bx";
                operands[i].value.reg.size = 2;
                operands[i].value.reg.encoding = (i == 0) ? 0 : 3;
                operands[i].size = 2;
            }
        } else if (strcmp(arch_name, "x86_64") == 0) {
            operands[i].type = OPERAND_REGISTER;
            operands[i].value.reg.name = (i == 0) ? "rax" : "rbx";
            operands[i].value.reg.size = 8;
            operands[i].value.reg.encoding = (i == 0) ? 0 : 3;
            operands[i].size = 8;
        } else if (strcmp(arch_name, "arm64") == 0) {
            operands[i].type = OPERAND_REGISTER;
            operands[i].value.reg.name = (i == 0) ? "x0" : "x1";
            operands[i].value.reg.size = 8;
            operands[i].value.reg.encoding = (i == 0) ? 0 : 1;
            operands[i].size = 8;
        } else if (strcmp(arch_name, "riscv") == 0) {
            operands[i].type = OPERAND_REGISTER;
            operands[i].value.reg.name = (i == 0) ? "x1" : "x2";
            operands[i].value.reg.size = 8;
            operands[i].value.reg.encoding = (i == 0) ? 1 : 2;
            operands[i].size = 8;
        } else {
            // Default to register operands
            operands[i].type = OPERAND_REGISTER;
            operands[i].value.reg.name = "r0";
            operands[i].value.reg.size = 4;
            operands[i].value.reg.encoding = 0;
            operands[i].size = 4;
        }
    }
}

static bool test_instruction_functional(arch_ops_t* arch_ops, const instruction_def_t* instr) {
    if (!test_instruction_recognition(arch_ops, instr)) return false;
    
    // Test encoding capability for functional support
    if (!arch_ops->encode_instruction) return false;
    
    operand_t dummy_operands[4] = {0};
    instruction_t test_instr = {0};
    
    // Set up proper dummy operands - try to identify architecture by testing against known architectures
    const char* arch_name = "unknown";
    
    // Test with each architecture's get function to identify which one this is
    arch_ops_t* x86_16_ops = get_arch_ops_x86_16();
    arch_ops_t* x86_32_ops = get_arch_ops_x86_32();
    arch_ops_t* x86_64_ops = get_arch_ops_x86_64();
    arch_ops_t* arm64_ops = get_arch_ops_arm64();
    arch_ops_t* riscv_ops = get_riscv_arch_ops();
    
    if (arch_ops == x86_32_ops) {
        arch_name = "x86_32";
    } else if (arch_ops == x86_16_ops) {
        arch_name = "x86_16";
    } else if (arch_ops == x86_64_ops) {
        arch_name = "x86_64";
    } else if (arch_ops == arm64_ops) {
        arch_name = "arm64";
    } else if (arch_ops == riscv_ops) {
        arch_name = "riscv";
    }
    
    setup_dummy_operands(dummy_operands, instr->operand_count, arch_name, instr->mnemonic);
    
    int parse_result = arch_ops->parse_instruction(instr->mnemonic, dummy_operands, 
                                                 instr->operand_count, &test_instr);
    
    if (parse_result != 0) return false;
    
    uint8_t buffer[16] = {0};
    size_t length = 0;
    
    int encode_result = arch_ops->encode_instruction(&test_instr, buffer, &length);
    
    // Note: Don't free the instruction fields as they may not be heap-allocated
    
    return encode_result == 0 && length > 0;
}

instruction_test_result_t test_instruction_category(const char *arch_name, 
                                                   const instruction_category_t *category) {
    return test_instruction_category_verbose(arch_name, category, false);
}

instruction_test_result_t test_instruction_category_verbose(const char *arch_name, 
                                                           const instruction_category_t *category,
                                                           bool verbose_mode) {
    instruction_test_result_t result = {0};
    arch_ops_t* arch_ops = get_arch_ops_by_name(arch_name);
    
    if (!arch_ops || !category) return result;
    
    result.total = category->instruction_count;
    
    // Arrays to track failed instructions for verbose reporting
    const instruction_def_t **unrecognized = NULL;
    const instruction_def_t **nonfunctional = NULL;
    size_t unrecognized_count = 0;
    size_t nonfunctional_count = 0;
    
    if (verbose_mode) {
        unrecognized = malloc(category->instruction_count * sizeof(instruction_def_t*));
        nonfunctional = malloc(category->instruction_count * sizeof(instruction_def_t*));
    }
    
    for (size_t i = 0; i < category->instruction_count; i++) {
        const instruction_def_t* instr = &category->instructions[i];
        
        if (test_instruction_recognition(arch_ops, instr)) {
            result.recognized++;
            
            if (test_instruction_functional(arch_ops, instr)) {
                result.functional++;
            } else if (verbose_mode) {
                nonfunctional[nonfunctional_count++] = instr;
            }
        } else if (verbose_mode) {
            unrecognized[unrecognized_count++] = instr;
        }
    }
    
    result.recognition_percent = result.total > 0 ? 
        (double)result.recognized / result.total * 100.0 : 0.0;
    result.functional_percent = result.total > 0 ? 
        (double)result.functional / result.total * 100.0 : 0.0;
    
    // Print verbose failure reports
    if (verbose_mode) {
        if (unrecognized_count > 0) {
            printf("      ❌ UNRECOGNIZED (%zu instructions):\n", unrecognized_count);
            for (size_t i = 0; i < unrecognized_count; i++) {
                printf("         • %s", unrecognized[i]->mnemonic);
                if (unrecognized[i]->is_extension) {
                    printf(" (extension)");
                }
                printf("\n");
            }
        }
        
        if (nonfunctional_count > 0) {
            printf("      ⚠️  NON-FUNCTIONAL (%zu instructions):\n", nonfunctional_count);
            for (size_t i = 0; i < nonfunctional_count; i++) {
                printf("         • %s", nonfunctional[i]->mnemonic);
                if (nonfunctional[i]->is_extension) {
                    printf(" (extension)");
                }
                printf(" - parsing OK, encoding failed\n");
            }
        }
        
        free(unrecognized);
        free(nonfunctional);
    }
    
    return result;
}

void print_progress_bar(double percent, int width, bool compact) {
    if (compact) {
        // Ultra-compact: just percentage
        printf("%5.1f%%", percent);
        return;
    }
    
    if (width < 5) width = 5;
    if (width > 20) width = 20;
    
    int bars = (int)(percent * width / 100.0);
    printf("[");
    for (int i = 0; i < width; i++) {
        if (i < bars) printf("#");
        else printf(".");
    }
    printf("]");
}

void print_instruction_completeness_report_compact(arch_test_result_t *results, size_t arch_count, const report_config_t *config) {
    int max_width = config ? config->max_line_width : 80;
    bool compact = config ? config->compact_mode : false;
    bool show_bars = config ? config->show_progress_bars : true;
    
    printf("\n");
    if (compact) {
        // Ultra-compact format
        printf("+============================================================================+\n");
        printf("|                    STAS INSTRUCTION SET COMPLETENESS                      |\n");
        printf("+============================================================================+\n");
        
        for (size_t i = 0; i < arch_count; i++) {
            arch_test_result_t *arch = &results[i];
            printf("| %-8s | Overall: ", arch->arch_name);
            print_progress_bar(arch->overall.recognition_percent, 0, true);
            printf(" rec, ");
            print_progress_bar(arch->overall.functional_percent, 0, true);
            printf(" func");
            
            // Pad to line width
            int used = 25 + 12; // approx used chars
            for (int j = used; j < max_width - 3; j++) printf(" ");
            printf("|\n");
            
            // Show top categories briefly
            for (size_t j = 0; j < arch->category_count && j < 3; j++) {
                category_result_t *cat = &arch->category_results[j];
                printf("|   %-12s | ", cat->category_name);
                print_progress_bar(cat->result.recognition_percent, 0, true);
                printf("/");
                print_progress_bar(cat->result.functional_percent, 0, true);
                
                int used = 20 + 12; // approx used chars  
                for (int k = used; k < max_width - 3; k++) printf(" ");
                printf("|\n");
            }
            
            if (i < arch_count - 1) {
                printf("+----------------------------------------------------------------------------+\n");
            }
        }
        printf("+============================================================================+\n");
    } else {
        // Standard width format (≤80 chars)
        printf("+==============================================================================+\n");
        printf("|                        STAS INSTRUCTION COMPLETENESS REPORT                 |\n");
        printf("+==============================================================================+\n");
        
        for (size_t i = 0; i < arch_count; i++) {
            arch_test_result_t *arch = &results[i];
            
            printf("| %-8s | Category Analysis                                            |\n", arch->arch_name);
            printf("+----------+--------------------------------------------------------------+\n");
            
            for (size_t j = 0; j < arch->category_count; j++) {
                category_result_t *cat = &arch->category_results[j];
                printf("| %-12s | %3zu/%-3zu ", 
                       cat->category_name, 
                       cat->result.recognized, 
                       cat->result.total);
                
                if (show_bars) {
                    print_progress_bar(cat->result.recognition_percent, 8, false);
                    printf(" ");
                    print_progress_bar(cat->result.functional_percent, 8, false);
                } else {
                    printf("(%5.1f%% / %5.1f%%)", 
                           cat->result.recognition_percent,
                           cat->result.functional_percent);
                }
                printf(" |\n");
            }
            
            printf("+----------+--------------------------------------------------------------+\n");
            printf("| OVERALL  | %3zu/%-3zu ", 
                   arch->overall.recognized, 
                   arch->overall.total);
            
            if (show_bars) {
                print_progress_bar(arch->overall.recognition_percent, 8, false);
                printf(" ");
                print_progress_bar(arch->overall.functional_percent, 8, false);
            } else {
                printf("(%5.1f%% / %5.1f%%)", 
                       arch->overall.recognition_percent,
                       arch->overall.functional_percent);
            }
            printf(" |\n");
            
            if (i < arch_count - 1) {
                printf("+==============================================================================+\n");
            }
        }
        printf("+==============================================================================+\n");
    }
    
    printf("\n    Legend: ");
    if (show_bars && !compact) {
        printf("# = ~12.5%% per char, . = remaining\n");
    } else {
        printf("Recognition%% / Functional%%\n");
    }
    printf("    Recognition: Instruction parsing successful\n");
    printf("    Functional: Instruction encoding successful\n\n");
}

void print_instruction_completeness_report_with_config(arch_test_result_t *results, size_t arch_count, const report_config_t *config) {
    if (config && (config->compact_mode || config->max_line_width <= 80)) {
        print_instruction_completeness_report_compact(results, arch_count, config);
    } else {
        print_instruction_completeness_report(results, arch_count);
    }
}

void run_instruction_completeness_tests_with_config(const report_config_t *config) {
    printf("🚀 Starting STAS Instruction Set Completeness Analysis...\n");
    
    // Determine which architectures to test
    size_t test_arch_count = 0;
    size_t start_idx = 0;
    size_t end_idx = architecture_count;
    
    if (config && config->target_arch) {
        // Find the specific architecture
        for (size_t i = 0; i < architecture_count; i++) {
            if (strcmp(architectures[i].arch_name, config->target_arch) == 0) {
                start_idx = i;
                end_idx = i + 1;
                test_arch_count = 1;
                break;
            }
        }
        if (test_arch_count == 0) {
            printf("❌ Error: Architecture '%s' not found!\n", config->target_arch);
            return;
        }
        printf("🎯 Testing only %s architecture...\n", config->target_arch);
    } else {
        test_arch_count = architecture_count;
        printf("📊 Testing all %zu architectures...\n", architecture_count);
    }
    
    arch_test_result_t *results = malloc(test_arch_count * sizeof(arch_test_result_t));
    
    for (size_t i = start_idx, result_idx = 0; i < end_idx; i++, result_idx++) {
        const arch_instruction_set_t *arch = &architectures[i];
        arch_test_result_t *result = &results[result_idx];
        
        result->arch_name = arch->arch_name;
        result->category_count = arch->category_count;
        result->category_results = malloc(arch->category_count * sizeof(category_result_t));
        
        // Initialize overall counters
        result->overall.total = 0;
        result->overall.recognized = 0;
        result->overall.functional = 0;
        
        printf("📋 Testing %s instruction set...\n", arch->arch_name);
        
        for (size_t j = 0; j < arch->category_count; j++) {
            const instruction_category_t *category = &arch->categories[j];
            category_result_t *cat_result = &result->category_results[j];
            
            cat_result->category_name = category->category_name;
            cat_result->result = test_instruction_category_verbose(arch->arch_name, category, 
                                                                 config ? config->verbose_mode : false);
            
            // Add to overall totals
            result->overall.total += cat_result->result.total;
            result->overall.recognized += cat_result->result.recognized;
            result->overall.functional += cat_result->result.functional;
            
            printf("   ✓ %s: %zu/%zu recognized (%.1f%%), %zu/%zu functional (%.1f%%)\n",
                   category->category_name,
                   cat_result->result.recognized, cat_result->result.total, cat_result->result.recognition_percent,
                   cat_result->result.functional, cat_result->result.total, cat_result->result.functional_percent);
        }
        
        // Calculate overall percentages
        result->overall.recognition_percent = result->overall.total > 0 ? 
            (double)result->overall.recognized / result->overall.total * 100.0 : 0.0;
        result->overall.functional_percent = result->overall.total > 0 ? 
            (double)result->overall.functional / result->overall.total * 100.0 : 0.0;
    }
    
    print_instruction_completeness_report_with_config(results, test_arch_count, config);
    
    // Cleanup
    for (size_t i = 0; i < test_arch_count; i++) {
        free(results[i].category_results);
    }
    free(results);
    
    printf("✅ Instruction set completeness analysis completed!\n");
}

void print_instruction_completeness_report(arch_test_result_t *results, size_t arch_count) {
    printf("\n");
    printf("+==============================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================+\n");
    printf("|                                                                   STAS INSTRUCTION SET COMPLETENESS REPORT                                                                                  |\n");
    printf("+==============================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================+\n");
    
    for (size_t i = 0; i < arch_count; i++) {
        arch_test_result_t *arch = &results[i];
        
        printf("| %-12s | Category Breakdown                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                     |\n", arch->arch_name);
        printf("+--------------+-----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------+\n");
        
        for (size_t j = 0; j < arch->category_count; j++) {
            category_result_t *cat = &arch->category_results[j];
            printf("|              | %-18s | Total: %3zu | Recognized: %3zu (%5.1f%%) | Functional: %3zu (%5.1f%%) | Recognition: ", 
                   cat->category_name, 
                   cat->result.total,
                   cat->result.recognized, 
                   cat->result.recognition_percent,
                   cat->result.functional, 
                   cat->result.functional_percent);
            
            // Recognition progress bar
            int rec_bars = (int)(cat->result.recognition_percent / 5);
            printf("[");
            for (int k = 0; k < 20; k++) {
                if (k < rec_bars) printf("#");
                else printf(".");
            }
            printf("] Functional: [");
            
            // Functional progress bar
            int func_bars = (int)(cat->result.functional_percent / 5);
            for (int k = 0; k < 20; k++) {
                if (k < func_bars) printf("#");
                else printf(".");
            }
            printf("]\t|\n");
        }
        
        printf("+--------------+-----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------+\n");
        printf("| OVERALL      | %-18s | Total: %3zu | Recognized: %3zu (%5.1f%%) | Functional: %3zu (%5.1f%%) | Recognition: ", 
               "Summary",
               arch->overall.total,
               arch->overall.recognized, 
               arch->overall.recognition_percent,
               arch->overall.functional, 
               arch->overall.functional_percent);
        
        // Overall recognition progress bar
        int overall_rec_bars = (int)(arch->overall.recognition_percent / 5);
        printf("[");
        for (int k = 0; k < 20; k++) {
            if (k < overall_rec_bars) printf("#");
            else printf(".");
        }
        printf("] Functional: [");
        
        // Overall functional progress bar
        int overall_func_bars = (int)(arch->overall.functional_percent / 5);
        for (int k = 0; k < 20; k++) {
            if (k < overall_func_bars) printf("#");
            else printf(".");
        }
        printf("]\t|\n");
        
        if (i < arch_count - 1) {
            printf("+==============================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================+\n");
        }
    }
    
    printf("+==============================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================+\n");
    
    printf("\n    Legend: # = 5%% completion per char, . = remaining\n");
    printf("    Recognition: Instruction parsing successful\n");
    printf("    Functional: Instruction encoding successful\n\n");
}

void run_instruction_completeness_tests(void) {
    // Use compact format by default
    report_config_t config = {
        .max_line_width = 80,
        .compact_mode = false,  // Standard format within 80 chars
        .show_progress_bars = true
    };
    run_instruction_completeness_tests_with_config(&config);
}
