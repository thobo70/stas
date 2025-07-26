#include "arch_x86_64.h"

// ========================================
// x86_64 INSTRUCTION SET DEFINITIONS
// Based on Intel 64 and IA-32 Architectures Software Developer's Manual
// ========================================

// Data Movement Instructions (comprehensive operand support)
static const instruction_def_t x86_64_data_movement[] = {
    // Basic move instructions
    {"mov", "Data Movement", 2, false},        // r/m8,r8 | r/m16,r16 | r/m32,r32 | r/m64,r64 | r8,r/m8 | r16,r/m16 | r32,r/m32 | r64,r/m64 | r/m8,imm8 | r/m16,imm16 | r/m32,imm32 | r/m64,imm32 | r8,imm8 | r16,imm16 | r32,imm32 | r64,imm64
    {"movq", "Data Movement", 2, false},       // r/m64,r64 | r64,r/m64 | r/m64,imm32 | r64,imm64
    {"movl", "Data Movement", 2, false},       // r/m32,r32 | r32,r/m32 | r/m32,imm32 | r32,imm32
    {"movw", "Data Movement", 2, false},       // r/m16,r16 | r16,r/m16 | r/m16,imm16 | r16,imm16
    {"movb", "Data Movement", 2, false},       // r/m8,r8 | r8,r/m8 | r/m8,imm8 | r8,imm8
    
    // Move with zero extension
    {"movzx", "Data Movement", 2, false},      // r16,r/m8 | r32,r/m8 | r32,r/m16
    {"movzb", "Data Movement", 2, false},      // r32,r/m8 (move byte, zero-extend to 32-bit)
    {"movzw", "Data Movement", 2, false},      // r32,r/m16 (move word, zero-extend to 32-bit)
    {"movzbl", "Data Movement", 2, false},     // r32,r/m8 (move byte, zero-extend to 32-bit)
    {"movzwl", "Data Movement", 2, false},     // r32,r/m16 (move word, zero-extend to 32-bit)
    {"movzbq", "Data Movement", 2, false},     // r64,r/m8 (move byte, zero-extend to 64-bit)
    {"movzwq", "Data Movement", 2, false},     // r64,r/m16 (move word, zero-extend to 64-bit)
    
    // Move with sign extension
    {"movsx", "Data Movement", 2, false},      // r16,r/m8 | r32,r/m8 | r32,r/m16
    {"movsb", "Data Movement", 2, false},      // r32,r/m8 (move byte, sign-extend to 32-bit)
    {"movsw", "Data Movement", 2, false},      // r32,r/m16 (move word, sign-extend to 32-bit)
    {"movsbl", "Data Movement", 2, false},     // r32,r/m8 (move byte, sign-extend to 32-bit)
    {"movswl", "Data Movement", 2, false},     // r32,r/m16 (move word, sign-extend to 32-bit)
    {"movsbq", "Data Movement", 2, false},     // r64,r/m8 (move byte, sign-extend to 64-bit)
    {"movswq", "Data Movement", 2, false},     // r64,r/m16 (move word, sign-extend to 64-bit)
    {"movsxd", "Data Movement", 2, false},     // r64,r/m32 (move doubleword, sign-extend to 64-bit)
    
    // Load effective address
    {"lea", "Data Movement", 2, false},        // r16,m | r32,m | r64,m
    {"leaq", "Data Movement", 2, false},       // r64,m
    
    // Stack operations
    {"push", "Data Movement", 1, false},       // r/m16 | r/m32 | r/m64 | imm8 | imm16 | imm32
    {"pushq", "Data Movement", 1, false},      // r/m64 | imm8 | imm32
    {"pushw", "Data Movement", 1, false},      // r/m16 | imm8 | imm16
    {"pop", "Data Movement", 1, false},        // r/m16 | r/m32 | r/m64
    {"popq", "Data Movement", 1, false},       // r/m64
    {"popw", "Data Movement", 1, false},       // r/m16
    
    // Exchange operations
    {"xchg", "Data Movement", 2, false},       // r8,r/m8 | r/m8,r8 | r16,r/m16 | r/m16,r16 | r32,r/m32 | r/m32,r32 | r64,r/m64 | r/m64,r64
    {"xchgq", "Data Movement", 2, false},      // r64,r/m64 | r/m64,r64
    {"cmpxchg", "Data Movement", 2, false},    // r/m8,r8 | r/m16,r16 | r/m32,r32 | r/m64,r64
    {"cmpxchg8b", "Data Movement", 1, false},  // m64
    {"cmpxchg16b", "Data Movement", 1, false}, // m128
    {"xadd", "Data Movement", 2, false},       // r/m8,r8 | r/m16,r16 | r/m32,r32 | r/m64,r64
    {"bswap", "Data Movement", 1, false}       // r32 | r64
};

// Arithmetic Instructions (comprehensive operand support)
static const instruction_def_t x86_64_arithmetic[] = {
    // Basic arithmetic
    {"add", "Arithmetic", 2, false},           // r/m8,r8 | r/m16,r16 | r/m32,r32 | r/m64,r64 | r8,r/m8 | r16,r/m16 | r32,r/m32 | r64,r/m64 | r/m8,imm8 | r/m16,imm16 | r/m32,imm32 | r/m64,imm32 | AL,imm8 | AX,imm16 | EAX,imm32 | RAX,imm32
    {"addq", "Arithmetic", 2, false},          // r/m64,r64 | r64,r/m64 | r/m64,imm32 | RAX,imm32
    {"addl", "Arithmetic", 2, false},          // r/m32,r32 | r32,r/m32 | r/m32,imm32 | EAX,imm32
    {"addw", "Arithmetic", 2, false},          // r/m16,r16 | r16,r/m16 | r/m16,imm16 | AX,imm16
    {"addb", "Arithmetic", 2, false},          // r/m8,r8 | r8,r/m8 | r/m8,imm8 | AL,imm8
    {"adc", "Arithmetic", 2, false},           // r/m8,r8 | r/m16,r16 | r/m32,r32 | r/m64,r64 | r8,r/m8 | r16,r/m16 | r32,r/m32 | r64,r/m64 | r/m8,imm8 | r/m16,imm16 | r/m32,imm32 | r/m64,imm32 | AL,imm8 | AX,imm16 | EAX,imm32 | RAX,imm32
    {"adcq", "Arithmetic", 2, false},          // r/m64,r64 | r64,r/m64 | r/m64,imm32 | RAX,imm32
    {"adcl", "Arithmetic", 2, false},          // r/m32,r32 | r32,r/m32 | r/m32,imm32 | EAX,imm32
    {"adcw", "Arithmetic", 2, false},          // r/m16,r16 | r16,r/m16 | r/m16,imm16 | AX,imm16
    {"adcb", "Arithmetic", 2, false},          // r/m8,r8 | r8,r/m8 | r/m8,imm8 | AL,imm8
    
    {"sub", "Arithmetic", 2, false},           // r/m8,r8 | r/m16,r16 | r/m32,r32 | r/m64,r64 | r8,r/m8 | r16,r/m16 | r32,r/m32 | r64,r/m64 | r/m8,imm8 | r/m16,imm16 | r/m32,imm32 | r/m64,imm32 | AL,imm8 | AX,imm16 | EAX,imm32 | RAX,imm32
    {"subq", "Arithmetic", 2, false},          // r/m64,r64 | r64,r/m64 | r/m64,imm32 | RAX,imm32
    {"subl", "Arithmetic", 2, false},          // r/m32,r32 | r32,r/m32 | r/m32,imm32 | EAX,imm32
    {"subw", "Arithmetic", 2, false},          // r/m16,r16 | r16,r/m16 | r/m16,imm16 | AX,imm16
    {"subb", "Arithmetic", 2, false},          // r/m8,r8 | r8,r/m8 | r/m8,imm8 | AL,imm8
    {"sbb", "Arithmetic", 2, false},           // r/m8,r8 | r/m16,r16 | r/m32,r32 | r/m64,r64 | r8,r/m8 | r16,r/m16 | r32,r/m32 | r64,r/m64 | r/m8,imm8 | r/m16,imm16 | r/m32,imm32 | r/m64,imm32 | AL,imm8 | AX,imm16 | EAX,imm32 | RAX,imm32
    {"sbbq", "Arithmetic", 2, false},          // r/m64,r64 | r64,r/m64 | r/m64,imm32 | RAX,imm32
    {"sbbl", "Arithmetic", 2, false},          // r/m32,r32 | r32,r/m32 | r/m32,imm32 | EAX,imm32
    {"sbbw", "Arithmetic", 2, false},          // r/m16,r16 | r16,r/m16 | r/m16,imm16 | AX,imm16
    {"sbbb", "Arithmetic", 2, false},          // r/m8,r8 | r8,r/m8 | r/m8,imm8 | AL,imm8
    
    // Multiplication
    {"mul", "Arithmetic", 1, false},           // r/m8 | r/m16 | r/m32 | r/m64
    {"mulq", "Arithmetic", 1, false},          // r/m64
    {"mull", "Arithmetic", 1, false},          // r/m32
    {"mulw", "Arithmetic", 1, false},          // r/m16
    {"mulb", "Arithmetic", 1, false},          // r/m8
    {"imul", "Arithmetic", 1, false},          // r/m8 | r/m16 | r/m32 | r/m64
    {"imul", "Arithmetic", 2, false},          // r16,r/m16 | r32,r/m32 | r64,r/m64
    {"imul", "Arithmetic", 3, false},          // r16,r/m16,imm8 | r16,r/m16,imm16 | r32,r/m32,imm8 | r32,r/m32,imm32 | r64,r/m64,imm8 | r64,r/m64,imm32
    {"imulq", "Arithmetic", 1, false},         // r/m64
    {"imulq", "Arithmetic", 2, false},         // r64,r/m64
    {"imulq", "Arithmetic", 3, false},         // r64,r/m64,imm8 | r64,r/m64,imm32
    {"imull", "Arithmetic", 1, false},         // r/m32
    {"imull", "Arithmetic", 2, false},         // r32,r/m32
    {"imull", "Arithmetic", 3, false},         // r32,r/m32,imm8 | r32,r/m32,imm32
    {"imulw", "Arithmetic", 1, false},         // r/m16
    {"imulw", "Arithmetic", 2, false},         // r16,r/m16
    {"imulw", "Arithmetic", 3, false},         // r16,r/m16,imm8 | r16,r/m16,imm16
    {"imulb", "Arithmetic", 1, false},         // r/m8
    
    // Division
    {"div", "Arithmetic", 1, false},           // r/m8 | r/m16 | r/m32 | r/m64
    {"divq", "Arithmetic", 1, false},          // r/m64
    {"divl", "Arithmetic", 1, false},          // r/m32
    {"divw", "Arithmetic", 1, false},          // r/m16
    {"divb", "Arithmetic", 1, false},          // r/m8
    {"idiv", "Arithmetic", 1, false},          // r/m8 | r/m16 | r/m32 | r/m64
    {"idivq", "Arithmetic", 1, false},         // r/m64
    {"idivl", "Arithmetic", 1, false},         // r/m32
    {"idivw", "Arithmetic", 1, false},         // r/m16
    {"idivb", "Arithmetic", 1, false},         // r/m8
    
    // Increment/Decrement
    {"inc", "Arithmetic", 1, false},           // r/m8 | r/m16 | r/m32 | r/m64
    {"incq", "Arithmetic", 1, false},          // r/m64
    {"incl", "Arithmetic", 1, false},          // r/m32
    {"incw", "Arithmetic", 1, false},          // r/m16
    {"incb", "Arithmetic", 1, false},          // r/m8
    {"dec", "Arithmetic", 1, false},           // r/m8 | r/m16 | r/m32 | r/m64
    {"decq", "Arithmetic", 1, false},          // r/m64
    {"decl", "Arithmetic", 1, false},          // r/m32
    {"decw", "Arithmetic", 1, false},          // r/m16
    {"decb", "Arithmetic", 1, false},          // r/m8
    
    // Negation
    {"neg", "Arithmetic", 1, false},           // r/m8 | r/m16 | r/m32 | r/m64
    {"negq", "Arithmetic", 1, false},          // r/m64
    {"negl", "Arithmetic", 1, false},          // r/m32
    {"negw", "Arithmetic", 1, false},          // r/m16
    {"negb", "Arithmetic", 1, false},          // r/m8
    
    // Comparison
    {"cmp", "Arithmetic", 2, false},           // r/m8,r8 | r/m16,r16 | r/m32,r32 | r/m64,r64 | r8,r/m8 | r16,r/m16 | r32,r/m32 | r64,r/m64 | r/m8,imm8 | r/m16,imm16 | r/m32,imm32 | r/m64,imm32 | AL,imm8 | AX,imm16 | EAX,imm32 | RAX,imm32
    {"cmpq", "Arithmetic", 2, false},          // r/m64,r64 | r64,r/m64 | r/m64,imm32 | RAX,imm32
    {"cmpl", "Arithmetic", 2, false},          // r/m32,r32 | r32,r/m32 | r/m32,imm32 | EAX,imm32
    {"cmpw", "Arithmetic", 2, false},          // r/m16,r16 | r16,r/m16 | r/m16,imm16 | AX,imm16
    {"cmpb", "Arithmetic", 2, false}           // r/m8,r8 | r8,r/m8 | r/m8,imm8 | AL,imm8
};

// Logical Instructions (comprehensive operand support)
static const instruction_def_t x86_64_logical[] = {
    {"and", "Logical", 2, false},              // r/m8,r8 | r/m16,r16 | r/m32,r32 | r/m64,r64 | r8,r/m8 | r16,r/m16 | r32,r/m32 | r64,r/m64 | r/m8,imm8 | r/m16,imm16 | r/m32,imm32 | r/m64,imm32 | AL,imm8 | AX,imm16 | EAX,imm32 | RAX,imm32
    {"andq", "Logical", 2, false},             // r/m64,r64 | r64,r/m64 | r/m64,imm32 | RAX,imm32
    {"andl", "Logical", 2, false},             // r/m32,r32 | r32,r/m32 | r/m32,imm32 | EAX,imm32
    {"andw", "Logical", 2, false},             // r/m16,r16 | r16,r/m16 | r/m16,imm16 | AX,imm16
    {"andb", "Logical", 2, false},             // r/m8,r8 | r8,r/m8 | r/m8,imm8 | AL,imm8
    {"or", "Logical", 2, false},               // r/m8,r8 | r/m16,r16 | r/m32,r32 | r/m64,r64 | r8,r/m8 | r16,r/m16 | r32,r/m32 | r64,r/m64 | r/m8,imm8 | r/m16,imm16 | r/m32,imm32 | r/m64,imm32 | AL,imm8 | AX,imm16 | EAX,imm32 | RAX,imm32
    {"orq", "Logical", 2, false},              // r/m64,r64 | r64,r/m64 | r/m64,imm32 | RAX,imm32
    {"orl", "Logical", 2, false},              // r/m32,r32 | r32,r/m32 | r/m32,imm32 | EAX,imm32
    {"orw", "Logical", 2, false},              // r/m16,r16 | r16,r/m16 | r/m16,imm16 | AX,imm16
    {"orb", "Logical", 2, false},              // r/m8,r8 | r8,r/m8 | r/m8,imm8 | AL,imm8
    {"xor", "Logical", 2, false},              // r/m8,r8 | r/m16,r16 | r/m32,r32 | r/m64,r64 | r8,r/m8 | r16,r/m16 | r32,r/m32 | r64,r/m64 | r/m8,imm8 | r/m16,imm16 | r/m32,imm32 | r/m64,imm32 | AL,imm8 | AX,imm16 | EAX,imm32 | RAX,imm32
    {"xorq", "Logical", 2, false},             // r/m64,r64 | r64,r/m64 | r/m64,imm32 | RAX,imm32
    {"xorl", "Logical", 2, false},             // r/m32,r32 | r32,r/m32 | r/m32,imm32 | EAX,imm32
    {"xorw", "Logical", 2, false},             // r/m16,r16 | r16,r/m16 | r/m16,imm16 | AX,imm16
    {"xorb", "Logical", 2, false},             // r/m8,r8 | r8,r/m8 | r/m8,imm8 | AL,imm8
    {"not", "Logical", 1, false},              // r/m8 | r/m16 | r/m32 | r/m64
    {"notq", "Logical", 1, false},             // r/m64
    {"notl", "Logical", 1, false},             // r/m32
    {"notw", "Logical", 1, false},             // r/m16
    {"notb", "Logical", 1, false},             // r/m8
    {"test", "Logical", 2, false},             // r/m8,r8 | r/m16,r16 | r/m32,r32 | r/m64,r64 | r/m8,imm8 | r/m16,imm16 | r/m32,imm32 | r/m64,imm32 | AL,imm8 | AX,imm16 | EAX,imm32 | RAX,imm32
    {"testq", "Logical", 2, false},            // r/m64,r64 | r/m64,imm32 | RAX,imm32
    {"testl", "Logical", 2, false},            // r/m32,r32 | r/m32,imm32 | EAX,imm32
    {"testw", "Logical", 2, false},            // r/m16,r16 | r/m16,imm16 | AX,imm16
    {"testb", "Logical", 2, false}             // r/m8,r8 | r/m8,imm8 | AL,imm8
};

// Shift and Rotate Instructions (comprehensive operand support)
static const instruction_def_t x86_64_shift[] = {
    // Shift arithmetic left (same as shl)
    {"sal", "Shift", 2, false},                // r/m8,1 | r/m8,CL | r/m8,imm8 | r/m16,1 | r/m16,CL | r/m16,imm8 | r/m32,1 | r/m32,CL | r/m32,imm8 | r/m64,1 | r/m64,CL | r/m64,imm8
    {"salq", "Shift", 2, false},               // r/m64,1 | r/m64,CL | r/m64,imm8
    {"sall", "Shift", 2, false},               // r/m32,1 | r/m32,CL | r/m32,imm8
    {"salw", "Shift", 2, false},               // r/m16,1 | r/m16,CL | r/m16,imm8
    {"salb", "Shift", 2, false},               // r/m8,1 | r/m8,CL | r/m8,imm8
    // Shift logical left
    {"shl", "Shift", 2, false},                // r/m8,1 | r/m8,CL | r/m8,imm8 | r/m16,1 | r/m16,CL | r/m16,imm8 | r/m32,1 | r/m32,CL | r/m32,imm8 | r/m64,1 | r/m64,CL | r/m64,imm8
    {"shlq", "Shift", 2, false},               // r/m64,1 | r/m64,CL | r/m64,imm8
    {"shll", "Shift", 2, false},               // r/m32,1 | r/m32,CL | r/m32,imm8
    {"shlw", "Shift", 2, false},               // r/m16,1 | r/m16,CL | r/m16,imm8
    {"shlb", "Shift", 2, false},               // r/m8,1 | r/m8,CL | r/m8,imm8
    // Shift arithmetic right
    {"sar", "Shift", 2, false},                // r/m8,1 | r/m8,CL | r/m8,imm8 | r/m16,1 | r/m16,CL | r/m16,imm8 | r/m32,1 | r/m32,CL | r/m32,imm8 | r/m64,1 | r/m64,CL | r/m64,imm8
    {"sarq", "Shift", 2, false},               // r/m64,1 | r/m64,CL | r/m64,imm8
    {"sarl", "Shift", 2, false},               // r/m32,1 | r/m32,CL | r/m32,imm8
    {"sarw", "Shift", 2, false},               // r/m16,1 | r/m16,CL | r/m16,imm8
    {"sarb", "Shift", 2, false},               // r/m8,1 | r/m8,CL | r/m8,imm8
    // Shift logical right
    {"shr", "Shift", 2, false},                // r/m8,1 | r/m8,CL | r/m8,imm8 | r/m16,1 | r/m16,CL | r/m16,imm8 | r/m32,1 | r/m32,CL | r/m32,imm8 | r/m64,1 | r/m64,CL | r/m64,imm8
    {"shrq", "Shift", 2, false},               // r/m64,1 | r/m64,CL | r/m64,imm8
    {"shrl", "Shift", 2, false},               // r/m32,1 | r/m32,CL | r/m32,imm8
    {"shrw", "Shift", 2, false},               // r/m16,1 | r/m16,CL | r/m16,imm8
    {"shrb", "Shift", 2, false},               // r/m8,1 | r/m8,CL | r/m8,imm8
    // Rotate left
    {"rol", "Shift", 2, false},                // r/m8,1 | r/m8,CL | r/m8,imm8 | r/m16,1 | r/m16,CL | r/m16,imm8 | r/m32,1 | r/m32,CL | r/m32,imm8 | r/m64,1 | r/m64,CL | r/m64,imm8
    {"rolq", "Shift", 2, false},               // r/m64,1 | r/m64,CL | r/m64,imm8
    {"roll", "Shift", 2, false},               // r/m32,1 | r/m32,CL | r/m32,imm8
    {"rolw", "Shift", 2, false},               // r/m16,1 | r/m16,CL | r/m16,imm8
    {"rolb", "Shift", 2, false},               // r/m8,1 | r/m8,CL | r/m8,imm8
    // Rotate right
    {"ror", "Shift", 2, false},                // r/m8,1 | r/m8,CL | r/m8,imm8 | r/m16,1 | r/m16,CL | r/m16,imm8 | r/m32,1 | r/m32,CL | r/m32,imm8 | r/m64,1 | r/m64,CL | r/m64,imm8
    {"rorq", "Shift", 2, false},               // r/m64,1 | r/m64,CL | r/m64,imm8
    {"rorl", "Shift", 2, false},               // r/m32,1 | r/m32,CL | r/m32,imm8
    {"rorw", "Shift", 2, false},               // r/m16,1 | r/m16,CL | r/m16,imm8
    {"rorb", "Shift", 2, false},               // r/m8,1 | r/m8,CL | r/m8,imm8
    // Rotate through carry left
    {"rcl", "Shift", 2, false},                // r/m8,1 | r/m8,CL | r/m8,imm8 | r/m16,1 | r/m16,CL | r/m16,imm8 | r/m32,1 | r/m32,CL | r/m32,imm8 | r/m64,1 | r/m64,CL | r/m64,imm8
    {"rclq", "Shift", 2, false},               // r/m64,1 | r/m64,CL | r/m64,imm8
    {"rcll", "Shift", 2, false},               // r/m32,1 | r/m32,CL | r/m32,imm8
    {"rclw", "Shift", 2, false},               // r/m16,1 | r/m16,CL | r/m16,imm8
    {"rclb", "Shift", 2, false},               // r/m8,1 | r/m8,CL | r/m8,imm8
    // Rotate through carry right
    {"rcr", "Shift", 2, false},                // r/m8,1 | r/m8,CL | r/m8,imm8 | r/m16,1 | r/m16,CL | r/m16,imm8 | r/m32,1 | r/m32,CL | r/m32,imm8 | r/m64,1 | r/m64,CL | r/m64,imm8
    {"rcrq", "Shift", 2, false},               // r/m64,1 | r/m64,CL | r/m64,imm8
    {"rcrl", "Shift", 2, false},               // r/m32,1 | r/m32,CL | r/m32,imm8
    {"rcrw", "Shift", 2, false},               // r/m16,1 | r/m16,CL | r/m16,imm8
    {"rcrb", "Shift", 2, false}                // r/m8,1 | r/m8,CL | r/m8,imm8
};

// Bit Manipulation Instructions (BMI/BMI2 and other bit operations)
static const instruction_def_t x86_64_bit_manipulation[] = {
    // Bit test instructions
    {"bt", "Bit Manipulation", 2, false},      // r/m16,r16 | r/m32,r32 | r/m64,r64 | r/m16,imm8 | r/m32,imm8 | r/m64,imm8
    {"btq", "Bit Manipulation", 2, false},     // r/m64,r64 | r/m64,imm8
    {"btl", "Bit Manipulation", 2, false},     // r/m32,r32 | r/m32,imm8
    {"btw", "Bit Manipulation", 2, false},     // r/m16,r16 | r/m16,imm8
    {"btc", "Bit Manipulation", 2, false},     // r/m16,r16 | r/m32,r32 | r/m64,r64 | r/m16,imm8 | r/m32,imm8 | r/m64,imm8
    {"btcq", "Bit Manipulation", 2, false},    // r/m64,r64 | r/m64,imm8
    {"btcl", "Bit Manipulation", 2, false},    // r/m32,r32 | r/m32,imm8
    {"btcw", "Bit Manipulation", 2, false},    // r/m16,r16 | r/m16,imm8
    {"btr", "Bit Manipulation", 2, false},     // r/m16,r16 | r/m32,r32 | r/m64,r64 | r/m16,imm8 | r/m32,imm8 | r/m64,imm8
    {"btrq", "Bit Manipulation", 2, false},    // r/m64,r64 | r/m64,imm8
    {"btrl", "Bit Manipulation", 2, false},    // r/m32,r32 | r/m32,imm8
    {"btrw", "Bit Manipulation", 2, false},    // r/m16,r16 | r/m16,imm8
    {"bts", "Bit Manipulation", 2, false},     // r/m16,r16 | r/m32,r32 | r/m64,r64 | r/m16,imm8 | r/m32,imm8 | r/m64,imm8
    {"btsq", "Bit Manipulation", 2, false},    // r/m64,r64 | r/m64,imm8
    {"btsl", "Bit Manipulation", 2, false},    // r/m32,r32 | r/m32,imm8
    {"btsw", "Bit Manipulation", 2, false},    // r/m16,r16 | r/m16,imm8
    
    // Bit scan instructions
    {"bsf", "Bit Manipulation", 2, false},     // r16,r/m16 | r32,r/m32 | r64,r/m64
    {"bsfq", "Bit Manipulation", 2, false},    // r64,r/m64
    {"bsfl", "Bit Manipulation", 2, false},    // r32,r/m32
    {"bsfw", "Bit Manipulation", 2, false},    // r16,r/m16
    {"bsr", "Bit Manipulation", 2, false},     // r16,r/m16 | r32,r/m32 | r64,r/m64
    {"bsrq", "Bit Manipulation", 2, false},    // r64,r/m64
    {"bsrl", "Bit Manipulation", 2, false},    // r32,r/m32
    {"bsrw", "Bit Manipulation", 2, false},    // r16,r/m16
    
    // BMI/BMI2 instructions
    {"andn", "Bit Manipulation", 3, true},     // r32,r32,r/m32 | r64,r64,r/m64
    {"andnq", "Bit Manipulation", 3, true},    // r64,r64,r/m64
    {"andnl", "Bit Manipulation", 3, true},    // r32,r32,r/m32
    {"bextr", "Bit Manipulation", 3, true},    // r32,r/m32,r32 | r64,r/m64,r64
    {"bextrq", "Bit Manipulation", 3, true},   // r64,r/m64,r64
    {"bextrl", "Bit Manipulation", 3, true},   // r32,r/m32,r32
    {"blsi", "Bit Manipulation", 2, true},     // r32,r/m32 | r64,r/m64
    {"blsiq", "Bit Manipulation", 2, true},    // r64,r/m64
    {"blsil", "Bit Manipulation", 2, true},    // r32,r/m32
    {"blsmsk", "Bit Manipulation", 2, true},   // r32,r/m32 | r64,r/m64
    {"blsmskq", "Bit Manipulation", 2, true},  // r64,r/m64
    {"blsmskl", "Bit Manipulation", 2, true},  // r32,r/m32
    {"blsr", "Bit Manipulation", 2, true},     // r32,r/m32 | r64,r/m64
    {"blsrq", "Bit Manipulation", 2, true},    // r64,r/m64
    {"blsrl", "Bit Manipulation", 2, true},    // r32,r/m32
    {"bzhi", "Bit Manipulation", 3, true},     // r32,r/m32,r32 | r64,r/m64,r64
    {"bzhiq", "Bit Manipulation", 3, true},    // r64,r/m64,r64
    {"bzhil", "Bit Manipulation", 3, true},    // r32,r/m32,r32
    {"lzcnt", "Bit Manipulation", 2, true},    // r16,r/m16 | r32,r/m32 | r64,r/m64
    {"lzcntq", "Bit Manipulation", 2, true},   // r64,r/m64
    {"lzcntl", "Bit Manipulation", 2, true},   // r32,r/m32
    {"lzcntw", "Bit Manipulation", 2, true},   // r16,r/m16
    {"pdep", "Bit Manipulation", 3, true},     // r32,r32,r/m32 | r64,r64,r/m64
    {"pdepq", "Bit Manipulation", 3, true},    // r64,r64,r/m64
    {"pdepl", "Bit Manipulation", 3, true},    // r32,r32,r/m32
    {"pext", "Bit Manipulation", 3, true},     // r32,r32,r/m32 | r64,r64,r/m64
    {"pextq", "Bit Manipulation", 3, true},    // r64,r64,r/m64
    {"pextl", "Bit Manipulation", 3, true},    // r32,r32,r/m32
    {"popcnt", "Bit Manipulation", 2, true},   // r16,r/m16 | r32,r/m32 | r64,r/m64
    {"popcntq", "Bit Manipulation", 2, true},  // r64,r/m64
    {"popcntl", "Bit Manipulation", 2, true},  // r32,r/m32
    {"popcntw", "Bit Manipulation", 2, true},  // r16,r/m16
    {"rorx", "Bit Manipulation", 3, true},     // r32,r/m32,imm8 | r64,r/m64,imm8
    {"rorxq", "Bit Manipulation", 3, true},    // r64,r/m64,imm8
    {"rorxl", "Bit Manipulation", 3, true},    // r32,r/m32,imm8
    {"sarx", "Bit Manipulation", 3, true},     // r32,r/m32,r32 | r64,r/m64,r64
    {"sarxq", "Bit Manipulation", 3, true},    // r64,r/m64,r64
    {"sarxl", "Bit Manipulation", 3, true},    // r32,r/m32,r32
    {"shlx", "Bit Manipulation", 3, true},     // r32,r/m32,r32 | r64,r/m64,r64
    {"shlxq", "Bit Manipulation", 3, true},    // r64,r/m64,r64
    {"shlxl", "Bit Manipulation", 3, true},    // r32,r/m32,r32
    {"shrx", "Bit Manipulation", 3, true},     // r32,r/m32,r32 | r64,r/m64,r64
    {"shrxq", "Bit Manipulation", 3, true},    // r64,r/m64,r64
    {"shrxl", "Bit Manipulation", 3, true},    // r32,r/m32,r32
    {"tzcnt", "Bit Manipulation", 2, true},    // r16,r/m16 | r32,r/m32 | r64,r/m64
    {"tzcntq", "Bit Manipulation", 2, true},   // r64,r/m64
    {"tzcntl", "Bit Manipulation", 2, true},   // r32,r/m32
    {"tzcntw", "Bit Manipulation", 2, true}    // r16,r/m16
};

// Control Transfer Instructions (comprehensive jumps, calls, returns)
static const instruction_def_t x86_64_control_transfer[] = {
    // Unconditional jumps
    {"jmp", "Control Transfer", 1, false},     // rel8 | rel16 | rel32 | r/m16 | r/m32 | r/m64 | ptr16:16 | ptr16:32
    {"jmpq", "Control Transfer", 1, false},    // rel32 | r/m64
    {"jmpl", "Control Transfer", 1, false},    // rel32 | r/m32
    {"jmpw", "Control Transfer", 1, false},    // rel16 | r/m16
    
    // Conditional jumps (short and near)
    {"ja", "Control Transfer", 1, false},      // rel8 | rel16 | rel32
    {"jae", "Control Transfer", 1, false},     // rel8 | rel16 | rel32 
    {"jb", "Control Transfer", 1, false},      // rel8 | rel16 | rel32
    {"jbe", "Control Transfer", 1, false},     // rel8 | rel16 | rel32
    {"jc", "Control Transfer", 1, false},      // rel8 | rel16 | rel32
    {"je", "Control Transfer", 1, false},      // rel8 | rel16 | rel32
    {"jz", "Control Transfer", 1, false},      // rel8 | rel16 | rel32 (alias for je)
    {"jg", "Control Transfer", 1, false},      // rel8 | rel16 | rel32
    {"jge", "Control Transfer", 1, false},     // rel8 | rel16 | rel32
    {"jl", "Control Transfer", 1, false},      // rel8 | rel16 | rel32
    {"jle", "Control Transfer", 1, false},     // rel8 | rel16 | rel32
    {"jna", "Control Transfer", 1, false},     // rel8 | rel16 | rel32
    {"jnae", "Control Transfer", 1, false},    // rel8 | rel16 | rel32
    {"jnb", "Control Transfer", 1, false},     // rel8 | rel16 | rel32
    {"jnbe", "Control Transfer", 1, false},    // rel8 | rel16 | rel32
    {"jnc", "Control Transfer", 1, false},     // rel8 | rel16 | rel32
    {"jne", "Control Transfer", 1, false},     // rel8 | rel16 | rel32
    {"jnz", "Control Transfer", 1, false},     // rel8 | rel16 | rel32 (alias for jne)
    {"jng", "Control Transfer", 1, false},     // rel8 | rel16 | rel32
    {"jnge", "Control Transfer", 1, false},    // rel8 | rel16 | rel32
    {"jnl", "Control Transfer", 1, false},     // rel8 | rel16 | rel32
    {"jnle", "Control Transfer", 1, false},    // rel8 | rel16 | rel32
    {"jno", "Control Transfer", 1, false},     // rel8 | rel16 | rel32
    {"jnp", "Control Transfer", 1, false},     // rel8 | rel16 | rel32
    {"jns", "Control Transfer", 1, false},     // rel8 | rel16 | rel32
    {"jo", "Control Transfer", 1, false},      // rel8 | rel16 | rel32
    {"jp", "Control Transfer", 1, false},      // rel8 | rel16 | rel32
    {"jpe", "Control Transfer", 1, false},     // rel8 | rel16 | rel32 (alias for jp)
    {"jpo", "Control Transfer", 1, false},     // rel8 | rel16 | rel32 (alias for jnp)
    {"js", "Control Transfer", 1, false},      // rel8 | rel16 | rel32
    
    // Conditional jumps based on CX/ECX/RCX register
    {"jcxz", "Control Transfer", 1, false},    // rel8
    {"jecxz", "Control Transfer", 1, false},   // rel8
    {"jrcxz", "Control Transfer", 1, false},   // rel8
    
    // Loop instructions
    {"loop", "Control Transfer", 1, false},    // rel8
    {"loope", "Control Transfer", 1, false},   // rel8
    {"loopz", "Control Transfer", 1, false},   // rel8 (alias for loope)
    {"loopne", "Control Transfer", 1, false},  // rel8
    {"loopnz", "Control Transfer", 1, false},  // rel8 (alias for loopne)
    
    // Call instructions
    {"call", "Control Transfer", 1, false},    // rel16 | rel32 | r/m16 | r/m32 | r/m64 | ptr16:16 | ptr16:32
    {"callq", "Control Transfer", 1, false},   // rel32 | r/m64
    {"calll", "Control Transfer", 1, false},   // rel32 | r/m32
    {"callw", "Control Transfer", 1, false},   // rel16 | r/m16
    
    // Return instructions
    {"ret", "Control Transfer", 0, false},     // none | imm16
    {"retq", "Control Transfer", 0, false},    // none | imm16
    {"retl", "Control Transfer", 0, false},    // none | imm16
    {"retw", "Control Transfer", 0, false},    // none | imm16
    {"retf", "Control Transfer", 0, false},    // none | imm16 (far return)
    {"lret", "Control Transfer", 0, false},    // none | imm16 (alias for retf)
    
    // Interrupt returns
    {"iret", "Control Transfer", 0, false},    // none
    {"iretd", "Control Transfer", 0, false},   // none
    {"iretq", "Control Transfer", 0, false},   // none
    
    // Enter/Leave
    {"enter", "Control Transfer", 2, false},   // imm16,imm8
    {"leave", "Control Transfer", 0, false},   // none
    {"leaveq", "Control Transfer", 0, false},  // none
    {"leavew", "Control Transfer", 0, false}   // none
};

// String Operations (comprehensive string manipulation)
static const instruction_def_t x86_64_string[] = {
    // Move string
    {"movs", "String", 0, false},              // m8,m8 | m16,m16 | m32,m32 | m64,m64 (implicit: [RSI] to [RDI])
    {"movsb", "String", 0, false},             // m8,m8 (move byte)
    {"movsw", "String", 0, false},             // m16,m16 (move word)
    {"movsd", "String", 0, false},             // m32,m32 (move dword)
    {"movsq", "String", 0, false},             // m64,m64 (move qword)
    
    // Compare string
    {"cmps", "String", 0, false},              // m8,m8 | m16,m16 | m32,m32 | m64,m64 (implicit: [RSI] with [RDI])
    {"cmpsb", "String", 0, false},             // m8,m8 (compare byte)
    {"cmpsw", "String", 0, false},             // m16,m16 (compare word)
    {"cmpsd", "String", 0, false},             // m32,m32 (compare dword)
    {"cmpsq", "String", 0, false},             // m64,m64 (compare qword)
    
    // Scan string
    {"scas", "String", 0, false},              // AL,m8 | AX,m16 | EAX,m32 | RAX,m64 (implicit: accumulator with [RDI])
    {"scasb", "String", 0, false},             // AL,m8 (scan byte)
    {"scasw", "String", 0, false},             // AX,m16 (scan word)
    {"scasd", "String", 0, false},             // EAX,m32 (scan dword)
    {"scasq", "String", 0, false},             // RAX,m64 (scan qword)
    
    // Load string
    {"lods", "String", 0, false},              // AL,m8 | AX,m16 | EAX,m32 | RAX,m64 (implicit: [RSI] to accumulator)
    {"lodsb", "String", 0, false},             // AL,m8 (load byte)
    {"lodsw", "String", 0, false},             // AX,m16 (load word)
    {"lodsd", "String", 0, false},             // EAX,m32 (load dword)
    {"lodsq", "String", 0, false},             // RAX,m64 (load qword)
    
    // Store string
    {"stos", "String", 0, false},              // m8,AL | m16,AX | m32,EAX | m64,RAX (implicit: accumulator to [RDI])
    {"stosb", "String", 0, false},             // m8,AL (store byte)
    {"stosw", "String", 0, false},             // m16,AX (store word)
    {"stosd", "String", 0, false},             // m32,EAX (store dword)
    {"stosq", "String", 0, false},             // m64,RAX (store qword)
    
    // Repeat prefixes (used with string instructions)
    {"rep", "String", 0, false},               // prefix for movs, stos, lods
    {"repe", "String", 0, false},              // prefix for cmps, scas (repeat while equal)
    {"repz", "String", 0, false},              // prefix for cmps, scas (repeat while zero) - alias for repe
    {"repne", "String", 0, false},             // prefix for cmps, scas (repeat while not equal)
    {"repnz", "String", 0, false}              // prefix for cmps, scas (repeat while not zero) - alias for repne
};

// I/O Instructions (port input/output)
static const instruction_def_t x86_64_io[] = {
    // Input from port
    {"in", "I/O", 2, false},                   // AL,imm8 | AX,imm8 | EAX,imm8 | AL,DX | AX,DX | EAX,DX
    {"inb", "I/O", 2, false},                  // AL,imm8 | AL,DX
    {"inw", "I/O", 2, false},                  // AX,imm8 | AX,DX
    {"inl", "I/O", 2, false},                  // EAX,imm8 | EAX,DX
    
    // Output to port
    {"out", "I/O", 2, false},                  // imm8,AL | imm8,AX | imm8,EAX | DX,AL | DX,AX | DX,EAX
    {"outb", "I/O", 2, false},                 // imm8,AL | DX,AL
    {"outw", "I/O", 2, false},                 // imm8,AX | DX,AX
    {"outl", "I/O", 2, false},                 // imm8,EAX | DX,EAX
    
    // Input string from port
    {"ins", "I/O", 0, false},                  // m8,DX | m16,DX | m32,DX (implicit: DX to [RDI])
    {"insb", "I/O", 0, false},                 // m8,DX (input byte string)
    {"insw", "I/O", 0, false},                 // m16,DX (input word string)
    {"insd", "I/O", 0, false},                 // m32,DX (input dword string)
    
    // Output string to port
    {"outs", "I/O", 0, false},                 // DX,m8 | DX,m16 | DX,m32 (implicit: [RSI] to DX)
    {"outsb", "I/O", 0, false},                // DX,m8 (output byte string)
    {"outsw", "I/O", 0, false},                // DX,m16 (output word string)
    {"outsd", "I/O", 0, false}                 // DX,m32 (output dword string)
};

// Flag Control Instructions
static const instruction_def_t x86_64_flag_control[] = {
    // Carry flag
    {"clc", "Flag Control", 0, false},         // Clear carry flag
    {"stc", "Flag Control", 0, false},         // Set carry flag
    {"cmc", "Flag Control", 0, false},         // Complement carry flag
    
    // Direction flag
    {"cld", "Flag Control", 0, false},         // Clear direction flag
    {"std", "Flag Control", 0, false},         // Set direction flag
    
    // Interrupt flag
    {"cli", "Flag Control", 0, false},         // Clear interrupt flag
    {"sti", "Flag Control", 0, false},         // Set interrupt flag
    
    // EFLAGS/RFLAGS operations
    {"lahf", "Flag Control", 0, false},        // Load AH from flags
    {"sahf", "Flag Control", 0, false},        // Store AH to flags
    {"pushf", "Flag Control", 0, false},       // Push 16-bit flags
    {"pushfd", "Flag Control", 0, false},      // Push 32-bit EFLAGS
    {"pushfq", "Flag Control", 0, false},      // Push 64-bit RFLAGS
    {"popf", "Flag Control", 0, false},        // Pop 16-bit flags
    {"popfd", "Flag Control", 0, false},       // Pop 32-bit EFLAGS
    {"popfq", "Flag Control", 0, false}        // Pop 64-bit RFLAGS
};

// Enhanced System Instructions (comprehensive privileged and system-level operations)
static const instruction_def_t x86_64_system[] = {
    // System calls
    {"syscall", "System", 0, false},           // System call (64-bit)
    {"sysenter", "System", 0, false},          // Fast system call entry
    {"sysexit", "System", 0, false},           // Fast system call exit
    {"sysexitq", "System", 0, false},          // Fast system call exit (64-bit)
    {"sysret", "System", 0, false},            // System call return
    {"sysretq", "System", 0, false},           // System call return (64-bit)
    
    // Interrupts
    {"int", "System", 1, false},               // imm8 (software interrupt)
    {"int3", "System", 0, false},              // Breakpoint interrupt
    {"into", "System", 0, false},              // Interrupt on overflow
    {"bound", "System", 2, false},             // r16,m16&16 | r32,m32&32 (check array bounds)
    
    // Processor identification and control
    {"cpuid", "System", 0, true},              // CPU identification
    {"nop", "System", 0, false},               // No operation
    {"pause", "System", 0, false},             // Spin loop hint
    {"hlt", "System", 0, false},               // Halt processor
    {"wait", "System", 0, false},              // Wait for floating-point unit
    {"fwait", "System", 0, false},             // Wait for floating-point unit (alias)
    
    // Memory management
    {"invd", "System", 0, true},               // Invalidate cache
    {"wbinvd", "System", 0, true},             // Write back and invalidate cache
    {"invlpg", "System", 1, true},             // m (invalidate page in TLB)
    {"invpcid", "System", 2, true},            // r32,m128 | r64,m128 (invalidate process-context identifier)
    
    // Time stamp counter
    {"rdtsc", "System", 0, true},              // Read time stamp counter
    {"rdtscp", "System", 0, true},             // Read time stamp counter and processor ID
    {"rdpmc", "System", 0, true},              // Read performance monitoring counter
    
    // Model specific registers
    {"rdmsr", "System", 0, true},              // Read model specific register
    {"wrmsr", "System", 0, true},              // Write model specific register
    
    // Load effective address and address calculation
    {"lea", "System", 2, false},               // r16,m | r32,m | r64,m (load effective address)
    {"leaq", "System", 2, false},              // r64,m (load effective address 64-bit)
    {"leal", "System", 2, false},              // r32,m (load effective address 32-bit)
    {"leaw", "System", 2, false},              // r16,m (load effective address 16-bit)
    
    // Miscellaneous
    {"ud2", "System", 0, false},               // Undefined instruction (guaranteed to cause #UD)
    {"lock", "System", 0, false},              // Lock prefix for atomic operations
    {"xchg", "System", 2, false},              // r/m8,r8 | r8,r/m8 | r/m16,r16 | r16,r/m16 | r/m32,r32 | r32,r/m32 | r/m64,r64 | r64,r/m64 | AX,r16 | r16,AX | EAX,r32 | r32,EAX | RAX,r64 | r64,RAX
    {"xchgq", "System", 2, false},            // r/m64,r64 | r64,r/m64 | RAX,r64 | r64,RAX
    {"xchgl", "System", 2, false},            // r/m32,r32 | r32,r/m32 | EAX,r32 | r32,EAX
    {"xchgw", "System", 2, false},            // r/m16,r16 | r16,r/m16 | AX,r16 | r16,AX
    {"xchgb", "System", 2, false},            // r/m8,r8 | r8,r/m8
    {"xlat", "System", 0, false},              // Translate byte in AL
    {"xlatb", "System", 0, false},             // Translate byte in AL (explicit)
    
    // Atomic operations
    {"cmpxchg", "System", 2, false},           // r/m8,r8 | r/m16,r16 | r/m32,r32 | r/m64,r64
    {"cmpxchgq", "System", 2, false},          // r/m64,r64
    {"cmpxchgl", "System", 2, false},          // r/m32,r32
    {"cmpxchgw", "System", 2, false},          // r/m16,r16
    {"cmpxchgb", "System", 2, false},          // r/m8,r8
    {"cmpxchg8b", "System", 1, false},         // m64
    {"cmpxchg16b", "System", 1, true},         // m128
    {"xadd", "System", 2, false},              // r/m8,r8 | r/m16,r16 | r/m32,r32 | r/m64,r64
    {"xaddq", "System", 2, false},             // r/m64,r64
    {"xaddl", "System", 2, false},             // r/m32,r32
    {"xaddw", "System", 2, false},             // r/m16,r16
    {"xaddb", "System", 2, false}              // r/m8,r8
};

static const instruction_category_t x86_64_categories[] = {
    {"Arithmetic", x86_64_arithmetic, sizeof(x86_64_arithmetic)/sizeof(instruction_def_t)},
    {"Data Movement", x86_64_data_movement, sizeof(x86_64_data_movement)/sizeof(instruction_def_t)},
    {"Logical", x86_64_logical, sizeof(x86_64_logical)/sizeof(instruction_def_t)},
    {"Shift", x86_64_shift, sizeof(x86_64_shift)/sizeof(instruction_def_t)},
    {"Bit Manipulation", x86_64_bit_manipulation, sizeof(x86_64_bit_manipulation)/sizeof(instruction_def_t)},
    {"Control Transfer", x86_64_control_transfer, sizeof(x86_64_control_transfer)/sizeof(instruction_def_t)},
    {"String", x86_64_string, sizeof(x86_64_string)/sizeof(instruction_def_t)},
    {"I/O", x86_64_io, sizeof(x86_64_io)/sizeof(instruction_def_t)},
    {"Flag Control", x86_64_flag_control, sizeof(x86_64_flag_control)/sizeof(instruction_def_t)},
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
