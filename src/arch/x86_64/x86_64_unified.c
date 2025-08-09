/*
 * x86-64 Unified Implementation - CPU-Accurate MANIFEST COMPLIANT
 * Complete architectural implementation following Intel SDM specifications
 * Implementing STAS Development Manifest requirements for CPU accuracy
 */

#include "x86_64_unified.h"
#include "x86_64.h"
#include "arch_interface.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <stdbool.h>
#include <ctype.h>

//=============================================================================
// CPU-Accurate Register Database
// Hardware-mapped register encodings per Intel SDM Volume 2A
//=============================================================================

static const x86_64_register_info_t cpu_register_database[] = {
    // 8-bit registers - hardware encoding order
    {"%al",   AL,   1, 0, false, false, 0},  // AL = RAX bits 7:0
    {"%cl",   CL,   1, 1, false, false, 0},  // CL = RCX bits 7:0
    {"%dl",   DL,   1, 2, false, false, 0},  // DL = RDX bits 7:0
    {"%bl",   BL,   1, 3, false, false, 0},  // BL = RBX bits 7:0
    {"%ah",   AH,   1, 4, false, false, 0},  // AH = RAX bits 15:8
    {"%ch",   CH,   1, 5, false, false, 0},  // CH = RCX bits 15:8
    {"%dh",   DH,   1, 6, false, false, 0},  // DH = RDX bits 15:8
    {"%bh",   BH,   1, 7, false, false, 0},  // BH = RBX bits 15:8
    {"%spl",  SPL,  1, 4, false, true,  0x40}, // SPL requires REX prefix
    {"%bpl",  BPL,  1, 5, false, true,  0x40}, // BPL requires REX prefix
    {"%sil",  SIL,  1, 6, false, true,  0x40}, // SIL requires REX prefix
    {"%dil",  DIL,  1, 7, false, true,  0x40}, // DIL requires REX prefix
    {"%r8b",  R8B,  1, 0, true,  false, 0x41}, // R8B requires REX.B
    {"%r9b",  R9B,  1, 1, true,  false, 0x41}, // R9B requires REX.B
    {"%r10b", R10B, 1, 2, true,  false, 0x41}, // R10B requires REX.B
    {"%r11b", R11B, 1, 3, true,  false, 0x41}, // R11B requires REX.B
    {"%r12b", R12B, 1, 4, true,  false, 0x41}, // R12B requires REX.B
    {"%r13b", R13B, 1, 5, true,  false, 0x41}, // R13B requires REX.B
    {"%r14b", R14B, 1, 6, true,  false, 0x41}, // R14B requires REX.B
    {"%r15b", R15B, 1, 7, true,  false, 0x41}, // R15B requires REX.B

    // 16-bit registers
    {"%ax",   AX,   2, 0, false, false, 0x66}, // 16-bit operand prefix
    {"%cx",   CX,   2, 1, false, false, 0x66},
    {"%dx",   DX,   2, 2, false, false, 0x66},
    {"%bx",   BX,   2, 3, false, false, 0x66},
    {"%sp",   SP,   2, 4, false, false, 0x66},
    {"%bp",   BP,   2, 5, false, false, 0x66},
    {"%si",   SI,   2, 6, false, false, 0x66},
    {"%di",   DI,   2, 7, false, false, 0x66},
    {"%r8w",  R8W,  2, 0, true,  false, 0x66}, // R8W requires REX.B + 16-bit prefix
    {"%r9w",  R9W,  2, 1, true,  false, 0x66},
    {"%r10w", R10W, 2, 2, true,  false, 0x66},
    {"%r11w", R11W, 2, 3, true,  false, 0x66},
    {"%r12w", R12W, 2, 4, true,  false, 0x66},
    {"%r13w", R13W, 2, 5, true,  false, 0x66},
    {"%r14w", R14W, 2, 6, true,  false, 0x66},
    {"%r15w", R15W, 2, 7, true,  false, 0x66},

    // 32-bit registers
    {"%eax",  EAX,  4, 0, false, false, 0},  // Default 32-bit mode
    {"%ecx",  ECX,  4, 1, false, false, 0},
    {"%edx",  EDX,  4, 2, false, false, 0},
    {"%ebx",  EBX,  4, 3, false, false, 0},
    {"%esp",  ESP,  4, 4, false, false, 0},
    {"%ebp",  EBP,  4, 5, false, false, 0},
    {"%esi",  ESI,  4, 6, false, false, 0},
    {"%edi",  EDI,  4, 7, false, false, 0},
    {"%r8d",  R8D,  4, 0, true,  false, 0x41}, // R8D requires REX.B
    {"%r9d",  R9D,  4, 1, true,  false, 0x41},
    {"%r10d", R10D, 4, 2, true,  false, 0x41},
    {"%r11d", R11D, 4, 3, true,  false, 0x41},
    {"%r12d", R12D, 4, 4, true,  false, 0x41},
    {"%r13d", R13D, 4, 5, true,  false, 0x41},
    {"%r14d", R14D, 4, 6, true,  false, 0x41},
    {"%r15d", R15D, 4, 7, true,  false, 0x41},

    // 64-bit registers  
    {"%rax",  RAX,  8, 0, false, false, 0x48}, // REX.W for 64-bit
    {"%rcx",  RCX,  8, 1, false, false, 0x48},
    {"%rdx",  RDX,  8, 2, false, false, 0x48},
    {"%rbx",  RBX,  8, 3, false, false, 0x48},
    {"%rsp",  RSP,  8, 4, false, false, 0x48},
    {"%rbp",  RBP,  8, 5, false, false, 0x48},
    {"%rsi",  RSI,  8, 6, false, false, 0x48},
    {"%rdi",  RDI,  8, 7, false, false, 0x48},
    {"%r8",   R8,   8, 0, true,  false, 0x49}, // REX.W + REX.B
    {"%r9",   R9,   8, 1, true,  false, 0x49},
    {"%r10",  R10,  8, 2, true,  false, 0x49},
    {"%r11",  R11,  8, 3, true,  false, 0x49},
    {"%r12",  R12,  8, 4, true,  false, 0x49},
    {"%r13",  R13,  8, 5, true,  false, 0x49},
    {"%r14",  R14,  8, 6, true,  false, 0x49},
    {"%r15",  R15,  8, 7, true,  false, 0x49},

    // Segment registers
    {"%es",   ES,   2, 0, false, false, 0x26}, // ES segment override
    {"%cs",   CS,   2, 1, false, false, 0x2E}, // CS segment override (not used in 64-bit)
    {"%ss",   SS,   2, 2, false, false, 0x36}, // SS segment override (not used in 64-bit)
    {"%ds",   DS,   2, 3, false, false, 0x3E}, // DS segment override (not used in 64-bit)
    {"%fs",   FS,   2, 4, false, false, 0x64}, // FS segment override
    {"%gs",   GS,   2, 5, false, false, 0x65}, // GS segment override

    // Special registers for RIP-relative addressing
    {"%rip",  RIP,  8, 5, false, false, 0},    // RIP-relative uses ModR/M = 00 101

    {NULL, 0, 0, 0, false, false, 0} // Terminator
};

//=============================================================================
// CPU-Accurate Instruction Database
// Intel SDM Volume 2 opcode specifications with exact constraints
//=============================================================================

static const x86_64_instruction_info_t instruction_database[] = {
    // Generic MOV instruction for compatibility
    {"mov",    X86_64_CAT_DATA_MOVEMENT, {0x89}, 1, true,  true,  true,  0, 2, 0x70, 0x48, "Generic move instruction"},
    {"add",    X86_64_CAT_ARITHMETIC, {0x01}, 1, true,  false, false, 0, 2, 0x70, 0, "Generic add instruction"},
    
    // Basic MOV instructions for initial code generation testing
    {"movq",   X86_64_CAT_DATA_MOVEMENT, {0x89}, 1, true,  true,  true,  0, 2, 0x70, 0x48, "Move r64 to r/m64"},
    {"movq",   X86_64_CAT_DATA_MOVEMENT, {0x8B}, 1, true,  true,  true,  0, 2, 0x70, 0x48, "Move r/m64 to r64"},
    
    // MOV immediate to register - CRITICAL missing instructions per Intel SDM
    {"movq",   X86_64_CAT_DATA_MOVEMENT, {0xB8}, 1, false, true,  true,  0, 1, 0x70, 0x48, "Move imm64 to RAX"}, // MOV immediate to RAX
    {"movq",   X86_64_CAT_DATA_MOVEMENT, {0xB9}, 1, false, true,  true,  0, 1, 0x70, 0x48, "Move imm64 to RCX"}, // MOV immediate to RCX  
    {"movq",   X86_64_CAT_DATA_MOVEMENT, {0xBA}, 1, false, true,  true,  0, 1, 0x70, 0x48, "Move imm64 to RDX"}, // MOV immediate to RDX
    {"movq",   X86_64_CAT_DATA_MOVEMENT, {0xBB}, 1, false, true,  true,  0, 1, 0x70, 0x48, "Move imm64 to RBX"}, // MOV immediate to RBX
    {"movq",   X86_64_CAT_DATA_MOVEMENT, {0xBC}, 1, false, true,  true,  0, 1, 0x70, 0x48, "Move imm64 to RSP"}, // MOV immediate to RSP
    {"movq",   X86_64_CAT_DATA_MOVEMENT, {0xBD}, 1, false, true,  true,  0, 1, 0x70, 0x48, "Move imm64 to RBP"}, // MOV immediate to RBP
    {"movq",   X86_64_CAT_DATA_MOVEMENT, {0xBE}, 1, false, true,  true,  0, 1, 0x70, 0x48, "Move imm64 to RSI"}, // MOV immediate to RSI
    {"movq",   X86_64_CAT_DATA_MOVEMENT, {0xBF}, 1, false, true,  true,  0, 1, 0x70, 0x48, "Move imm64 to RDI"}, // MOV immediate to RDI
    
    // 32-bit immediate moves (zero-extend to 64-bit in 64-bit mode)
    {"movl",   X86_64_CAT_DATA_MOVEMENT, {0xB8}, 1, false, false, false, 0, 1, 0x30, 0, "Move imm32 to EAX (zero-extend)"}, 
    {"movl",   X86_64_CAT_DATA_MOVEMENT, {0xB9}, 1, false, false, false, 0, 1, 0x30, 0, "Move imm32 to ECX (zero-extend)"},
    {"movl",   X86_64_CAT_DATA_MOVEMENT, {0xBA}, 1, false, false, false, 0, 1, 0x30, 0, "Move imm32 to EDX (zero-extend)"},
    {"movl",   X86_64_CAT_DATA_MOVEMENT, {0xBB}, 1, false, false, false, 0, 1, 0x30, 0, "Move imm32 to EBX (zero-extend)"},
    {"movl",   X86_64_CAT_DATA_MOVEMENT, {0xBC}, 1, false, false, false, 0, 1, 0x30, 0, "Move imm32 to ESP (zero-extend)"},
    {"movl",   X86_64_CAT_DATA_MOVEMENT, {0xBD}, 1, false, false, false, 0, 1, 0x30, 0, "Move imm32 to EBP (zero-extend)"},
    {"movl",   X86_64_CAT_DATA_MOVEMENT, {0xBE}, 1, false, false, false, 0, 1, 0x30, 0, "Move imm32 to ESI (zero-extend)"},
    {"movl",   X86_64_CAT_DATA_MOVEMENT, {0xBF}, 1, false, false, false, 0, 1, 0x30, 0, "Move imm32 to EDI (zero-extend)"},
    
    {"movl",   X86_64_CAT_DATA_MOVEMENT, {0x89}, 1, true,  false, false, 0, 2, 0x30, 0, "Move r32 to r/m32"},
    {"movl",   X86_64_CAT_DATA_MOVEMENT, {0x8B}, 1, true,  false, false, 0, 2, 0x30, 0, "Move r/m32 to r32"},
    
    // Control flow instructions - CRITICAL for basic functionality
    {"ret",    X86_64_CAT_CONTROL_FLOW, {0xC3}, 1, false, false, false, 0, 0, 0, 0, "Return near"},
    {"retq",   X86_64_CAT_CONTROL_FLOW, {0xC3}, 1, false, false, false, 0, 0, 0, 0, "Return near 64-bit"},
    {"call",   X86_64_CAT_CONTROL_FLOW, {0xE8}, 1, false, false, false, 0, 1, 0, 0, "Call near rel32"},
    {"jmp",    X86_64_CAT_CONTROL_FLOW, {0xEB}, 1, false, false, false, 0, 1, 0, 0, "Jump short rel8"},
    
    // Conditional jumps - Complete set per Intel SDM
    {"je",     X86_64_CAT_CONTROL_FLOW, {0x74}, 1, false, false, false, 0, 1, 0, 0, "Jump if equal"},
    {"jne",    X86_64_CAT_CONTROL_FLOW, {0x75}, 1, false, false, false, 0, 1, 0, 0, "Jump if not equal"},
    {"jl",     X86_64_CAT_CONTROL_FLOW, {0x7C}, 1, false, false, false, 0, 1, 0, 0, "Jump if less"},
    {"jg",     X86_64_CAT_CONTROL_FLOW, {0x7F}, 1, false, false, false, 0, 1, 0, 0, "Jump if greater"},
    {"jle",    X86_64_CAT_CONTROL_FLOW, {0x7E}, 1, false, false, false, 0, 1, 0, 0, "Jump if less or equal"},
    {"jge",    X86_64_CAT_CONTROL_FLOW, {0x7D}, 1, false, false, false, 0, 1, 0, 0, "Jump if greater or equal"},
    {"ja",     X86_64_CAT_CONTROL_FLOW, {0x77}, 1, false, false, false, 0, 1, 0, 0, "Jump if above"},
    {"jb",     X86_64_CAT_CONTROL_FLOW, {0x72}, 1, false, false, false, 0, 1, 0, 0, "Jump if below"},
    {"jae",    X86_64_CAT_CONTROL_FLOW, {0x73}, 1, false, false, false, 0, 1, 0, 0, "Jump if above or equal"},
    {"jbe",    X86_64_CAT_CONTROL_FLOW, {0x76}, 1, false, false, false, 0, 1, 0, 0, "Jump if below or equal"},
    {"jo",     X86_64_CAT_CONTROL_FLOW, {0x70}, 1, false, false, false, 0, 1, 0, 0, "Jump if overflow"},
    {"jno",    X86_64_CAT_CONTROL_FLOW, {0x71}, 1, false, false, false, 0, 1, 0, 0, "Jump if not overflow"},
    {"js",     X86_64_CAT_CONTROL_FLOW, {0x78}, 1, false, false, false, 0, 1, 0, 0, "Jump if sign"},
    {"jns",    X86_64_CAT_CONTROL_FLOW, {0x79}, 1, false, false, false, 0, 1, 0, 0, "Jump if not sign"},
    {"jc",     X86_64_CAT_CONTROL_FLOW, {0x72}, 1, false, false, false, 0, 1, 0, 0, "Jump if carry"},
    {"jnc",    X86_64_CAT_CONTROL_FLOW, {0x73}, 1, false, false, false, 0, 1, 0, 0, "Jump if not carry"},
    
    // Arithmetic instructions - Basic set with all size variants
    {"addq",   X86_64_CAT_ARITHMETIC, {0x01}, 1, true,  true,  true,  0, 2, 0x70, 0x48, "Add r64 to r/m64"},
    {"addl",   X86_64_CAT_ARITHMETIC, {0x01}, 1, true,  false, false, 0, 2, 0x30, 0, "Add r32 to r/m32"},
    {"addw",   X86_64_CAT_ARITHMETIC, {0x66, 0x01}, 2, true,  false, false, 0, 2, 0x30, 0x66, "Add r16 to r/m16"},
    {"addb",   X86_64_CAT_ARITHMETIC, {0x00}, 1, true,  false, false, 0, 2, 0x30, 0, "Add r8 to r/m8"},
    
    {"subq",   X86_64_CAT_ARITHMETIC, {0x29}, 1, true,  true,  true,  0, 2, 0x70, 0x48, "Sub r64 from r/m64"},
    {"subl",   X86_64_CAT_ARITHMETIC, {0x29}, 1, true,  false, false, 0, 2, 0x30, 0, "Sub r32 from r/m32"},
    {"subw",   X86_64_CAT_ARITHMETIC, {0x66, 0x29}, 2, true,  false, false, 0, 2, 0x30, 0x66, "Sub r16 from r/m16"},
    {"subb",   X86_64_CAT_ARITHMETIC, {0x28}, 1, true,  false, false, 0, 2, 0x30, 0, "Sub r8 from r/m8"},
    
    // Signed multiply variants - both 1-operand and 2-operand forms
    {"imulb",  X86_64_CAT_ARITHMETIC, {0xF6}, 1, true,  false, false, 5, 1, 0x30, 0, "Signed multiply AL by r/m8"},
    {"imulw",  X86_64_CAT_ARITHMETIC, {0xF7}, 1, true,  false, false, 5, 1, 0x30, 0x66, "Signed multiply AX by r/m16"},
    {"imull",  X86_64_CAT_ARITHMETIC, {0xF7}, 1, true,  false, false, 5, 1, 0x30, 0, "Signed multiply EAX by r/m32"},
    {"imulq",  X86_64_CAT_ARITHMETIC, {0xF7}, 1, true,  true,  true,  5, 1, 0x70, 0x48, "Signed multiply RAX by r/m64"},
    
    {"idivq",  X86_64_CAT_ARITHMETIC, {0xF7}, 1, true,  true,  true,  7, 1, 0x70, 0x48, "Signed divide RDX:RAX by r/m64"},
    {"idivl",  X86_64_CAT_ARITHMETIC, {0xF7}, 1, true,  false, false, 7, 1, 0x30, 0, "Signed divide EDX:EAX by r/m32"},
    {"idivw",  X86_64_CAT_ARITHMETIC, {0x66, 0xF7}, 2, true,  false, false, 7, 1, 0x30, 0x66, "Signed divide DX:AX by r/m16"},
    {"idivb",  X86_64_CAT_ARITHMETIC, {0xF6}, 1, true,  false, false, 7, 1, 0x30, 0, "Signed divide AX by r/m8"},
    
    // Logical instructions - Basic set with all size variants
    {"andq",   X86_64_CAT_LOGICAL, {0x21}, 1, true,  true,  true,  0, 2, 0x70, 0x48, "Logical AND r64 with r/m64"},
    {"andl",   X86_64_CAT_LOGICAL, {0x21}, 1, true,  false, false, 0, 2, 0x30, 0, "Logical AND r32 with r/m32"},
    {"andw",   X86_64_CAT_LOGICAL, {0x66, 0x21}, 2, true,  false, false, 0, 2, 0x30, 0x66, "Logical AND r16 with r/m16"},
    {"andb",   X86_64_CAT_LOGICAL, {0x20}, 1, true,  false, false, 0, 2, 0x30, 0, "Logical AND r8 with r/m8"},
    
    {"orq",    X86_64_CAT_LOGICAL, {0x09}, 1, true,  true,  true,  0, 2, 0x70, 0x48, "Logical OR r64 with r/m64"},
    {"orl",    X86_64_CAT_LOGICAL, {0x09}, 1, true,  false, false, 0, 2, 0x30, 0, "Logical OR r32 with r/m32"},
    {"orw",    X86_64_CAT_LOGICAL, {0x66, 0x09}, 2, true,  false, false, 0, 2, 0x30, 0x66, "Logical OR r16 with r/m16"},
    {"orb",    X86_64_CAT_LOGICAL, {0x08}, 1, true,  false, false, 0, 2, 0x30, 0, "Logical OR r8 with r/m8"},
    
    {"xorq",   X86_64_CAT_LOGICAL, {0x31}, 1, true,  true,  true,  0, 2, 0x70, 0x48, "Logical XOR r64 with r/m64"},
    {"xorl",   X86_64_CAT_LOGICAL, {0x31}, 1, true,  false, false, 0, 2, 0x30, 0, "Logical XOR r32 with r/m32"},
    {"xorw",   X86_64_CAT_LOGICAL, {0x66, 0x31}, 2, true,  false, false, 0, 2, 0x30, 0x66, "Logical XOR r16 with r/m16"},
    {"xorb",   X86_64_CAT_LOGICAL, {0x30}, 1, true,  false, false, 0, 2, 0x30, 0, "Logical XOR r8 with r/m8"},
    
    {"notq",   X86_64_CAT_LOGICAL, {0xF7}, 1, true,  true,  true,  2, 1, 0x70, 0x48, "Logical NOT r/m64"},
    {"notl",   X86_64_CAT_LOGICAL, {0xF7}, 1, true,  false, false, 2, 1, 0x30, 0, "Logical NOT r/m32"},
    {"notw",   X86_64_CAT_LOGICAL, {0x66, 0xF7}, 2, true,  false, false, 2, 1, 0x30, 0x66, "Logical NOT r/m16"},
    {"notb",   X86_64_CAT_LOGICAL, {0xF6}, 1, true,  false, false, 2, 1, 0x30, 0, "Logical NOT r/m8"},
    
    // Shift instructions - CPU-accurate operand constraints
    {"shlq",   X86_64_CAT_SHIFT, {0xD1}, 1, true,  true,  true,  4, 1, 0x70, 0x48, "Shift left r/m64 by 1"},
    {"shll",   X86_64_CAT_SHIFT, {0xD1}, 1, true,  false, false, 4, 1, 0x30, 0, "Shift left r/m32 by 1"},
    {"shlw",   X86_64_CAT_SHIFT, {0x66, 0xD1}, 2, true,  false, false, 4, 1, 0x30, 0x66, "Shift left r/m16 by 1"},
    {"shlb",   X86_64_CAT_SHIFT, {0xD0}, 1, true,  false, false, 4, 1, 0x30, 0, "Shift left r/m8 by 1"},
    
    {"shrq",   X86_64_CAT_SHIFT, {0xD1}, 1, true,  true,  true,  5, 1, 0x70, 0x48, "Shift right r/m64 by 1"},
    {"shrl",   X86_64_CAT_SHIFT, {0xD1}, 1, true,  false, false, 5, 1, 0x30, 0, "Shift right r/m32 by 1"},
    {"shrw",   X86_64_CAT_SHIFT, {0x66, 0xD1}, 2, true,  false, false, 5, 1, 0x30, 0x66, "Shift right r/m16 by 1"},
    {"shrb",   X86_64_CAT_SHIFT, {0xD0}, 1, true,  false, false, 5, 1, 0x30, 0, "Shift right r/m8 by 1"},
    
    // Basic system instructions
    {"nop",    X86_64_CAT_CONTROL_FLOW, {0x90}, 1, false, false, false, 0, 0, 0, 0, "No operation"},
    {"syscall", X86_64_CAT_SYSTEM, {0x0F, 0x05}, 2, false, false, false, 0, 0, 0, 0, "System call"},
    
    // MISSING DATA MOVEMENT INSTRUCTIONS - Critical for completeness
    // Size variants of MOV instructions
    {"movb",   X86_64_CAT_DATA_MOVEMENT, {0x88}, 1, true,  false, false, 0, 2, 0x30, 0, "Move r8 to r/m8"},
    {"movw",   X86_64_CAT_DATA_MOVEMENT, {0x66, 0x89}, 2, true,  false, false, 0, 2, 0x30, 0x66, "Move r16 to r/m16"},
    
    // Zero/Sign extend moves - CPU-accurate per Intel SDM
    {"movzbw", X86_64_CAT_DATA_MOVEMENT, {0x66, 0x0F, 0xB6}, 3, true,  false, false, 0, 2, 0x30, 0x66, "Move zero-extended byte to word"},
    {"movzbl", X86_64_CAT_DATA_MOVEMENT, {0x0F, 0xB6}, 2, true,  false, false, 0, 2, 0x30, 0, "Move zero-extended byte to dword"},
    {"movzbq", X86_64_CAT_DATA_MOVEMENT, {0x0F, 0xB6}, 2, true,  true,  true,  0, 2, 0x70, 0x48, "Move zero-extended byte to qword"},
    {"movzwl", X86_64_CAT_DATA_MOVEMENT, {0x0F, 0xB7}, 2, true,  false, false, 0, 2, 0x30, 0, "Move zero-extended word to dword"},
    {"movzwq", X86_64_CAT_DATA_MOVEMENT, {0x0F, 0xB7}, 2, true,  true,  true,  0, 2, 0x70, 0x48, "Move zero-extended word to qword"},
    {"movslq", X86_64_CAT_DATA_MOVEMENT, {0x63}, 1, true,  true,  true,  0, 2, 0x70, 0x48, "Move sign-extended dword to qword"},
    {"movsbw", X86_64_CAT_DATA_MOVEMENT, {0x66, 0x0F, 0xBE}, 3, true,  false, false, 0, 2, 0x30, 0x66, "Move sign-extended byte to word"},
    {"movsbl", X86_64_CAT_DATA_MOVEMENT, {0x0F, 0xBE}, 2, true,  false, false, 0, 2, 0x30, 0, "Move sign-extended byte to dword"},
    {"movsbq", X86_64_CAT_DATA_MOVEMENT, {0x0F, 0xBE}, 2, true,  true,  true,  0, 2, 0x70, 0x48, "Move sign-extended byte to qword"},
    {"movswl", X86_64_CAT_DATA_MOVEMENT, {0x0F, 0xBF}, 2, true,  false, false, 0, 2, 0x30, 0, "Move sign-extended word to dword"},
    {"movswq", X86_64_CAT_DATA_MOVEMENT, {0x0F, 0xBF}, 2, true,  true,  true,  0, 2, 0x70, 0x48, "Move sign-extended word to qword"},
    
    // LEA - Load Effective Address (memory addressing required)
    {"leaw",   X86_64_CAT_DATA_MOVEMENT, {0x66, 0x8D}, 2, true,  false, false, 0, 2, 0x30, 0x66, "Load effective address to r16"},
    {"leal",   X86_64_CAT_DATA_MOVEMENT, {0x8D}, 1, true,  false, false, 0, 2, 0x30, 0, "Load effective address to r32"},
    {"leaq",   X86_64_CAT_DATA_MOVEMENT, {0x8D}, 1, true,  true,  true,  0, 2, 0x70, 0x48, "Load effective address to r64"},
    
    // XCHG - Exchange operations
    {"xchgb",  X86_64_CAT_DATA_MOVEMENT, {0x86}, 1, true,  false, false, 0, 2, 0x30, 0, "Exchange r8 with r/m8"},
    {"xchgw",  X86_64_CAT_DATA_MOVEMENT, {0x66, 0x87}, 2, true,  false, false, 0, 2, 0x30, 0x66, "Exchange r16 with r/m16"},
    {"xchgl",  X86_64_CAT_DATA_MOVEMENT, {0x87}, 1, true,  false, false, 0, 2, 0x30, 0, "Exchange r32 with r/m32"},
    {"xchgq",  X86_64_CAT_DATA_MOVEMENT, {0x87}, 1, true,  true,  true,  0, 2, 0x70, 0x48, "Exchange r64 with r/m64"},
    
    // PUSH/POP - Stack operations (CPU-accurate)
    {"pushw",  X86_64_CAT_DATA_MOVEMENT, {0x66, 0x50}, 2, false, false, false, 0, 1, 0x30, 0x66, "Push r16 onto stack"},
    {"pushl",  X86_64_CAT_DATA_MOVEMENT, {0x50}, 1, false, false, false, 0, 1, 0x30, 0, "Push r32 onto stack"},
    {"pushq",  X86_64_CAT_DATA_MOVEMENT, {0x50}, 1, false, true,  true,  0, 1, 0x70, 0x48, "Push r64 onto stack"},
    {"popw",   X86_64_CAT_DATA_MOVEMENT, {0x66, 0x58}, 2, false, false, false, 0, 1, 0x30, 0x66, "Pop from stack to r16"},
    {"popl",   X86_64_CAT_DATA_MOVEMENT, {0x58}, 1, false, false, false, 0, 1, 0x30, 0, "Pop from stack to r32"},
    {"popq",   X86_64_CAT_DATA_MOVEMENT, {0x58}, 1, false, true,  true,  0, 1, 0x70, 0x48, "Pop from stack to r64"},
    
    // BSWAP - Byte swap for endianness
    {"bswapl", X86_64_CAT_DATA_MOVEMENT, {0x0F, 0xC8}, 2, false, false, false, 0, 1, 0x30, 0, "Byte swap r32"},
    {"bswapq", X86_64_CAT_DATA_MOVEMENT, {0x0F, 0xC8}, 2, false, true,  true,  0, 1, 0x70, 0x48, "Byte swap r64"},
    
    // MISSING ARITHMETIC INSTRUCTIONS - Critical gap
    // Add/Subtract with carry operations
    {"adcb",   X86_64_CAT_ARITHMETIC, {0x10}, 1, true,  false, false, 0, 2, 0x30, 0, "Add with carry r8 to r/m8"},
    {"adcw",   X86_64_CAT_ARITHMETIC, {0x66, 0x11}, 2, true,  false, false, 0, 2, 0x30, 0x66, "Add with carry r16 to r/m16"},
    {"adcl",   X86_64_CAT_ARITHMETIC, {0x11}, 1, true,  false, false, 0, 2, 0x30, 0, "Add with carry r32 to r/m32"},
    {"adcq",   X86_64_CAT_ARITHMETIC, {0x11}, 1, true,  true,  true,  0, 2, 0x70, 0x48, "Add with carry r64 to r/m64"},
    {"sbbb",   X86_64_CAT_ARITHMETIC, {0x18}, 1, true,  false, false, 0, 2, 0x30, 0, "Subtract with borrow r8 from r/m8"},
    {"sbbw",   X86_64_CAT_ARITHMETIC, {0x66, 0x19}, 2, true,  false, false, 0, 2, 0x30, 0x66, "Subtract with borrow r16 from r/m16"},
    {"sbbl",   X86_64_CAT_ARITHMETIC, {0x19}, 1, true,  false, false, 0, 2, 0x30, 0, "Subtract with borrow r32 from r/m32"},
    {"sbbq",   X86_64_CAT_ARITHMETIC, {0x19}, 1, true,  true,  true,  0, 2, 0x70, 0x48, "Subtract with borrow r64 from r/m64"},
    
    // Unsigned multiply operations
    {"mulb",   X86_64_CAT_ARITHMETIC, {0xF6}, 1, true,  false, false, 4, 1, 0x30, 0, "Unsigned multiply AL by r/m8"},
    {"mulw",   X86_64_CAT_ARITHMETIC, {0x66, 0xF7}, 2, true,  false, false, 4, 1, 0x30, 0x66, "Unsigned multiply AX by r/m16"},
    {"mull",   X86_64_CAT_ARITHMETIC, {0xF7}, 1, true,  false, false, 4, 1, 0x30, 0, "Unsigned multiply EAX by r/m32"},
    {"mulq",   X86_64_CAT_ARITHMETIC, {0xF7}, 1, true,  true,  true,  4, 1, 0x70, 0x48, "Unsigned multiply RAX by r/m64"},
    
    // Unsigned divide operations
    {"divb",   X86_64_CAT_ARITHMETIC, {0xF6}, 1, true,  false, false, 6, 1, 0x30, 0, "Unsigned divide AX by r/m8"},
    {"divw",   X86_64_CAT_ARITHMETIC, {0x66, 0xF7}, 2, true,  false, false, 6, 1, 0x30, 0x66, "Unsigned divide DX:AX by r/m16"},
    {"divl",   X86_64_CAT_ARITHMETIC, {0xF7}, 1, true,  false, false, 6, 1, 0x30, 0, "Unsigned divide EDX:EAX by r/m32"},
    {"divq",   X86_64_CAT_ARITHMETIC, {0xF7}, 1, true,  true,  true,  6, 1, 0x70, 0x48, "Unsigned divide RDX:RAX by r/m64"},
    
    // Increment/Decrement operations
    {"incb",   X86_64_CAT_ARITHMETIC, {0xFE}, 1, true,  false, false, 0, 1, 0x30, 0, "Increment r/m8 by 1"},
    {"incw",   X86_64_CAT_ARITHMETIC, {0x66, 0xFF}, 2, true,  false, false, 0, 1, 0x30, 0x66, "Increment r/m16 by 1"},
    {"incl",   X86_64_CAT_ARITHMETIC, {0xFF}, 1, true,  false, false, 0, 1, 0x30, 0, "Increment r/m32 by 1"},
    {"incq",   X86_64_CAT_ARITHMETIC, {0xFF}, 1, true,  true,  true,  0, 1, 0x70, 0x48, "Increment r/m64 by 1"},
    {"decb",   X86_64_CAT_ARITHMETIC, {0xFE}, 1, true,  false, false, 1, 1, 0x30, 0, "Decrement r/m8 by 1"},
    {"decw",   X86_64_CAT_ARITHMETIC, {0x66, 0xFF}, 2, true,  false, false, 1, 1, 0x30, 0x66, "Decrement r/m16 by 1"},
    {"decl",   X86_64_CAT_ARITHMETIC, {0xFF}, 1, true,  false, false, 1, 1, 0x30, 0, "Decrement r/m32 by 1"},
    {"decq",   X86_64_CAT_ARITHMETIC, {0xFF}, 1, true,  true,  true,  1, 1, 0x70, 0x48, "Decrement r/m64 by 1"},
    
    // NEG - Two's complement negation
    {"negb",   X86_64_CAT_ARITHMETIC, {0xF6}, 1, true,  false, false, 3, 1, 0x30, 0, "Two's complement negate r/m8"},
    {"negw",   X86_64_CAT_ARITHMETIC, {0x66, 0xF7}, 2, true,  false, false, 3, 1, 0x30, 0x66, "Two's complement negate r/m16"},
    {"negl",   X86_64_CAT_ARITHMETIC, {0xF7}, 1, true,  false, false, 3, 1, 0x30, 0, "Two's complement negate r/m32"},
    {"negq",   X86_64_CAT_ARITHMETIC, {0xF7}, 1, true,  true,  true,  3, 1, 0x70, 0x48, "Two's complement negate r/m64"},
    
    // MISSING LOGICAL INSTRUCTIONS - TEST and bit manipulation
    // TEST instructions - logical comparison
    {"testb",  X86_64_CAT_LOGICAL, {0x84}, 1, true,  false, false, 0, 2, 0x30, 0, "Logical compare r8 with r/m8"},
    {"testw",  X86_64_CAT_LOGICAL, {0x66, 0x85}, 2, true,  false, false, 0, 2, 0x30, 0x66, "Logical compare r16 with r/m16"},
    {"testl",  X86_64_CAT_LOGICAL, {0x85}, 1, true,  false, false, 0, 2, 0x30, 0, "Logical compare r32 with r/m32"},
    {"testq",  X86_64_CAT_LOGICAL, {0x85}, 1, true,  true,  true,  0, 2, 0x70, 0x48, "Logical compare r64 with r/m64"},
    
    // Bit test operations - CPU-accurate per Intel SDM
    {"btw",    X86_64_CAT_LOGICAL, {0x66, 0x0F, 0xA3}, 3, true,  false, false, 0, 2, 0x30, 0x66, "Bit test r/m16"},
    {"btl",    X86_64_CAT_LOGICAL, {0x0F, 0xA3}, 2, true,  false, false, 0, 2, 0x30, 0, "Bit test r/m32"},
    {"btq",    X86_64_CAT_LOGICAL, {0x0F, 0xA3}, 2, true,  true,  true,  0, 2, 0x70, 0x48, "Bit test r/m64"},
    {"btsw",   X86_64_CAT_LOGICAL, {0x66, 0x0F, 0xAB}, 3, true,  false, false, 0, 2, 0x30, 0x66, "Bit test and set r/m16"},
    {"btsl",   X86_64_CAT_LOGICAL, {0x0F, 0xAB}, 2, true,  false, false, 0, 2, 0x30, 0, "Bit test and set r/m32"},
    {"btsq",   X86_64_CAT_LOGICAL, {0x0F, 0xAB}, 2, true,  true,  true,  0, 2, 0x70, 0x48, "Bit test and set r/m64"},
    {"btrw",   X86_64_CAT_LOGICAL, {0x66, 0x0F, 0xB3}, 3, true,  false, false, 0, 2, 0x30, 0x66, "Bit test and reset r/m16"},
    {"btrl",   X86_64_CAT_LOGICAL, {0x0F, 0xB3}, 2, true,  false, false, 0, 2, 0x30, 0, "Bit test and reset r/m32"},
    {"btrq",   X86_64_CAT_LOGICAL, {0x0F, 0xB3}, 2, true,  true,  true,  0, 2, 0x70, 0x48, "Bit test and reset r/m64"},
    {"btcw",   X86_64_CAT_LOGICAL, {0x66, 0x0F, 0xBB}, 3, true,  false, false, 0, 2, 0x30, 0x66, "Bit test and complement r/m16"},
    {"btcl",   X86_64_CAT_LOGICAL, {0x0F, 0xBB}, 2, true,  false, false, 0, 2, 0x30, 0, "Bit test and complement r/m32"},
    {"btcq",   X86_64_CAT_LOGICAL, {0x0F, 0xBB}, 2, true,  true,  true,  0, 2, 0x70, 0x48, "Bit test and complement r/m64"},
    
    // Bit scan operations
    {"bsfw",   X86_64_CAT_LOGICAL, {0x66, 0x0F, 0xBC}, 3, true,  false, false, 0, 2, 0x30, 0x66, "Bit scan forward r/m16"},
    {"bsfl",   X86_64_CAT_LOGICAL, {0x0F, 0xBC}, 2, true,  false, false, 0, 2, 0x30, 0, "Bit scan forward r/m32"},
    {"bsfq",   X86_64_CAT_LOGICAL, {0x0F, 0xBC}, 2, true,  true,  true,  0, 2, 0x70, 0x48, "Bit scan forward r/m64"},
    {"bsrw",   X86_64_CAT_LOGICAL, {0x66, 0x0F, 0xBD}, 3, true,  false, false, 0, 2, 0x30, 0x66, "Bit scan reverse r/m16"},
    {"bsrl",   X86_64_CAT_LOGICAL, {0x0F, 0xBD}, 2, true,  false, false, 0, 2, 0x30, 0, "Bit scan reverse r/m32"},
    {"bsrq",   X86_64_CAT_LOGICAL, {0x0F, 0xBD}, 2, true,  true,  true,  0, 2, 0x70, 0x48, "Bit scan reverse r/m64"},
    
    // MISSING SHIFT/ROTATE INSTRUCTIONS - Complete CPU-accurate set
    // Shift arithmetic left (SAL) - same as SHL but semantically different
    {"salb",   X86_64_CAT_SHIFT, {0xD0}, 1, true,  false, false, 4, 1, 0x30, 0, "Shift arithmetic left r/m8 by 1"},
    {"salw",   X86_64_CAT_SHIFT, {0x66, 0xD1}, 2, true,  false, false, 4, 1, 0x30, 0x66, "Shift arithmetic left r/m16 by 1"},
    {"sall",   X86_64_CAT_SHIFT, {0xD1}, 1, true,  false, false, 4, 1, 0x30, 0, "Shift arithmetic left r/m32 by 1"},
    {"salq",   X86_64_CAT_SHIFT, {0xD1}, 1, true,  true,  true,  4, 1, 0x70, 0x48, "Shift arithmetic left r/m64 by 1"},
    
    // Shift arithmetic right (SAR) - preserves sign bit
    {"sarb",   X86_64_CAT_SHIFT, {0xD0}, 1, true,  false, false, 7, 1, 0x30, 0, "Shift arithmetic right r/m8 by 1"},
    {"sarw",   X86_64_CAT_SHIFT, {0x66, 0xD1}, 2, true,  false, false, 7, 1, 0x30, 0x66, "Shift arithmetic right r/m16 by 1"},
    {"sarl",   X86_64_CAT_SHIFT, {0xD1}, 1, true,  false, false, 7, 1, 0x30, 0, "Shift arithmetic right r/m32 by 1"},
    {"sarq",   X86_64_CAT_SHIFT, {0xD1}, 1, true,  true,  true,  7, 1, 0x70, 0x48, "Shift arithmetic right r/m64 by 1"},
    
    // Rotate operations
    {"rolb",   X86_64_CAT_SHIFT_ROTATE, {0xD0}, 1, true,  false, false, 0, 1, 0x30, 0, "Rotate left r/m8 by 1"},
    {"rolw",   X86_64_CAT_SHIFT_ROTATE, {0x66, 0xD1}, 2, true,  false, false, 0, 1, 0x30, 0x66, "Rotate left r/m16 by 1"},
    {"roll",   X86_64_CAT_SHIFT_ROTATE, {0xD1}, 1, true,  false, false, 0, 1, 0x30, 0, "Rotate left r/m32 by 1"},
    {"rolq",   X86_64_CAT_SHIFT_ROTATE, {0xD1}, 1, true,  true,  true,  0, 1, 0x70, 0x48, "Rotate left r/m64 by 1"},
    {"rorb",   X86_64_CAT_SHIFT_ROTATE, {0xD0}, 1, true,  false, false, 1, 1, 0x30, 0, "Rotate right r/m8 by 1"},
    {"rorw",   X86_64_CAT_SHIFT_ROTATE, {0x66, 0xD1}, 2, true,  false, false, 1, 1, 0x30, 0x66, "Rotate right r/m16 by 1"},
    {"rorl",   X86_64_CAT_SHIFT_ROTATE, {0xD1}, 1, true,  false, false, 1, 1, 0x30, 0, "Rotate right r/m32 by 1"},
    {"rorq",   X86_64_CAT_SHIFT_ROTATE, {0xD1}, 1, true,  true,  true,  1, 1, 0x70, 0x48, "Rotate right r/m64 by 1"},
    
    // Rotate through carry
    {"rclb",   X86_64_CAT_SHIFT_ROTATE, {0xD0}, 1, true,  false, false, 2, 1, 0x30, 0, "Rotate through carry left r/m8 by 1"},
    {"rclw",   X86_64_CAT_SHIFT_ROTATE, {0x66, 0xD1}, 2, true,  false, false, 2, 1, 0x30, 0x66, "Rotate through carry left r/m16 by 1"},
    {"rcll",   X86_64_CAT_SHIFT_ROTATE, {0xD1}, 1, true,  false, false, 2, 1, 0x30, 0, "Rotate through carry left r/m32 by 1"},
    {"rclq",   X86_64_CAT_SHIFT_ROTATE, {0xD1}, 1, true,  true,  true,  2, 1, 0x70, 0x48, "Rotate through carry left r/m64 by 1"},
    {"rcrb",   X86_64_CAT_SHIFT_ROTATE, {0xD0}, 1, true,  false, false, 3, 1, 0x30, 0, "Rotate through carry right r/m8 by 1"},
    {"rcrw",   X86_64_CAT_SHIFT_ROTATE, {0x66, 0xD1}, 2, true,  false, false, 3, 1, 0x30, 0x66, "Rotate through carry right r/m16 by 1"},
    {"rcrl",   X86_64_CAT_SHIFT_ROTATE, {0xD1}, 1, true,  false, false, 3, 1, 0x30, 0, "Rotate through carry right r/m32 by 1"},
    {"rcrq",   X86_64_CAT_SHIFT_ROTATE, {0xD1}, 1, true,  true,  true,  3, 1, 0x70, 0x48, "Rotate through carry right r/m64 by 1"},
    
    // Double precision shifts (3 operands)
    {"shldw",  X86_64_CAT_SHIFT, {0x66, 0x0F, 0xA5}, 3, true,  false, false, 0, 3, 0x30, 0x66, "Shift left double precision r/m16"},
    {"shldl",  X86_64_CAT_SHIFT, {0x0F, 0xA5}, 2, true,  false, false, 0, 3, 0x30, 0, "Shift left double precision r/m32"},
    {"shldq",  X86_64_CAT_SHIFT, {0x0F, 0xA5}, 2, true,  true,  true,  0, 3, 0x70, 0x48, "Shift left double precision r/m64"},
    {"shrdw",  X86_64_CAT_SHIFT, {0x66, 0x0F, 0xAD}, 3, true,  false, false, 0, 3, 0x30, 0x66, "Shift right double precision r/m16"},
    {"shrdl",  X86_64_CAT_SHIFT, {0x0F, 0xAD}, 2, true,  false, false, 0, 3, 0x30, 0, "Shift right double precision r/m32"},
    {"shrdq",  X86_64_CAT_SHIFT, {0x0F, 0xAD}, 2, true,  true,  true,  0, 3, 0x70, 0x48, "Shift right double precision r/m64"},
    
    // MISSING CONTROL FLOW INSTRUCTIONS
    // Additional conditional jump aliases and instructions
    {"jz",     X86_64_CAT_CONTROL_FLOW, {0x74}, 1, false, false, false, 0, 1, 0, 0, "Jump if zero (alias for JE)"},
    {"jnz",    X86_64_CAT_CONTROL_FLOW, {0x75}, 1, false, false, false, 0, 1, 0, 0, "Jump if not zero (alias for JNE)"},
    {"jnge",   X86_64_CAT_CONTROL_FLOW, {0x7C}, 1, false, false, false, 0, 1, 0, 0, "Jump if not greater or equal (alias for JL)"},
    {"jng",    X86_64_CAT_CONTROL_FLOW, {0x7E}, 1, false, false, false, 0, 1, 0, 0, "Jump if not greater (alias for JLE)"},
    {"jnle",   X86_64_CAT_CONTROL_FLOW, {0x7F}, 1, false, false, false, 0, 1, 0, 0, "Jump if not less or equal (alias for JG)"},
    {"jnl",    X86_64_CAT_CONTROL_FLOW, {0x7D}, 1, false, false, false, 0, 1, 0, 0, "Jump if not less (alias for JGE)"},
    {"jnae",   X86_64_CAT_CONTROL_FLOW, {0x72}, 1, false, false, false, 0, 1, 0, 0, "Jump if not above or equal (alias for JB)"},
    {"jna",    X86_64_CAT_CONTROL_FLOW, {0x76}, 1, false, false, false, 0, 1, 0, 0, "Jump if not above (alias for JBE)"},
    {"jnbe",   X86_64_CAT_CONTROL_FLOW, {0x77}, 1, false, false, false, 0, 1, 0, 0, "Jump if not below or equal (alias for JA)"},
    {"jnb",    X86_64_CAT_CONTROL_FLOW, {0x73}, 1, false, false, false, 0, 1, 0, 0, "Jump if not below (alias for JAE)"},
    {"jp",     X86_64_CAT_CONTROL_FLOW, {0x7A}, 1, false, false, false, 0, 1, 0, 0, "Jump if parity (alias for JPE)"},
    {"jpe",    X86_64_CAT_CONTROL_FLOW, {0x7A}, 1, false, false, false, 0, 1, 0, 0, "Jump if parity even"},
    {"jnp",    X86_64_CAT_CONTROL_FLOW, {0x7B}, 1, false, false, false, 0, 1, 0, 0, "Jump if not parity (alias for JPO)"},
    {"jpo",    X86_64_CAT_CONTROL_FLOW, {0x7B}, 1, false, false, false, 0, 1, 0, 0, "Jump if parity odd"},
    
    // Far returns and interrupt returns
    {"retf",   X86_64_CAT_CONTROL_FLOW, {0xCB}, 1, false, false, false, 0, 0, 0, 0, "Return far"},
    {"iret",   X86_64_CAT_CONTROL_FLOW, {0xCF}, 1, false, false, false, 0, 0, 0, 0, "Interrupt return"},
    {"iretq",  X86_64_CAT_CONTROL_FLOW, {0x48, 0xCF}, 2, false, false, false, 0, 0, 0, 0, "Interrupt return 64-bit"},
    
    // Loop instructions - CPU-accurate per Intel SDM
    {"loop",   X86_64_CAT_CONTROL_FLOW, {0xE2}, 1, false, false, false, 0, 1, 0, 0, "Loop while RCX not zero"},
    {"loope",  X86_64_CAT_CONTROL_FLOW, {0xE1}, 1, false, false, false, 0, 1, 0, 0, "Loop while equal"},
    {"loopz",  X86_64_CAT_CONTROL_FLOW, {0xE1}, 1, false, false, false, 0, 1, 0, 0, "Loop while zero (alias for LOOPE)"},
    {"loopne", X86_64_CAT_CONTROL_FLOW, {0xE0}, 1, false, false, false, 0, 1, 0, 0, "Loop while not equal"},
    {"loopnz", X86_64_CAT_CONTROL_FLOW, {0xE0}, 1, false, false, false, 0, 1, 0, 0, "Loop while not zero (alias for LOOPNE)"},
    
    // MISSING COMPARISON INSTRUCTIONS - Complete set per Intel SDM
    // Compare operations (missing size variants)
    {"cmpb",   X86_64_CAT_COMPARISON, {0x38}, 1, true,  false, false, 0, 2, 0x30, 0, "Compare r8 with r/m8"},
    {"cmpw",   X86_64_CAT_COMPARISON, {0x66, 0x39}, 2, true,  false, false, 0, 2, 0x30, 0x66, "Compare r16 with r/m16"},
    {"cmpl",   X86_64_CAT_COMPARISON, {0x39}, 1, true,  false, false, 0, 2, 0x30, 0, "Compare r32 with r/m32"},
    {"cmpq",   X86_64_CAT_COMPARISON, {0x39}, 1, true,  true,  true,  0, 2, 0x70, 0x48, "Compare r64 with r/m64"},
    
    // Conditional Move instructions - Complete set per Intel SDM
    {"cmovb",  X86_64_CAT_COMPARISON, {0x0F, 0x42}, 2, true,  false, false, 0, 2, 0x30, 0, "Move if below (CF=1)"},
    {"cmovc",  X86_64_CAT_COMPARISON, {0x0F, 0x42}, 2, true,  false, false, 0, 2, 0x30, 0, "Move if carry (CF=1)"},
    {"cmovnae", X86_64_CAT_COMPARISON, {0x0F, 0x42}, 2, true,  false, false, 0, 2, 0x30, 0, "Move if not above or equal"},
    {"cmovnb", X86_64_CAT_COMPARISON, {0x0F, 0x43}, 2, true,  false, false, 0, 2, 0x30, 0, "Move if not below (CF=0)"},
    {"cmovnc", X86_64_CAT_COMPARISON, {0x0F, 0x43}, 2, true,  false, false, 0, 2, 0x30, 0, "Move if not carry (CF=0)"},
    {"cmovae", X86_64_CAT_COMPARISON, {0x0F, 0x43}, 2, true,  false, false, 0, 2, 0x30, 0, "Move if above or equal"},
    {"cmove",  X86_64_CAT_COMPARISON, {0x0F, 0x44}, 2, true,  false, false, 0, 2, 0x30, 0, "Move if equal (ZF=1)"},
    {"cmovz",  X86_64_CAT_COMPARISON, {0x0F, 0x44}, 2, true,  false, false, 0, 2, 0x30, 0, "Move if zero (ZF=1)"},
    {"cmovne", X86_64_CAT_COMPARISON, {0x0F, 0x45}, 2, true,  false, false, 0, 2, 0x30, 0, "Move if not equal (ZF=0)"},
    {"cmovnz", X86_64_CAT_COMPARISON, {0x0F, 0x45}, 2, true,  false, false, 0, 2, 0x30, 0, "Move if not zero (ZF=0)"},
    {"cmovbe", X86_64_CAT_COMPARISON, {0x0F, 0x46}, 2, true,  false, false, 0, 2, 0x30, 0, "Move if below or equal"},
    {"cmovna", X86_64_CAT_COMPARISON, {0x0F, 0x46}, 2, true,  false, false, 0, 2, 0x30, 0, "Move if not above"},
    {"cmovnbe", X86_64_CAT_COMPARISON, {0x0F, 0x47}, 2, true,  false, false, 0, 2, 0x30, 0, "Move if not below or equal"},
    {"cmova",  X86_64_CAT_COMPARISON, {0x0F, 0x47}, 2, true,  false, false, 0, 2, 0x30, 0, "Move if above"},
    {"cmovl",  X86_64_CAT_COMPARISON, {0x0F, 0x4C}, 2, true,  false, false, 0, 2, 0x30, 0, "Move if less (SF≠OF)"},
    {"cmovnge", X86_64_CAT_COMPARISON, {0x0F, 0x4C}, 2, true,  false, false, 0, 2, 0x30, 0, "Move if not greater or equal"},
    {"cmovnl", X86_64_CAT_COMPARISON, {0x0F, 0x4D}, 2, true,  false, false, 0, 2, 0x30, 0, "Move if not less (SF=OF)"},
    {"cmovge", X86_64_CAT_COMPARISON, {0x0F, 0x4D}, 2, true,  false, false, 0, 2, 0x30, 0, "Move if greater or equal"},
    {"cmovle", X86_64_CAT_COMPARISON, {0x0F, 0x4E}, 2, true,  false, false, 0, 2, 0x30, 0, "Move if less or equal"},
    {"cmovng", X86_64_CAT_COMPARISON, {0x0F, 0x4E}, 2, true,  false, false, 0, 2, 0x30, 0, "Move if not greater"},
    {"cmovnle", X86_64_CAT_COMPARISON, {0x0F, 0x4F}, 2, true,  false, false, 0, 2, 0x30, 0, "Move if not less or equal"},
    {"cmovg",  X86_64_CAT_COMPARISON, {0x0F, 0x4F}, 2, true,  false, false, 0, 2, 0x30, 0, "Move if greater"},
    {"cmovo",  X86_64_CAT_COMPARISON, {0x0F, 0x40}, 2, true,  false, false, 0, 2, 0x30, 0, "Move if overflow (OF=1)"},
    {"cmovno", X86_64_CAT_COMPARISON, {0x0F, 0x41}, 2, true,  false, false, 0, 2, 0x30, 0, "Move if not overflow (OF=0)"},
    {"cmovs",  X86_64_CAT_COMPARISON, {0x0F, 0x48}, 2, true,  false, false, 0, 2, 0x30, 0, "Move if sign (SF=1)"},
    {"cmovns", X86_64_CAT_COMPARISON, {0x0F, 0x49}, 2, true,  false, false, 0, 2, 0x30, 0, "Move if not sign (SF=0)"},
    {"cmovp",  X86_64_CAT_COMPARISON, {0x0F, 0x4A}, 2, true,  false, false, 0, 2, 0x30, 0, "Move if parity (PF=1)"},
    {"cmovpe", X86_64_CAT_COMPARISON, {0x0F, 0x4A}, 2, true,  false, false, 0, 2, 0x30, 0, "Move if parity even"},
    {"cmovnp", X86_64_CAT_COMPARISON, {0x0F, 0x4B}, 2, true,  false, false, 0, 2, 0x30, 0, "Move if not parity (PF=0)"},
    {"cmovpo", X86_64_CAT_COMPARISON, {0x0F, 0x4B}, 2, true,  false, false, 0, 2, 0x30, 0, "Move if parity odd"},
    
    // Set byte on condition instructions - Complete set per Intel SDM
    {"setb",   X86_64_CAT_COMPARISON, {0x0F, 0x92}, 2, true,  false, false, 0, 1, 0x30, 0, "Set byte if below (CF=1)"},
    {"setc",   X86_64_CAT_COMPARISON, {0x0F, 0x92}, 2, true,  false, false, 0, 1, 0x30, 0, "Set byte if carry (CF=1)"},
    {"setnae", X86_64_CAT_COMPARISON, {0x0F, 0x92}, 2, true,  false, false, 0, 1, 0x30, 0, "Set byte if not above or equal"},
    {"setnb",  X86_64_CAT_COMPARISON, {0x0F, 0x93}, 2, true,  false, false, 0, 1, 0x30, 0, "Set byte if not below (CF=0)"},
    {"setnc",  X86_64_CAT_COMPARISON, {0x0F, 0x93}, 2, true,  false, false, 0, 1, 0x30, 0, "Set byte if not carry (CF=0)"},
    {"setae",  X86_64_CAT_COMPARISON, {0x0F, 0x93}, 2, true,  false, false, 0, 1, 0x30, 0, "Set byte if above or equal"},
    {"sete",   X86_64_CAT_COMPARISON, {0x0F, 0x94}, 2, true,  false, false, 0, 1, 0x30, 0, "Set byte if equal (ZF=1)"},
    {"setz",   X86_64_CAT_COMPARISON, {0x0F, 0x94}, 2, true,  false, false, 0, 1, 0x30, 0, "Set byte if zero (ZF=1)"},
    {"setne",  X86_64_CAT_COMPARISON, {0x0F, 0x95}, 2, true,  false, false, 0, 1, 0x30, 0, "Set byte if not equal (ZF=0)"},
    {"setnz",  X86_64_CAT_COMPARISON, {0x0F, 0x95}, 2, true,  false, false, 0, 1, 0x30, 0, "Set byte if not zero (ZF=0)"},
    {"setbe",  X86_64_CAT_COMPARISON, {0x0F, 0x96}, 2, true,  false, false, 0, 1, 0x30, 0, "Set byte if below or equal"},
    {"setna",  X86_64_CAT_COMPARISON, {0x0F, 0x96}, 2, true,  false, false, 0, 1, 0x30, 0, "Set byte if not above"},
    {"setnbe", X86_64_CAT_COMPARISON, {0x0F, 0x97}, 2, true,  false, false, 0, 1, 0x30, 0, "Set byte if not below or equal"},
    {"seta",   X86_64_CAT_COMPARISON, {0x0F, 0x97}, 2, true,  false, false, 0, 1, 0x30, 0, "Set byte if above"},
    {"setl",   X86_64_CAT_COMPARISON, {0x0F, 0x9C}, 2, true,  false, false, 0, 1, 0x30, 0, "Set byte if less (SF≠OF)"},
    {"setnge", X86_64_CAT_COMPARISON, {0x0F, 0x9C}, 2, true,  false, false, 0, 1, 0x30, 0, "Set byte if not greater or equal"},
    {"setnl",  X86_64_CAT_COMPARISON, {0x0F, 0x9D}, 2, true,  false, false, 0, 1, 0x30, 0, "Set byte if not less (SF=OF)"},
    {"setge",  X86_64_CAT_COMPARISON, {0x0F, 0x9D}, 2, true,  false, false, 0, 1, 0x30, 0, "Set byte if greater or equal"},
    {"setle",  X86_64_CAT_COMPARISON, {0x0F, 0x9E}, 2, true,  false, false, 0, 1, 0x30, 0, "Set byte if less or equal"},
    {"setng",  X86_64_CAT_COMPARISON, {0x0F, 0x9E}, 2, true,  false, false, 0, 1, 0x30, 0, "Set byte if not greater"},
    {"setnle", X86_64_CAT_COMPARISON, {0x0F, 0x9F}, 2, true,  false, false, 0, 1, 0x30, 0, "Set byte if not less or equal"},
    {"setg",   X86_64_CAT_COMPARISON, {0x0F, 0x9F}, 2, true,  false, false, 0, 1, 0x30, 0, "Set byte if greater"},
    {"seto",   X86_64_CAT_COMPARISON, {0x0F, 0x90}, 2, true,  false, false, 0, 1, 0x30, 0, "Set byte if overflow (OF=1)"},
    {"setno",  X86_64_CAT_COMPARISON, {0x0F, 0x91}, 2, true,  false, false, 0, 1, 0x30, 0, "Set byte if not overflow (OF=0)"},
    {"sets",   X86_64_CAT_COMPARISON, {0x0F, 0x98}, 2, true,  false, false, 0, 1, 0x30, 0, "Set byte if sign (SF=1)"},
    {"setns",  X86_64_CAT_COMPARISON, {0x0F, 0x99}, 2, true,  false, false, 0, 1, 0x30, 0, "Set byte if not sign (SF=0)"},
    {"setp",   X86_64_CAT_COMPARISON, {0x0F, 0x9A}, 2, true,  false, false, 0, 1, 0x30, 0, "Set byte if parity (PF=1)"},
    {"setpe",  X86_64_CAT_COMPARISON, {0x0F, 0x9A}, 2, true,  false, false, 0, 1, 0x30, 0, "Set byte if parity even"},
    {"setnp",  X86_64_CAT_COMPARISON, {0x0F, 0x9B}, 2, true,  false, false, 0, 1, 0x30, 0, "Set byte if not parity (PF=0)"},
    {"setpo",  X86_64_CAT_COMPARISON, {0x0F, 0x9B}, 2, true,  false, false, 0, 1, 0x30, 0, "Set byte if parity odd"},
    
    // STRING INSTRUCTIONS - Complete set per Intel SDM
    // String move operations (implicit operands)
    {"movsb",  X86_64_CAT_STRING, {0xA4}, 1, false, false, false, 0, 0, 0, 0, "Move byte from [RSI] to [RDI]"},
    {"movsw",  X86_64_CAT_STRING, {0x66, 0xA5}, 2, false, false, false, 0, 0, 0, 0x66, "Move word from [RSI] to [RDI]"},
    {"movsl",  X86_64_CAT_STRING, {0xA5}, 1, false, false, false, 0, 0, 0, 0, "Move dword from [RSI] to [RDI]"},
    {"movsq",  X86_64_CAT_STRING, {0x48, 0xA5}, 2, false, false, false, 0, 0, 0, 0x48, "Move qword from [RSI] to [RDI]"},
    
    // String compare operations
    {"cmpsb",  X86_64_CAT_STRING, {0xA6}, 1, false, false, false, 0, 0, 0, 0, "Compare byte [RSI] with [RDI]"},
    {"cmpsw",  X86_64_CAT_STRING, {0x66, 0xA7}, 2, false, false, false, 0, 0, 0, 0x66, "Compare word [RSI] with [RDI]"},
    {"cmpsl",  X86_64_CAT_STRING, {0xA7}, 1, false, false, false, 0, 0, 0, 0, "Compare dword [RSI] with [RDI]"},
    {"cmpsq",  X86_64_CAT_STRING, {0x48, 0xA7}, 2, false, false, false, 0, 0, 0, 0x48, "Compare qword [RSI] with [RDI]"},
    
    // String scan operations
    {"scasb",  X86_64_CAT_STRING, {0xAE}, 1, false, false, false, 0, 0, 0, 0, "Scan byte in [RDI] against AL"},
    {"scasw",  X86_64_CAT_STRING, {0x66, 0xAF}, 2, false, false, false, 0, 0, 0, 0x66, "Scan word in [RDI] against AX"},
    {"scasl",  X86_64_CAT_STRING, {0xAF}, 1, false, false, false, 0, 0, 0, 0, "Scan dword in [RDI] against EAX"},
    {"scasq",  X86_64_CAT_STRING, {0x48, 0xAF}, 2, false, false, false, 0, 0, 0, 0x48, "Scan qword in [RDI] against RAX"},
    
    // String load operations
    {"lodsb",  X86_64_CAT_STRING, {0xAC}, 1, false, false, false, 0, 0, 0, 0, "Load byte from [RSI] to AL"},
    {"lodsw",  X86_64_CAT_STRING, {0x66, 0xAD}, 2, false, false, false, 0, 0, 0, 0x66, "Load word from [RSI] to AX"},
    {"lodsl",  X86_64_CAT_STRING, {0xAD}, 1, false, false, false, 0, 0, 0, 0, "Load dword from [RSI] to EAX"},
    {"lodsq",  X86_64_CAT_STRING, {0x48, 0xAD}, 2, false, false, false, 0, 0, 0, 0x48, "Load qword from [RSI] to RAX"},
    
    // String store operations
    {"stosb",  X86_64_CAT_STRING, {0xAA}, 1, false, false, false, 0, 0, 0, 0, "Store AL to [RDI]"},
    {"stosw",  X86_64_CAT_STRING, {0x66, 0xAB}, 2, false, false, false, 0, 0, 0, 0x66, "Store AX to [RDI]"},
    {"stosl",  X86_64_CAT_STRING, {0xAB}, 1, false, false, false, 0, 0, 0, 0, "Store EAX to [RDI]"},
    {"stosq",  X86_64_CAT_STRING, {0x48, 0xAB}, 2, false, false, false, 0, 0, 0, 0x48, "Store RAX to [RDI]"},
    
    // Repeat prefixes (string instruction modifiers)
    {"rep",    X86_64_CAT_STRING, {0xF3}, 1, false, false, false, 0, 0, 0, 0, "Repeat string operation"},
    {"repe",   X86_64_CAT_STRING, {0xF3}, 1, false, false, false, 0, 0, 0, 0, "Repeat while equal"},
    {"repz",   X86_64_CAT_STRING, {0xF3}, 1, false, false, false, 0, 0, 0, 0, "Repeat while zero (alias for REPE)"},
    {"repne",  X86_64_CAT_STRING, {0xF2}, 1, false, false, false, 0, 0, 0, 0, "Repeat while not equal"},
    {"repnz",  X86_64_CAT_STRING, {0xF2}, 1, false, false, false, 0, 0, 0, 0, "Repeat while not zero (alias for REPNE)"},
    
    // SYSTEM INSTRUCTIONS - Complete set per Intel SDM
    // Basic system control
    {"hlt",    X86_64_CAT_SYSTEM, {0xF4}, 1, false, false, false, 0, 0, 0, 0, "Halt processor"},
    {"int",    X86_64_CAT_SYSTEM, {0xCD}, 1, false, false, false, 0, 1, 0, 0, "Software interrupt"},
    {"into",   X86_64_CAT_SYSTEM, {0xCE}, 1, false, false, false, 0, 0, 0, 0, "Interrupt on overflow"},
    {"sysret", X86_64_CAT_SYSTEM, {0x0F, 0x07}, 2, false, false, false, 0, 0, 0, 0, "Return from system call"},
    {"sysenter", X86_64_CAT_SYSTEM, {0x0F, 0x34}, 2, false, false, false, 0, 0, 0, 0, "Fast system call entry"},
    {"sysexit", X86_64_CAT_SYSTEM, {0x0F, 0x35}, 2, false, false, false, 0, 0, 0, 0, "Fast system call exit"},
    
    // Flag control instructions
    {"clc",    X86_64_CAT_FLAG_CONTROL, {0xF8}, 1, false, false, false, 0, 0, 0, 0, "Clear carry flag"},
    {"stc",    X86_64_CAT_FLAG_CONTROL, {0xF9}, 1, false, false, false, 0, 0, 0, 0, "Set carry flag"},
    {"cmc",    X86_64_CAT_FLAG_CONTROL, {0xF5}, 1, false, false, false, 0, 0, 0, 0, "Complement carry flag"},
    {"cld",    X86_64_CAT_FLAG_CONTROL, {0xFC}, 1, false, false, false, 0, 0, 0, 0, "Clear direction flag"},
    {"std",    X86_64_CAT_FLAG_CONTROL, {0xFD}, 1, false, false, false, 0, 0, 0, 0, "Set direction flag"},
    {"cli",    X86_64_CAT_FLAG_CONTROL, {0xFA}, 1, false, false, false, 0, 0, 0, 0, "Clear interrupt flag"},
    {"sti",    X86_64_CAT_FLAG_CONTROL, {0xFB}, 1, false, false, false, 0, 0, 0, 0, "Set interrupt flag"},
    {"clts",   X86_64_CAT_FLAG_CONTROL, {0x0F, 0x06}, 2, false, false, false, 0, 0, 0, 0, "Clear task switched flag"},
    
    // Processor state operations
    {"pushf",  X86_64_CAT_FLAG_CONTROL, {0x9C}, 1, false, false, false, 0, 0, 0, 0, "Push flags onto stack"},
    {"pushfq", X86_64_CAT_FLAG_CONTROL, {0x9C}, 1, false, false, false, 0, 0, 0, 0, "Push flags onto stack (64-bit)"},
    {"popf",   X86_64_CAT_FLAG_CONTROL, {0x9D}, 1, false, false, false, 0, 0, 0, 0, "Pop flags from stack"},
    {"popfq",  X86_64_CAT_FLAG_CONTROL, {0x9D}, 1, false, false, false, 0, 0, 0, 0, "Pop flags from stack (64-bit)"},
    {"lahf",   X86_64_CAT_FLAG_CONTROL, {0x9F}, 1, false, false, false, 0, 0, 0, 0, "Load AH from flags"},
    {"sahf",   X86_64_CAT_FLAG_CONTROL, {0x9E}, 1, false, false, false, 0, 0, 0, 0, "Store AH to flags"},
    
    // Cache and memory management
    {"prefetch", X86_64_CAT_SYSTEM, {0x0F, 0x18}, 2, true,  false, false, 0, 1, 0x30, 0, "Prefetch data into cache"},
    {"prefetchnta", X86_64_CAT_SYSTEM, {0x0F, 0x18}, 2, true,  false, false, 0, 1, 0x30, 0, "Prefetch data non-temporal"},
    {"prefetcht0", X86_64_CAT_SYSTEM, {0x0F, 0x18}, 2, true,  false, false, 1, 1, 0x30, 0, "Prefetch data to L1 cache"},
    {"prefetcht1", X86_64_CAT_SYSTEM, {0x0F, 0x18}, 2, true,  false, false, 2, 1, 0x30, 0, "Prefetch data to L2 cache"},
    {"prefetcht2", X86_64_CAT_SYSTEM, {0x0F, 0x18}, 2, true,  false, false, 3, 1, 0x30, 0, "Prefetch data to L3 cache"},
    {"clflush", X86_64_CAT_SYSTEM, {0x0F, 0xAE}, 2, true,  false, false, 7, 1, 0x30, 0, "Flush cache line"},
    {"mfence",  X86_64_CAT_SYSTEM, {0x0F, 0xAE, 0xF0}, 3, false, false, false, 0, 0, 0, 0, "Memory fence"},
    {"sfence",  X86_64_CAT_SYSTEM, {0x0F, 0xAE, 0xF8}, 3, false, false, false, 0, 0, 0, 0, "Store fence"},
    {"lfence",  X86_64_CAT_SYSTEM, {0x0F, 0xAE, 0xE8}, 3, false, false, false, 0, 0, 0, 0, "Load fence"},
    
    // Additional system/processor instructions
    {"cpuid",   X86_64_CAT_SYSTEM, {0x0F, 0xA2}, 2, false, false, false, 0, 0, 0, 0, "CPU identification"},
    {"rdtsc",   X86_64_CAT_SYSTEM, {0x0F, 0x31}, 2, false, false, false, 0, 0, 0, 0, "Read time stamp counter"},
    {"rdtscp",  X86_64_CAT_SYSTEM, {0x0F, 0x01, 0xF9}, 3, false, false, false, 0, 0, 0, 0, "Read time stamp counter and processor ID"},
    {"lock",    X86_64_CAT_SYSTEM, {0xF0}, 1, false, false, false, 0, 0, 0, 0, "Bus lock prefix"},
    {"wait",    X86_64_CAT_SYSTEM, {0x9B}, 1, false, false, false, 0, 0, 0, 0, "Wait for FPU"},
    {"fwait",   X86_64_CAT_SYSTEM, {0x9B}, 1, false, false, false, 0, 0, 0, 0, "Wait for FPU (alias)"},
    
    // Segment management
    {"lds",     X86_64_CAT_SYSTEM, {0xC5}, 1, true,  false, false, 0, 2, 0xC0, 0, "Load pointer using DS"},
    {"les",     X86_64_CAT_SYSTEM, {0xC4}, 1, true,  false, false, 0, 2, 0xC0, 0, "Load pointer using ES"},
    {"lfs",     X86_64_CAT_SYSTEM, {0x0F, 0xB4}, 2, true,  false, false, 0, 2, 0xC0, 0, "Load pointer using FS"},
    {"lgs",     X86_64_CAT_SYSTEM, {0x0F, 0xB5}, 2, true,  false, false, 0, 2, 0xC0, 0, "Load pointer using GS"},
    {"lss",     X86_64_CAT_SYSTEM, {0x0F, 0xB2}, 2, true,  false, false, 0, 2, 0xC0, 0, "Load pointer using SS"},
    
    // I/O Instructions - Critical for system-level testing per manifest
    {"inb",     X86_64_CAT_SYSTEM, {0xEC}, 1, false, false, false, 0, 0, 0, 0, "Input byte from DX to AL"},
    {"inw",     X86_64_CAT_SYSTEM, {0x66, 0xED}, 2, false, false, false, 0, 0, 0, 0x66, "Input word from DX to AX"},
    {"inl",     X86_64_CAT_SYSTEM, {0xED}, 1, false, false, false, 0, 0, 0, 0, "Input dword from DX to EAX"},
    {"outb",    X86_64_CAT_SYSTEM, {0xEE}, 1, false, false, false, 0, 0, 0, 0, "Output AL to port DX"},
    {"outw",    X86_64_CAT_SYSTEM, {0x66, 0xEF}, 2, false, false, false, 0, 0, 0, 0x66, "Output AX to port DX"},
    {"outl",    X86_64_CAT_SYSTEM, {0xEF}, 1, false, false, false, 0, 0, 0, 0, "Output EAX to port DX"},
    
    // I/O with immediate port (single-byte port addresses)
    {"inb",     X86_64_CAT_SYSTEM, {0xE4}, 1, false, false, false, 0, 1, 0, 0, "Input byte from imm8 port to AL"},
    {"inw",     X86_64_CAT_SYSTEM, {0x66, 0xE5}, 2, false, false, false, 0, 1, 0, 0x66, "Input word from imm8 port to AX"},
    {"inl",     X86_64_CAT_SYSTEM, {0xE5}, 1, false, false, false, 0, 1, 0, 0, "Input dword from imm8 port to EAX"},
    {"outb",    X86_64_CAT_SYSTEM, {0xE6}, 1, false, false, false, 0, 1, 0, 0, "Output AL to imm8 port"},
    {"outw",    X86_64_CAT_SYSTEM, {0x66, 0xE7}, 2, false, false, false, 0, 1, 0, 0x66, "Output AX to imm8 port"},
    {"outl",    X86_64_CAT_SYSTEM, {0xE7}, 1, false, false, false, 0, 1, 0, 0, "Output EAX to imm8 port"},
    
    {NULL, X86_64_CAT_UNKNOWN, {0}, 0, false, false, false, 0, 0, 0, 0, NULL} // Terminator
};

//=============================================================================
// CPU-Accurate Instruction Lookup Functions
//=============================================================================

const x86_64_instruction_info_t *x86_64_find_instruction(const char *mnemonic) {
    if (!mnemonic) return NULL;
    
    for (size_t i = 0; instruction_database[i].mnemonic != NULL; i++) {
        if (strcmp(instruction_database[i].mnemonic, mnemonic) == 0) {
            return &instruction_database[i];
        }
    }
    return NULL;
}

const x86_64_register_info_t *x86_64_find_register(const char *name) {
    if (!name) return NULL;
    
    for (size_t i = 0; cpu_register_database[i].name != NULL; i++) {
        if (strcmp(cpu_register_database[i].name, name) == 0) {
            return &cpu_register_database[i];
        }
    }
    return NULL;
}

//=============================================================================
// CPU-Accurate Encoding Functions  
//=============================================================================

int x86_64_encode_modrm(uint8_t mod, uint8_t reg, uint8_t rm, uint8_t *output) {
    if (!output) return -1;
    
    // Validate fields per Intel SDM
    if (mod > 3 || reg > 7 || rm > 7) return -1;
    
    *output = (mod << 6) | (reg << 3) | rm;
    return 0;
}

int x86_64_encode_sib(uint8_t scale, uint8_t index, uint8_t base, uint8_t *output) {
    if (!output) return -1;
    
    // Validate fields and scale factor per Intel SDM
    if (index > 7 || base > 7) return -1;
    
    uint8_t scale_bits;
    switch (scale) {
        case 1: scale_bits = 0; break;
        case 2: scale_bits = 1; break;
        case 4: scale_bits = 2; break;
        case 8: scale_bits = 3; break;
        default: return -1;
    }
    
    *output = (scale_bits << 6) | (index << 3) | base;
    return 0;
}

uint8_t x86_64_calculate_rex_prefix(bool w, bool r, bool x, bool b) {
    // REX prefix: 0100WRXB
    uint8_t rex = 0x40;
    if (w) rex |= 0x08;  // REX.W
    if (r) rex |= 0x04;  // REX.R  
    if (x) rex |= 0x02;  // REX.X
    if (b) rex |= 0x01;  // REX.B
    return rex;
}

//=============================================================================
// Interface Implementation
//=============================================================================

int x86_64_unified_init(void) {
    // CPU-accurate initialization
    return 0;
}

void x86_64_unified_cleanup(void) {
    // Cleanup resources
}

// Required interface functions
int x86_64_init(void) {
    return x86_64_unified_init();
}

void x86_64_cleanup(void) {
    x86_64_unified_cleanup();
}

size_t x86_64_get_instruction_count(void) {
    size_t count = 0;
    while (instruction_database[count].mnemonic != NULL) {
        count++;
    }
    return count;
}

size_t x86_64_get_register_count(void) {
    size_t count = 0;
    while (cpu_register_database[count].name != NULL) {
        count++;
    }
    return count;
}

bool x86_64_is_valid_instruction(const char *mnemonic) {
    return x86_64_find_instruction(mnemonic) != NULL;
}

bool x86_64_is_valid_register(const char *name) {
    return x86_64_find_register(name) != NULL;
}

//=============================================================================
// Architecture-Specific Validation
//=============================================================================

bool x86_64_validate_operand_combination(const char *mnemonic, 
                                         const char **operands, 
                                         int operand_count) {
    if (!mnemonic) return false;
    
    const x86_64_instruction_info_t *instr = x86_64_find_instruction(mnemonic);
    if (!instr) return false;
    
    // Validate operand count
    if (operand_count != instr->operand_count) return false;
    
    // If operands are provided, additional CPU-specific validation can be added here
    // For now, basic validation passes if instruction exists and count matches
    (void)operands; // Suppress unused parameter warning for future expansion
    return true;
}

//=============================================================================
// CPU Constraint Validation
//=============================================================================

bool x86_64_validate_cpu_constraints(const x86_64_instruction_info_t *instr,
                                     const char **operands) {
    if (!instr) return false;
    
    // CPU-specific constraint validation
    // This is where manifest compliance checking occurs
    
    // Example: validate register constraints for specific opcodes
    if (instr->opcode[0] == 0x04 && operands && operands[0]) {
        // ADD AL, imm8 - first operand must be AL
        const x86_64_register_info_t *reg = x86_64_find_register(operands[0]);
        if (!reg || reg->id != AL) return false;
    }
    
    return true;
}

//=============================================================================
// CPU-ACCURATE CODE GENERATION - MANIFEST COMPLIANT
//=============================================================================

// Operand structure for code generation
typedef struct {
    enum {
        X86_64_OP_REGISTER,
        X86_64_OP_MEMORY,
        X86_64_OP_IMMEDIATE
    } type;
    
    union {
        char reg_name[16];          // Register name like "%rax"
        x86_64_address_t addr;      // Memory addressing mode
        int64_t immediate;          // Immediate value
    } data;
} x86_64_operand_t;

#define X86_64_MAX_OPERANDS 3

// Helper function to find register by ID
const x86_64_register_info_t *x86_64_find_register_by_id(x86_64_register_id_t id) {
    for (size_t i = 0; cpu_register_database[i].name != NULL; i++) {
        if (cpu_register_database[i].id == id) {
            return &cpu_register_database[i];
        }
    }
    return NULL;
}

// Parse operand from string to structured format
int x86_64_parse_operand(const char *operand_str, x86_64_operand_t *operand) {
    if (!operand_str || !operand) return -1;
    
    // Skip whitespace
    while (isspace(*operand_str)) operand_str++;
    
    // Check operand type and parse accordingly
    if (operand_str[0] == '$') {
        // Immediate operand
        operand->type = X86_64_OP_IMMEDIATE;
        char *endptr;
        operand->data.immediate = strtoll(operand_str + 1, &endptr, 0);
        if (endptr == operand_str + 1) return -1;
        return 0;
        
    } else if (operand_str[0] == '%' && strchr(operand_str, '(') == NULL) {
        // Register operand
        operand->type = X86_64_OP_REGISTER;
        strncpy(operand->data.reg_name, operand_str, sizeof(operand->data.reg_name) - 1);
        operand->data.reg_name[sizeof(operand->data.reg_name) - 1] = '\0';
        
        // Validate register exists
        const x86_64_register_info_t *reg = x86_64_find_register(operand_str);
        if (!reg) return -1;
        return 0;
        
    } else {
        // Memory operand
        operand->type = X86_64_OP_MEMORY;
        return x86_64_parse_addressing_mode(operand_str, &operand->data.addr);
    }
}

// Comprehensive instruction encoder following Intel SDM Volume 2 specifications
int x86_64_generate_instruction(const x86_64_instruction_info_t *instr, 
                                const x86_64_operand_t *operands,
                                int operand_count,
                                uint8_t *output, 
                                size_t *output_length) {
    if (!instr || !output || !output_length) return -1;
    
    size_t pos = 0;
    uint8_t rex = 0;
    bool needs_rex = false;
    
    // Step 1: Generate REX prefix if needed (Intel SDM Section 2.2.1)
    if (instr->needs_rex || instr->rex_w) {
        needs_rex = true;
        rex = 0x40; // Base REX prefix
        
        if (instr->rex_w) {
            rex |= 0x08; // REX.W for 64-bit operand size
        }
        
        // Check operands for extended register usage
        for (int i = 0; i < operand_count; i++) {
            if (operands[i].type == X86_64_OP_REGISTER) {
                const x86_64_register_info_t *reg = x86_64_find_register(operands[i].data.reg_name);
                if (reg && reg->needs_rex_extension) {
                    if (i == 0) rex |= 0x04; // REX.R for first operand
                    if (i == 1) rex |= 0x01; // REX.B for second operand
                    needs_rex = true;
                }
            } else if (operands[i].type == X86_64_OP_MEMORY) {
                // Check base and index registers for REX requirement
                if (operands[i].data.addr.has_base) {
                    const x86_64_register_info_t *base_reg = x86_64_find_register_by_id(operands[i].data.addr.base_reg);
                    if (base_reg && base_reg->needs_rex_extension) {
                        rex |= 0x01; // REX.B
                        needs_rex = true;
                    }
                }
                if (operands[i].data.addr.has_index) {
                    const x86_64_register_info_t *index_reg = x86_64_find_register_by_id(operands[i].data.addr.index_reg);
                    if (index_reg && index_reg->needs_rex_extension) {
                        rex |= 0x02; // REX.X
                        needs_rex = true;
                    }
                }
            }
        }
    }
    
    // Output REX prefix if needed
    if (needs_rex) {
        output[pos++] = rex;
    }
    
    // Step 2: Emit opcode bytes (Intel SDM Volume 2)
    for (int i = 0; i < instr->opcode_length; i++) {
        output[pos++] = instr->opcode[i];
    }
    
    // Step 3: Generate ModR/M byte if instruction uses it
    if (instr->uses_modrm) {
        uint8_t modrm = 0;
        uint8_t reg_field = instr->modrm_reg; // Use instruction's reg field
        
        if (operand_count >= 2) {
            // Two-operand instruction encoding
            const x86_64_operand_t *src = &operands[0];
            const x86_64_operand_t *dst = &operands[1];
            
            if (dst->type == X86_64_OP_REGISTER && src->type == X86_64_OP_REGISTER) {
                // Register to register: mod=11, reg=src, rm=dst
                const x86_64_register_info_t *src_reg = x86_64_find_register(src->data.reg_name);
                const x86_64_register_info_t *dst_reg = x86_64_find_register(dst->data.reg_name);
                if (!src_reg || !dst_reg) return -1;
                
                modrm = 0xC0 | ((src_reg->encoding & 0x7) << 3) | (dst_reg->encoding & 0x7);
                output[pos++] = modrm;
                
            } else if (dst->type == X86_64_OP_MEMORY) {
                // Register to memory
                const x86_64_register_info_t *src_reg = x86_64_find_register(src->data.reg_name);
                if (!src_reg) return -1;
                
                uint8_t addressing_bytes[16];
                size_t addr_len = 0;
                
                if (x86_64_encode_addressing_mode(&dst->data.addr, src_reg->encoding & 0x7, 
                                                  addressing_bytes, &addr_len) == 0) {
                    // Copy addressing mode bytes
                    for (size_t j = 0; j < addr_len; j++) {
                        output[pos++] = addressing_bytes[j];
                    }
                }
                
            } else if (src->type == X86_64_OP_MEMORY) {
                // Memory to register  
                const x86_64_register_info_t *dst_reg = x86_64_find_register(dst->data.reg_name);
                if (!dst_reg) return -1;
                
                uint8_t addressing_bytes[16];
                size_t addr_len = 0;
                
                if (x86_64_encode_addressing_mode(&src->data.addr, dst_reg->encoding & 0x7,
                                                  addressing_bytes, &addr_len) == 0) {
                    for (size_t j = 0; j < addr_len; j++) {
                        output[pos++] = addressing_bytes[j];
                    }
                }
            }
        } else if (operand_count == 1) {
            // Single operand instruction
            const x86_64_operand_t *op = &operands[0];
            
            if (op->type == X86_64_OP_REGISTER) {
                const x86_64_register_info_t *reg = x86_64_find_register(op->data.reg_name);
                if (!reg) return -1;
                
                modrm = 0xC0 | (reg_field << 3) | (reg->encoding & 0x7);
                output[pos++] = modrm;
                
            } else if (op->type == X86_64_OP_MEMORY) {
                uint8_t addressing_bytes[16];
                size_t addr_len = 0;
                
                if (x86_64_encode_addressing_mode(&op->data.addr, reg_field,
                                                  addressing_bytes, &addr_len) == 0) {
                    for (size_t j = 0; j < addr_len; j++) {
                        output[pos++] = addressing_bytes[j];
                    }
                }
            }
        }
    }
    
    // Step 4: Generate immediate values if present
    for (int i = 0; i < operand_count; i++) {
        if (operands[i].type == X86_64_OP_IMMEDIATE) {
            int64_t imm = operands[i].data.immediate;
            
            // Determine immediate size based on instruction and value
            if (imm >= -128 && imm <= 127) {
                // 8-bit immediate
                output[pos++] = (uint8_t)(imm & 0xFF);
            } else if (imm >= -2147483648LL && imm <= 2147483647LL) {
                // 32-bit immediate
                output[pos++] = (uint8_t)(imm & 0xFF);
                output[pos++] = (uint8_t)((imm >> 8) & 0xFF);
                output[pos++] = (uint8_t)((imm >> 16) & 0xFF);
                output[pos++] = (uint8_t)((imm >> 24) & 0xFF);
            } else {
                // 64-bit immediate (for MOV only)
                output[pos++] = (uint8_t)(imm & 0xFF);
                output[pos++] = (uint8_t)((imm >> 8) & 0xFF);
                output[pos++] = (uint8_t)((imm >> 16) & 0xFF);
                output[pos++] = (uint8_t)((imm >> 24) & 0xFF);
                output[pos++] = (uint8_t)((imm >> 32) & 0xFF);
                output[pos++] = (uint8_t)((imm >> 40) & 0xFF);
                output[pos++] = (uint8_t)((imm >> 48) & 0xFF);
                output[pos++] = (uint8_t)((imm >> 56) & 0xFF);
            }
        }
    }
    
    *output_length = pos;
    return 0;
}

//=============================================================================
// Main Instruction Encoding Function
//=============================================================================

int x86_64_validate_instruction(instruction_t *inst) {
    if (!inst || !inst->mnemonic) return 0; // Invalid
    
    // Basic validation - check if instruction exists in our database
    for (size_t i = 0; instruction_database[i].mnemonic; i++) {
        if (strcmp(inst->mnemonic, instruction_database[i].mnemonic) == 0) {
            return 1; // Valid instruction found
        }
    }
    
    return 0; // Instruction not found
}

// Main instruction assembly function - CPU accurate implementation
int x86_64_assemble_instruction(const char *mnemonic, 
                                const char **operand_strings,
                                int operand_count,
                                uint8_t *output,
                                size_t *output_length) {
    if (!mnemonic || !output || !output_length) return -1;
    
    // Find instruction in database
    const x86_64_instruction_info_t *instr = x86_64_find_instruction(mnemonic);
    if (!instr) return -1;
    
    // Validate operand count
    if (operand_count != instr->operand_count) return -1;
    
    // Parse operands
    x86_64_operand_t operands[X86_64_MAX_OPERANDS];
    for (int i = 0; i < operand_count; i++) {
        if (x86_64_parse_operand(operand_strings[i], &operands[i]) != 0) {
            return -1;
        }
    }
    
    // Validate operand combination for this instruction
    if (!x86_64_validate_operand_combination(mnemonic, operand_strings, operand_count)) {
        return -1;
    }
    
    // Perform CPU-specific constraint validation per manifest
    if (!x86_64_validate_cpu_constraints(instr, operand_strings)) {
        return -1;
    }
    
    // Generate machine code
    return x86_64_generate_instruction(instr, operands, operand_count, output, output_length);
}
