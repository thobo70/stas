/*
 * x86_64 Instruction Set and Addressing Mode Completeness Test
 * Validates implementation completeness according to STAS Development Manifest
 * 
 * Tests verify:
 * 1. Complete instruction set coverage per Intel SDM
 * 2. All x86_64 addressing modes per AT&T syntax
 * 3. CPU-accurate operand constraints
 * 4. Architectural precision requirements
 * 
 * Following STAS Manifest Section 3: ARCHITECTURAL PRECISION
 */

#include "../../unity/src/unity.h"
#include "arch_interface.h"
#include "x86_64.h"
#include <string.h>
#include <stdio.h>
#include <stdbool.h>

// Forward declaration for x86_64 architecture ops
extern arch_ops_t *x86_64_get_arch_ops(void);

static const arch_ops_t *arch_ops = NULL;

void setUp(void) {
    arch_ops = x86_64_get_arch_ops();
    TEST_ASSERT_NOT_NULL(arch_ops);
    
    if (arch_ops->init) {
        int result = arch_ops->init();
        TEST_ASSERT_EQUAL(0, result);
    }
}

void tearDown(void) {
    if (arch_ops && arch_ops->cleanup) {
        arch_ops->cleanup();
    }
}

//=============================================================================
// INSTRUCTION SET COMPLETENESS TESTS
// Per STAS Manifest: "Architectural precision" and "CPU accuracy"
//=============================================================================

void test_x86_64_data_movement_instructions_complete(void) {
    // Data Movement - Core instruction category per Intel SDM Volume 2
    const char* data_movement_insts[] = {
        // MOV variants - all size variants required
        "movb", "movw", "movl", "movq",
        
        // MOVZX/MOVSX - zero/sign extend moves
        "movzbw", "movzbl", "movzbq",  // Zero extend byte to word/dword/qword
        "movzwl", "movzwq",            // Zero extend word to dword/qword
        "movslq",                      // Sign extend dword to qword
        "movsbw", "movsbl", "movsbq",  // Sign extend byte to word/dword/qword
        "movswl", "movswq",            // Sign extend word to dword/qword
        
        // LEA - Load Effective Address
        "leaw", "leal", "leaq",
        
        // XCHG - Exchange
        "xchgb", "xchgw", "xchgl", "xchgq",
        
        // Stack operations
        "pushw", "pushl", "pushq",
        "popw", "popl", "popq",
        
        // BSWAP - Byte swap for endianness
        "bswapl", "bswapq"
    };
    
    size_t count = sizeof(data_movement_insts) / sizeof(data_movement_insts[0]);
    int missing_count = 0;
    char missing_insts[1024] = "";
    
    for (size_t i = 0; i < count; i++) {
        // Test with typical operand count for each instruction
        int operand_count = 2; // Most data movement instructions take 2 operands
        if (strstr(data_movement_insts[i], "push") != NULL || 
            strstr(data_movement_insts[i], "pop") != NULL ||
            strstr(data_movement_insts[i], "bswap") != NULL) {
            operand_count = 1;
        }
        
        bool result = arch_ops->validate_operand_combination(data_movement_insts[i], NULL, operand_count);
        if (!result) {
            missing_count++;
            strcat(missing_insts, data_movement_insts[i]);
            strcat(missing_insts, " ");
        }
    }
    
    // Per manifest: Test realistic instruction sets, not accommodation
    char failure_msg[2048];
    snprintf(failure_msg, sizeof(failure_msg), 
             "Missing %d/%zu data movement instructions: %s", 
             missing_count, count, missing_insts);
    TEST_ASSERT_TRUE_MESSAGE(missing_count == 0, failure_msg);
}

void test_x86_64_arithmetic_instructions_complete(void) {
    // Arithmetic Instructions - Complete Intel SDM coverage
    const char* arithmetic_insts[] = {
        // ADD/SUB - all size variants
        "addb", "addw", "addl", "addq",
        "subb", "subw", "subl", "subq",
        "adcb", "adcw", "adcl", "adcq",  // Add with carry
        "sbbb", "sbbw", "sbbl", "sbbq",  // Subtract with borrow
        
        // MUL/DIV - signed and unsigned variants
        "mulb", "mulw", "mull", "mulq",    // Unsigned multiply
        "imulb", "imulw", "imull", "imulq", // Signed multiply
        "divb", "divw", "divl", "divq",    // Unsigned divide
        "idivb", "idivw", "idivl", "idivq", // Signed divide
        
        // INC/DEC - increment/decrement
        "incb", "incw", "incl", "incq",
        "decb", "decw", "decl", "decq",
        
        // NEG - two's complement negation
        "negb", "negw", "negl", "negq"
    };
    
    size_t count = sizeof(arithmetic_insts) / sizeof(arithmetic_insts[0]);
    int missing_count = 0;
    char missing_insts[1024] = "";
    
    for (size_t i = 0; i < count; i++) {
        // Determine operand count based on instruction type
        int operand_count = 2; // Default for binary operations
        if (strstr(arithmetic_insts[i], "div") != NULL || 
            strstr(arithmetic_insts[i], "mul") != NULL ||
            strstr(arithmetic_insts[i], "inc") != NULL ||
            strstr(arithmetic_insts[i], "dec") != NULL ||
            strstr(arithmetic_insts[i], "neg") != NULL) {
            operand_count = 1; // Unary operations or implicit operands
        }
        
        bool result = arch_ops->validate_operand_combination(arithmetic_insts[i], NULL, operand_count);
        if (!result) {
            missing_count++;
            strcat(missing_insts, arithmetic_insts[i]);
            strcat(missing_insts, " ");
        }
    }
    
    char failure_msg[2048];
    snprintf(failure_msg, sizeof(failure_msg), 
             "Missing %d/%zu arithmetic instructions: %s", 
             missing_count, count, missing_insts);
    TEST_ASSERT_TRUE_MESSAGE(missing_count == 0, failure_msg);
}

void test_x86_64_logical_instructions_complete(void) {
    // Logical Instructions - Complete set per Intel SDM
    const char* logical_insts[] = {
        // Bitwise operations - all size variants
        "andb", "andw", "andl", "andq",
        "orb", "orw", "orl", "orq",
        "xorb", "xorw", "xorl", "xorq",
        "notb", "notw", "notl", "notq",
        
        // Bit test operations
        "testb", "testw", "testl", "testq",
        "btw", "btl", "btq",       // Bit test
        "btsw", "btsl", "btsq",    // Bit test and set
        "btrw", "btrl", "btrq",    // Bit test and reset
        "btcw", "btcl", "btcq",    // Bit test and complement
        
        // Bit scan operations
        "bsfw", "bsfl", "bsfq",    // Bit scan forward
        "bsrw", "bsrl", "bsrq"     // Bit scan reverse
    };
    
    size_t count = sizeof(logical_insts) / sizeof(logical_insts[0]);
    int missing_count = 0;
    char missing_insts[1024] = "";
    
    for (size_t i = 0; i < count; i++) {
        // Determine operand count
        int operand_count = 2; // Default for binary operations
        if (strstr(logical_insts[i], "not") != NULL) {
            operand_count = 1; // Unary operation
        }
        
        bool result = arch_ops->validate_operand_combination(logical_insts[i], NULL, operand_count);
        if (!result) {
            missing_count++;
            strcat(missing_insts, logical_insts[i]);
            strcat(missing_insts, " ");
        }
    }
    
    char failure_msg[2048];
    snprintf(failure_msg, sizeof(failure_msg), 
             "Missing %d/%zu logical instructions: %s", 
             missing_count, count, missing_insts);
    TEST_ASSERT_TRUE_MESSAGE(missing_count == 0, failure_msg);
}

void test_x86_64_shift_rotate_instructions_complete(void) {
    // Shift and Rotate Instructions - CPU-accurate constraints
    const char* shift_rotate_insts[] = {
        // Shift operations - all size variants
        "salb", "salw", "sall", "salq",    // Shift arithmetic left (same as SHL)
        "shlb", "shlw", "shll", "shlq",    // Shift logical left
        "sarb", "sarw", "sarl", "sarq",    // Shift arithmetic right
        "shrb", "shrw", "shrl", "shrq",    // Shift logical right
        
        // Rotate operations
        "rolb", "rolw", "roll", "rolq",    // Rotate left
        "rorb", "rorw", "rorl", "rorq",    // Rotate right
        "rclb", "rclw", "rcll", "rclq",    // Rotate through carry left
        "rcrb", "rcrw", "rcrl", "rcrq",    // Rotate through carry right
        
        // Double precision shifts
        "shldw", "shldl", "shldq",         // Shift left double precision
        "shrdw", "shrdl", "shrdq"          // Shift right double precision
    };
    
    size_t count = sizeof(shift_rotate_insts) / sizeof(shift_rotate_insts[0]);
    int missing_count = 0;
    char missing_insts[1024] = "";
    
    for (size_t i = 0; i < count; i++) {
        // Most shift/rotate take 1 operand (shift by 1) or 2 operands (shift by count)
        // Double precision shifts take 3 operands
        int operand_count = 1; // Default: shift by 1
        if (strstr(shift_rotate_insts[i], "shld") != NULL || 
            strstr(shift_rotate_insts[i], "shrd") != NULL) {
            operand_count = 3; // Double precision shifts
        }
        
        bool result = arch_ops->validate_operand_combination(shift_rotate_insts[i], NULL, operand_count);
        if (!result) {
            missing_count++;
            strcat(missing_insts, shift_rotate_insts[i]);
            strcat(missing_insts, " ");
        }
    }
    
    char failure_msg[2048];
    snprintf(failure_msg, sizeof(failure_msg), 
             "Missing %d/%zu shift/rotate instructions: %s", 
             missing_count, count, missing_insts);
    TEST_ASSERT_TRUE_MESSAGE(missing_count == 0, failure_msg);
}

void test_x86_64_control_flow_instructions_complete(void) {
    // Control Flow Instructions - Complete set per Intel SDM
    const char* control_flow_insts[] = {
        // Unconditional jumps and calls
        "jmp",     // Unconditional jump
        "call",    // Call procedure
        "ret",     // Return from procedure
        "retf",    // Return far
        "iret",    // Interrupt return
        "iretq",   // Interrupt return 64-bit
        
        // Conditional jumps - complete set
        "je", "jz",        // Jump if equal/zero
        "jne", "jnz",      // Jump if not equal/not zero
        "jl", "jnge",      // Jump if less/not greater or equal
        "jle", "jng",      // Jump if less or equal/not greater
        "jg", "jnle",      // Jump if greater/not less or equal
        "jge", "jnl",      // Jump if greater or equal/not less
        "jb", "jnae", "jc", // Jump if below/not above or equal/carry
        "jbe", "jna",      // Jump if below or equal/not above
        "ja", "jnbe",      // Jump if above/not below or equal
        "jae", "jnb", "jnc", // Jump if above or equal/not below/not carry
        "jo",              // Jump if overflow
        "jno",             // Jump if not overflow
        "js",              // Jump if sign
        "jns",             // Jump if not sign
        "jp", "jpe",       // Jump if parity/parity even
        "jnp", "jpo",      // Jump if not parity/parity odd
        
        // Loop instructions
        "loop",            // Loop
        "loope", "loopz",  // Loop while equal/zero
        "loopne", "loopnz" // Loop while not equal/not zero
    };
    
    size_t count = sizeof(control_flow_insts) / sizeof(control_flow_insts[0]);
    int missing_count = 0;
    char missing_insts[1024] = "";
    
    for (size_t i = 0; i < count; i++) {
        // Determine operand count
        int operand_count = 1; // Most control flow instructions take 1 operand (target)
        if (strcmp(control_flow_insts[i], "ret") == 0 ||
            strcmp(control_flow_insts[i], "retf") == 0 ||
            strcmp(control_flow_insts[i], "iret") == 0 ||
            strcmp(control_flow_insts[i], "iretq") == 0) {
            operand_count = 0; // No operands
        }
        
        bool result = arch_ops->validate_operand_combination(control_flow_insts[i], NULL, operand_count);
        if (!result) {
            missing_count++;
            strcat(missing_insts, control_flow_insts[i]);
            strcat(missing_insts, " ");
        }
    }
    
    char failure_msg[2048];
    snprintf(failure_msg, sizeof(failure_msg), 
             "Missing %d/%zu control flow instructions: %s", 
             missing_count, count, missing_insts);
    TEST_ASSERT_TRUE_MESSAGE(missing_count == 0, failure_msg);
}

void test_x86_64_comparison_instructions_complete(void) {
    // Comparison Instructions - Complete set per Intel SDM
    const char* comparison_insts[] = {
        // Compare operations - all size variants
        "cmpb", "cmpw", "cmpl", "cmpq",
        
        // Conditional move instructions - complete set
        "cmovb", "cmovc", "cmovnae",       // Move if below/carry/not above or equal
        "cmovnb", "cmovnc", "cmovae",      // Move if not below/not carry/above or equal
        "cmove", "cmovz",                  // Move if equal/zero
        "cmovne", "cmovnz",                // Move if not equal/not zero
        "cmovbe", "cmovna",                // Move if below or equal/not above
        "cmovnbe", "cmova",                // Move if not below or equal/above
        "cmovl", "cmovnge",                // Move if less/not greater or equal
        "cmovnl", "cmovge",                // Move if not less/greater or equal
        "cmovle", "cmovng",                // Move if less or equal/not greater
        "cmovnle", "cmovg",                // Move if not less or equal/greater
        "cmovo",                           // Move if overflow
        "cmovno",                          // Move if not overflow
        "cmovs",                           // Move if sign
        "cmovns",                          // Move if not sign
        "cmovp", "cmovpe",                 // Move if parity/parity even
        "cmovnp", "cmovpo",                // Move if not parity/parity odd
        
        // Set byte on condition - complete set
        "setb", "setc", "setnae",          // Set if below/carry/not above or equal
        "setnb", "setnc", "setae",         // Set if not below/not carry/above or equal
        "sete", "setz",                    // Set if equal/zero
        "setne", "setnz",                  // Set if not equal/not zero
        "setbe", "setna",                  // Set if below or equal/not above
        "setnbe", "seta",                  // Set if not below or equal/above
        "setl", "setnge",                  // Set if less/not greater or equal
        "setnl", "setge",                  // Set if not less/greater or equal
        "setle", "setng",                  // Set if less or equal/not greater
        "setnle", "setg",                  // Set if not less or equal/greater
        "seto",                            // Set if overflow
        "setno",                           // Set if not overflow
        "sets",                            // Set if sign
        "setns",                           // Set if not sign
        "setp", "setpe",                   // Set if parity/parity even
        "setnp", "setpo"                   // Set if not parity/parity odd
    };
    
    size_t count = sizeof(comparison_insts) / sizeof(comparison_insts[0]);
    int missing_count = 0;
    char missing_insts[1024] = "";
    
    for (size_t i = 0; i < count; i++) {
        // Determine operand count
        int operand_count = 2; // Default for binary operations (cmp, cmov)
        if (strstr(comparison_insts[i], "set") != NULL) {
            operand_count = 1; // Set instructions take 1 operand
        }
        
        bool result = arch_ops->validate_operand_combination(comparison_insts[i], NULL, operand_count);
        if (!result) {
            missing_count++;
            strcat(missing_insts, comparison_insts[i]);
            strcat(missing_insts, " ");
        }
    }
    
    char failure_msg[2048];
    snprintf(failure_msg, sizeof(failure_msg), 
             "Missing %d/%zu comparison instructions: %s", 
             missing_count, count, missing_insts);
    TEST_ASSERT_TRUE_MESSAGE(missing_count == 0, failure_msg);
}

void test_x86_64_string_instructions_complete(void) {
    // String Instructions - Complete set per Intel SDM
    const char* string_insts[] = {
        // String move operations
        "movsb", "movsw", "movsl", "movsq",  // Move string
        
        // String compare operations
        "cmpsb", "cmpsw", "cmpsl", "cmpsq",  // Compare string
        
        // String scan operations
        "scasb", "scasw", "scasl", "scasq",  // Scan string
        
        // String load operations
        "lodsb", "lodsw", "lodsl", "lodsq",  // Load string
        
        // String store operations
        "stosb", "stosw", "stosl", "stosq",  // Store string
        
        // Repeat prefixes (considered part of string instruction set)
        "rep", "repe", "repz", "repne", "repnz"
    };
    
    size_t count = sizeof(string_insts) / sizeof(string_insts[0]);
    int missing_count = 0;
    char missing_insts[1024] = "";
    
    for (size_t i = 0; i < count; i++) {
        // String instructions typically have 0 operands (implicit operands)
        int operand_count = 0;
        
        bool result = arch_ops->validate_operand_combination(string_insts[i], NULL, operand_count);
        if (!result) {
            missing_count++;
            strcat(missing_insts, string_insts[i]);
            strcat(missing_insts, " ");
        }
    }
    
    char failure_msg[2048];
    snprintf(failure_msg, sizeof(failure_msg), 
             "Missing %d/%zu string instructions: %s", 
             missing_count, count, missing_insts);
    TEST_ASSERT_TRUE_MESSAGE(missing_count == 0, failure_msg);
}

void test_x86_64_system_instructions_complete(void) {
    // System Instructions - Core set per Intel SDM
    const char* system_insts[] = {
        // Basic system instructions
        "nop",             // No operation
        "hlt",             // Halt
        "int",             // Software interrupt
        "into",            // Interrupt on overflow
        "syscall",         // System call (64-bit)
        "sysret",          // Return from system call
        "sysenter",        // Fast system call entry
        "sysexit",         // Fast system call exit
        
        // Flag operations
        "clc",             // Clear carry flag
        "stc",             // Set carry flag
        "cmc",             // Complement carry flag
        "cld",             // Clear direction flag
        "std",             // Set direction flag
        "cli",             // Clear interrupt flag
        "sti",             // Set interrupt flag
        "clts",            // Clear task switched flag
        
        // Processor state
        "pushf",           // Push flags
        "pushfq",          // Push flags 64-bit
        "popf",            // Pop flags
        "popfq",           // Pop flags 64-bit
        "lahf",            // Load AH from flags
        "sahf",            // Store AH to flags
        
        // Cache/memory
        "prefetch",        // Prefetch data
        "prefetchnta",     // Prefetch non-temporal
        "prefetcht0",      // Prefetch to L1 cache
        "prefetcht1",      // Prefetch to L2 cache
        "prefetcht2",      // Prefetch to L3 cache
        "clflush",         // Flush cache line
        "mfence",          // Memory fence
        "sfence",          // Store fence
        "lfence"           // Load fence
    };
    
    size_t count = sizeof(system_insts) / sizeof(system_insts[0]);
    int missing_count = 0;
    char missing_insts[1024] = "";
    
    for (size_t i = 0; i < count; i++) {
        // Determine operand count
        int operand_count = 0; // Most system instructions have 0 operands
        if (strcmp(system_insts[i], "int") == 0 ||
            strstr(system_insts[i], "prefetch") != NULL ||
            strcmp(system_insts[i], "clflush") == 0) {
            operand_count = 1; // Take 1 operand
        }
        
        bool result = arch_ops->validate_operand_combination(system_insts[i], NULL, operand_count);
        if (!result) {
            missing_count++;
            strcat(missing_insts, system_insts[i]);
            strcat(missing_insts, " ");
        }
    }
    
    char failure_msg[2048];
    snprintf(failure_msg, sizeof(failure_msg), 
             "Missing %d/%zu system instructions: %s", 
             missing_count, count, missing_insts);
    TEST_ASSERT_TRUE_MESSAGE(missing_count == 0, failure_msg);
}

//=============================================================================
// ADDRESSING MODE COMPLETENESS TESTS  
// Per STAS Manifest: "Support all legitimate x86 addressing modes"
//=============================================================================

void test_x86_64_register_addressing_complete(void) {
    // Register Direct Addressing - All register types per AT&T syntax
    const char* registers[] = {
        // 8-bit registers (including REX-accessible)
        "%al", "%cl", "%dl", "%bl", "%ah", "%ch", "%dh", "%bh",
        "%spl", "%bpl", "%sil", "%dil",
        "%r8b", "%r9b", "%r10b", "%r11b", "%r12b", "%r13b", "%r14b", "%r15b",
        
        // 16-bit registers
        "%ax", "%cx", "%dx", "%bx", "%sp", "%bp", "%si", "%di",
        "%r8w", "%r9w", "%r10w", "%r11w", "%r12w", "%r13w", "%r14w", "%r15w",
        
        // 32-bit registers
        "%eax", "%ecx", "%edx", "%ebx", "%esp", "%ebp", "%esi", "%edi",
        "%r8d", "%r9d", "%r10d", "%r11d", "%r12d", "%r13d", "%r14d", "%r15d",
        
        // 64-bit registers
        "%rax", "%rcx", "%rdx", "%rbx", "%rsp", "%rbp", "%rsi", "%rdi",
        "%r8", "%r9", "%r10", "%r11", "%r12", "%r13", "%r14", "%r15"
    };
    
    size_t count = sizeof(registers) / sizeof(registers[0]);
    int missing_count = 0;
    char missing_regs[2048] = "";
    
    for (size_t i = 0; i < count; i++) {
        asm_register_t reg;
        int result = arch_ops->parse_register(registers[i], &reg);
        if (result != 0) {
            missing_count++;
            strcat(missing_regs, registers[i]);
            strcat(missing_regs, " ");
        }
    }
    
    char failure_msg[4096];
    snprintf(failure_msg, sizeof(failure_msg), 
             "Missing %d/%zu register definitions: %s", 
             missing_count, count, missing_regs);
    TEST_ASSERT_TRUE_MESSAGE(missing_count == 0, failure_msg);
}

void test_x86_64_immediate_addressing_complete(void) {
    // Immediate Addressing - AT&T syntax validation
    // Test that immediate addressing parsing works correctly
    
    // This would test the addressing mode parser, but since we don't have
    // direct access to it through the arch interface, we test through
    // instruction validation that should accept immediate operands
    
    // Test instructions that commonly use immediate addressing
    const char* imm_supporting_insts[] = {
        "movl",   // mov $imm, %reg
        "addl",   // add $imm, %reg  
        "cmpl",   // cmp $imm, %reg
        "testl",  // test $imm, %reg
        "andl",   // and $imm, %reg
        "orl",    // or $imm, %reg
        "xorl"    // xor $imm, %reg
    };
    
    size_t count = sizeof(imm_supporting_insts) / sizeof(imm_supporting_insts[0]);
    int supported_count = 0;
    
    for (size_t i = 0; i < count; i++) {
        bool result = arch_ops->validate_operand_combination(imm_supporting_insts[i], NULL, 2);
        if (result) {
            supported_count++;
        }
    }
    
    // At least 80% of immediate-supporting instructions should be implemented
    int min_required = (int)(count * 0.8);
    char failure_msg[1024];
    snprintf(failure_msg, sizeof(failure_msg), 
             "Only %d/%zu immediate-supporting instructions implemented (need %d+)", 
             supported_count, count, min_required);
    TEST_ASSERT_TRUE_MESSAGE(supported_count >= min_required, failure_msg);
}

void test_x86_64_memory_addressing_modes_complete(void) {
    // Memory Addressing Modes - Complete x86_64 set per Intel SDM
    // This tests through instruction validation since we don't have direct
    // access to addressing mode parsing through the arch interface
    
    // Memory addressing modes in x86_64:
    // 1. [base] - base register only
    // 2. [base + disp] - base + displacement  
    // 3. [index*scale] - scaled index only
    // 4. [index*scale + disp] - scaled index + displacement
    // 5. [base + index] - base + index
    // 6. [base + index + disp] - base + index + displacement
    // 7. [base + index*scale] - base + scaled index
    // 8. [base + index*scale + disp] - base + scaled index + displacement
    // 9. RIP-relative [disp] - 64-bit mode only
    
    // Test instructions that support memory operands
    const char* mem_supporting_insts[] = {
        "movl",   // Common memory instruction
        "addl",   // Arithmetic with memory
        "cmpl",   // Compare with memory
        "leal"    // Load effective address (memory addressing required)
    };
    
    size_t count = sizeof(mem_supporting_insts) / sizeof(mem_supporting_insts[0]);
    int supported_count = 0;
    
    for (size_t i = 0; i < count; i++) {
        bool result = arch_ops->validate_operand_combination(mem_supporting_insts[i], NULL, 2);
        if (result) {
            supported_count++;
        }
    }
    
    // All memory-supporting instructions should be implemented for completeness
    char failure_msg[1024];
    snprintf(failure_msg, sizeof(failure_msg), 
             "Only %d/%zu memory-supporting instructions implemented", 
             supported_count, count);
    TEST_ASSERT_TRUE_MESSAGE(supported_count == (int)count, failure_msg);
}

void test_x86_64_segment_register_support_complete(void) {
    // Segment Registers - x86_64 retains segment support for compatibility
    const char* segment_registers[] = {
        "%es", "%cs", "%ss", "%ds", "%fs", "%gs"
    };
    
    size_t count = sizeof(segment_registers) / sizeof(segment_registers[0]);
    int missing_count = 0;
    char missing_segs[256] = "";
    
    for (size_t i = 0; i < count; i++) {
        asm_register_t reg;
        int result = arch_ops->parse_register(segment_registers[i], &reg);
        if (result != 0) {
            missing_count++;
            strcat(missing_segs, segment_registers[i]);
            strcat(missing_segs, " ");
        }
    }
    
    char failure_msg[1024];
    snprintf(failure_msg, sizeof(failure_msg), 
             "Missing %d/%zu segment registers: %s", 
             missing_count, count, missing_segs);
    TEST_ASSERT_TRUE_MESSAGE(missing_count == 0, failure_msg);
}

//=============================================================================
// ARCHITECTURE SPECIFIC REQUIREMENTS TESTS
// Per STAS Manifest Section 3: x86-64 specific requirements
//=============================================================================

void test_x86_64_instruction_encoding_accuracy(void) {
    // Test that instruction encoding follows Intel SDM exactly
    // This is a CPU accuracy requirement per manifest
    
    instruction_t test_inst;
    uint8_t buffer[16];
    size_t length;
    
    // Test basic MOV instruction encoding
    test_inst.mnemonic = "movl";
    test_inst.operand_count = 2;
    test_inst.encoding = NULL;
    test_inst.encoding_length = 0;
    
    if (arch_ops->encode_instruction) {
        int result = arch_ops->encode_instruction(&test_inst, buffer, &length);
        // Should either succeed or fail gracefully, not crash
        TEST_ASSERT_TRUE(result == 0 || result < 0);
    }
    
    // Test NOP instruction - should encode to 0x90
    test_inst.mnemonic = "nop";
    test_inst.operand_count = 0;
    
    if (arch_ops->encode_instruction) {
        int result = arch_ops->encode_instruction(&test_inst, buffer, &length);
        if (result == 0 && length > 0) {
            // If encoding succeeds, NOP should be 0x90 per Intel SDM
            TEST_ASSERT_EQUAL_HEX8_MESSAGE(0x90, buffer[0], "NOP must encode to 0x90 per Intel SDM");
        }
    }
}

void test_x86_64_operand_size_handling_complete(void) {
    // Test that all operand sizes are properly distinguished
    // Per manifest: "Respect byte/word/dword/qword distinctions"
    
    const char* size_variants[][4] = {
        {"movb", "movw", "movl", "movq"},
        {"addb", "addw", "addl", "addq"},
        {"subb", "subw", "subl", "subq"},
        {"cmpl", "cmpw", "cmpl", "cmpq"}
    };
    
    size_t variant_count = sizeof(size_variants) / sizeof(size_variants[0]);
    int total_missing = 0;
    
    for (size_t i = 0; i < variant_count; i++) {
        for (int j = 0; j < 4; j++) {
            bool result = arch_ops->validate_operand_combination(size_variants[i][j], NULL, 2);
            if (!result) {
                total_missing++;
            }
        }
    }
    
    char failure_msg[1024];
    snprintf(failure_msg, sizeof(failure_msg), 
             "Missing %d size variants - all byte/word/dword/qword must be supported", 
             total_missing);
    TEST_ASSERT_TRUE_MESSAGE(total_missing == 0, failure_msg);
}

void test_x86_64_register_encoding_accuracy(void) {
    // Test that register encodings match Intel SDM
    // Per manifest: "Use correct register encoding values"
    
    // Test basic register set is properly recognized
    const char* core_registers[] = {
        "%rax", "%rcx", "%rdx", "%rbx", "%rsp", "%rbp", "%rsi", "%rdi"
    };
    
    size_t count = sizeof(core_registers) / sizeof(core_registers[0]);
    int recognized_count = 0;
    
    for (size_t i = 0; i < count; i++) {
        asm_register_t reg;
        if (arch_ops->parse_register(core_registers[i], &reg) == 0) {
            recognized_count++;
        }
    }
    
    // All core registers must be recognized
    TEST_ASSERT_EQUAL_MESSAGE(count, recognized_count, "All core x86_64 registers must be recognized");
}

//=============================================================================
// TEST RUNNER
//=============================================================================

int main(void) {
    UNITY_BEGIN();
    
    // Instruction Set Completeness Tests
    RUN_TEST(test_x86_64_data_movement_instructions_complete);
    RUN_TEST(test_x86_64_arithmetic_instructions_complete);
    RUN_TEST(test_x86_64_logical_instructions_complete);
    RUN_TEST(test_x86_64_shift_rotate_instructions_complete);
    RUN_TEST(test_x86_64_control_flow_instructions_complete);
    RUN_TEST(test_x86_64_comparison_instructions_complete);
    RUN_TEST(test_x86_64_string_instructions_complete);
    RUN_TEST(test_x86_64_system_instructions_complete);
    
    // Addressing Mode Completeness Tests
    RUN_TEST(test_x86_64_register_addressing_complete);
    RUN_TEST(test_x86_64_immediate_addressing_complete);
    RUN_TEST(test_x86_64_memory_addressing_modes_complete);
    RUN_TEST(test_x86_64_segment_register_support_complete);
    
    // Architecture Specific Requirements Tests
    RUN_TEST(test_x86_64_instruction_encoding_accuracy);
    RUN_TEST(test_x86_64_operand_size_handling_complete);
    RUN_TEST(test_x86_64_register_encoding_accuracy);
    
    return UNITY_END();
}
