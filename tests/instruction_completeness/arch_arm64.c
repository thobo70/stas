#include "arch_arm64.h"

// ========================================
// ARM64 INSTRUCTION SET DEFINITIONS
// Based on ARM Architecture Reference Manual for A-profile Architecture
// ========================================

// Arithmetic Instructions (comprehensive operand support)
static const instruction_def_t arm64_arithmetic[] = {
    // Basic arithmetic operations
    {"add", "Arithmetic", 3, false},
    {"adds", "Arithmetic", 3, false},
    {"sub", "Arithmetic", 3, false},
    {"subs", "Arithmetic", 3, false},
    {"cmp", "Arithmetic", 2, false},
    {"cmn", "Arithmetic", 2, false},
    {"neg", "Arithmetic", 2, false},
    {"negs", "Arithmetic", 2, false},
    
    // Add/subtract with carry
    {"adc", "Arithmetic", 3, false},
    {"adcs", "Arithmetic", 3, false},
    {"sbc", "Arithmetic", 3, false},
    {"sbcs", "Arithmetic", 3, false},
    {"ngc", "Arithmetic", 2, false},
    {"ngcs", "Arithmetic", 2, false},
    
    // Multiplication
    {"mul", "Arithmetic", 3, false},
    {"mneg", "Arithmetic", 3, false},
    {"madd", "Arithmetic", 4, false},
    {"msub", "Arithmetic", 4, false},
    {"smull", "Arithmetic", 3, false},
    {"smnegl", "Arithmetic", 3, false},
    {"smaddl", "Arithmetic", 4, false},
    {"smsubl", "Arithmetic", 4, false},
    {"umull", "Arithmetic", 3, false},
    {"umnegl", "Arithmetic", 3, false},
    {"umaddl", "Arithmetic", 4, false},
    {"umsubl", "Arithmetic", 4, false},
    {"smulh", "Arithmetic", 3, false},
    {"umulh", "Arithmetic", 3, false},
    
    // Division
    {"sdiv", "Arithmetic", 3, false},
    {"udiv", "Arithmetic", 3, false},
    
    // Conditional operations
    {"csel", "Arithmetic", 4, false},
    {"csinc", "Arithmetic", 4, false},
    {"csinv", "Arithmetic", 4, false},
    {"csneg", "Arithmetic", 4, false},
    {"cinc", "Arithmetic", 3, false},
    {"cinv", "Arithmetic", 3, false},
    {"cneg", "Arithmetic", 3, false},
    {"cset", "Arithmetic", 2, false},
    {"csetm", "Arithmetic", 2, false},
    
    // Conditional compare
    {"ccmp", "Arithmetic", 4, false},
    {"ccmn", "Arithmetic", 4, false},
    
    // Absolute value
    {"abs", "Arithmetic", 2, false},
    
    // Variable shift operations
    {"asrv", "Arithmetic", 3, false},
    {"lslv", "Arithmetic", 3, false},
    {"lsrv", "Arithmetic", 3, false},
    {"rorv", "Arithmetic", 3, false},
    
    // CRC operations
    {"crc32b", "Arithmetic", 3, true},
    {"crc32h", "Arithmetic", 3, true},
    {"crc32w", "Arithmetic", 3, true},
    {"crc32x", "Arithmetic", 3, true},
    {"crc32cb", "Arithmetic", 3, true},
    {"crc32ch", "Arithmetic", 3, true},
    {"crc32cw", "Arithmetic", 3, true},
    {"crc32cx", "Arithmetic", 3, true}
};

// Logical Instructions (comprehensive operand support)
static const instruction_def_t arm64_logical[] = {
    // Basic logical operations
    {"and", "Logical", 3, false},              // Wd,Wn,Wm | Xd,Xn,Xm | Wd,Wn,#bimm32 | Xd,Xn,#bimm64 | Wd,Wn,Wm,shift | Xd,Xn,Xm,shift
    {"ands", "Logical", 3, false},             // Wd,Wn,Wm | Xd,Xn,Xm | Wd,Wn,#bimm32 | Xd,Xn,#bimm64 | Wd,Wn,Wm,shift | Xd,Xn,Xm,shift (sets flags)
    {"tst", "Logical", 2, false},              // Wn,Wm | Xn,Xm | Wn,#bimm32 | Xn,#bimm64 | Wn,Wm,shift | Xn,Xm,shift (alias for ands with Xzr)
    {"orr", "Logical", 3, false},              // Wd,Wn,Wm | Xd,Xn,Xm | Wd,Wn,#bimm32 | Xd,Xn,#bimm64 | Wd,Wn,Wm,shift | Xd,Xn,Xm,shift
    {"mov", "Logical", 2, false},              // Wd,Wm | Xd,Xm | Wd,#imm | Xd,#imm | Wd,Wn | Xd,Xn (register-to-register and immediate moves)
    {"orn", "Logical", 3, false},              // Wd,Wn,Wm | Xd,Xn,Xm | Wd,Wn,Wm,shift | Xd,Xn,Xm,shift (bitwise OR with bitwise NOT of shifted register)
    {"mvn", "Logical", 2, false},              // Wd,Wm | Xd,Xm | Wd,Wm,shift | Xd,Xm,shift (move bitwise NOT of register)
    {"eor", "Logical", 3, false},              // Wd,Wn,Wm | Xd,Xn,Xm | Wd,Wn,#bimm32 | Xd,Xn,#bimm64 | Wd,Wn,Wm,shift | Xd,Xn,Xm,shift
    {"eon", "Logical", 3, false},              // Wd,Wn,Wm | Xd,Xn,Xm | Wd,Wn,Wm,shift | Xd,Xn,Xm,shift (bitwise exclusive OR with bitwise NOT of shifted register)
    {"bic", "Logical", 3, false},              // Wd,Wn,Wm | Xd,Xn,Xm | Wd,Wn,Wm,shift | Xd,Xn,Xm,shift (bitwise AND with bitwise NOT of shifted register)
    {"bics", "Logical", 3, false},             // Wd,Wn,Wm | Xd,Xn,Xm | Wd,Wn,Wm,shift | Xd,Xn,Xm,shift (sets flags)
    
    // Shift operations (immediate)
    {"lsl", "Logical", 3, false},              // Wd,Wn,#shift | Xd,Xn,#shift (logical shift left)
    {"lsr", "Logical", 3, false},              // Wd,Wn,#shift | Xd,Xn,#shift (logical shift right)
    {"asr", "Logical", 3, false},              // Wd,Wn,#shift | Xd,Xn,#shift (arithmetic shift right)
    {"ror", "Logical", 3, false},              // Wd,Wn,#shift | Xd,Xn,#shift (rotate right)
    
    // Bit manipulation
    {"clz", "Logical", 2, false},              // Wd,Wn | Xd,Xn (count leading zeros)
    {"cls", "Logical", 2, false},              // Wd,Wn | Xd,Xn (count leading sign bits)
    {"rbit", "Logical", 2, false},             // Wd,Wn | Xd,Xn (reverse bits)
    {"rev", "Logical", 2, false},              // Wd,Wn | Xd,Xn (reverse bytes)
    {"rev16", "Logical", 2, false},            // Wd,Wn | Xd,Xn (reverse bytes in 16-bit halfwords)
    {"rev32", "Logical", 2, false},            // Xd,Xn (reverse bytes in 32-bit words)
    
    // Bit field operations
    {"sbfm", "Logical", 4, false},             // Wd,Wn,#immr,#imms | Xd,Xn,#immr,#imms (signed bit field move)
    {"bfm", "Logical", 4, false},              // Wd,Wn,#immr,#imms | Xd,Xn,#immr,#imms (bit field move)
    {"ubfm", "Logical", 4, false},             // Wd,Wn,#immr,#imms | Xd,Xn,#immr,#imms (unsigned bit field move)
    {"sbfiz", "Logical", 4, false},            // Wd,Wn,#lsb,#width | Xd,Xn,#lsb,#width (signed bit field insert zeros)
    {"bfi", "Logical", 4, false},              // Wd,Wn,#lsb,#width | Xd,Xn,#lsb,#width (bit field insert)
    {"ubfiz", "Logical", 4, false},            // Wd,Wn,#lsb,#width | Xd,Xn,#lsb,#width (unsigned bit field insert zeros)
    {"sbfx", "Logical", 4, false},             // Wd,Wn,#lsb,#width | Xd,Xn,#lsb,#width (signed bit field extract)
    {"bfxil", "Logical", 4, false},            // Wd,Wn,#lsb,#width | Xd,Xn,#lsb,#width (bit field extract and insert low)
    {"ubfx", "Logical", 4, false},             // Wd,Wn,#lsb,#width | Xd,Xn,#lsb,#width (unsigned bit field extract)
    {"sxtb", "Logical", 2, false},             // Wd,Wn | Xd,Wn (sign extend byte)
    {"sxth", "Logical", 2, false},             // Wd,Wn | Xd,Wn (sign extend halfword)
    {"sxtw", "Logical", 2, false},             // Xd,Wn (sign extend word)
    {"uxtb", "Logical", 2, false},             // Wd,Wn (zero extend byte)
    {"uxth", "Logical", 2, false},             // Wd,Wn (zero extend halfword)
    
    // Extract
    {"extr", "Logical", 4, false}              // Wd,Wn,Wm,#lsb | Xd,Xn,Xm,#lsb (extract register)
};

// Data Movement Instructions (comprehensive operand support)
static const instruction_def_t arm64_data_movement[] = {
    // Basic move operations
    {"mov", "Data Movement", 2, false},        // Wd,Wm | Xd,Xm | Wd,#imm16 | Xd,#imm16 | Wd,Wn | Xd,Xn
    {"movn", "Data Movement", 2, false},       // Wd,#imm16 | Xd,#imm16 (move wide with NOT)
    {"movz", "Data Movement", 2, false},       // Wd,#imm16 | Xd,#imm16 (move wide with zero)
    {"movk", "Data Movement", 2, false},       // Wd,#imm16 | Xd,#imm16 (move wide with keep)
    
    // Load operations
    {"ldr", "Data Movement", 2, false},        // Wt,[Xn] | Xt,[Xn] | Wt,[Xn,#imm] | Xt,[Xn,#imm] | Wt,[Xn,Xm] | Xt,[Xn,Xm] | Wt,=imm | Xt,=imm
    {"ldrb", "Data Movement", 2, false},       // Wt,[Xn] | Wt,[Xn,#imm] | Wt,[Xn,Xm]
    {"ldrh", "Data Movement", 2, false},       // Wt,[Xn] | Wt,[Xn,#imm] | Wt,[Xn,Xm]
    {"ldrsb", "Data Movement", 2, false},      // Wt,[Xn] | Xt,[Xn] | Wt,[Xn,#imm] | Xt,[Xn,#imm] | Wt,[Xn,Xm] | Xt,[Xn,Xm]
    {"ldrsh", "Data Movement", 2, false},      // Wt,[Xn] | Xt,[Xn] | Wt,[Xn,#imm] | Xt,[Xn,#imm] | Wt,[Xn,Xm] | Xt,[Xn,Xm]
    {"ldrsw", "Data Movement", 2, false},      // Xt,[Xn] | Xt,[Xn,#imm] | Xt,[Xn,Xm] | Xt,=imm
    {"ldur", "Data Movement", 2, false},       // Wt,[Xn,#imm] | Xt,[Xn,#imm] (unscaled immediate)
    {"ldurb", "Data Movement", 2, false},      // Wt,[Xn,#imm]
    {"ldurh", "Data Movement", 2, false},      // Wt,[Xn,#imm]
    {"ldursb", "Data Movement", 2, false},     // Wt,[Xn,#imm] | Xt,[Xn,#imm]
    {"ldursh", "Data Movement", 2, false},     // Wt,[Xn,#imm] | Xt,[Xn,#imm]
    {"ldursw", "Data Movement", 2, false},     // Xt,[Xn,#imm]
    
    // Store operations
    {"str", "Data Movement", 2, false},        // Wt,[Xn] | Xt,[Xn] | Wt,[Xn,#imm] | Xt,[Xn,#imm] | Wt,[Xn,Xm] | Xt,[Xn,Xm]
    {"strb", "Data Movement", 2, false},       // Wt,[Xn] | Wt,[Xn,#imm] | Wt,[Xn,Xm]
    {"strh", "Data Movement", 2, false},       // Wt,[Xn] | Wt,[Xn,#imm] | Wt,[Xn,Xm]
    {"stur", "Data Movement", 2, false},       // Wt,[Xn,#imm] | Xt,[Xn,#imm] (unscaled immediate)
    {"sturb", "Data Movement", 2, false},      // Wt,[Xn,#imm]
    {"sturh", "Data Movement", 2, false},      // Wt,[Xn,#imm]
    
    // Load/store pair
    {"ldp", "Data Movement", 3, false},        // Wt1,Wt2,[Xn] | Xt1,Xt2,[Xn] | Wt1,Wt2,[Xn,#imm] | Xt1,Xt2,[Xn,#imm]
    {"stp", "Data Movement", 3, false},        // Wt1,Wt2,[Xn] | Xt1,Xt2,[Xn] | Wt1,Wt2,[Xn,#imm] | Xt1,Xt2,[Xn,#imm]
    {"ldnp", "Data Movement", 3, false},       // Wt1,Wt2,[Xn,#imm] | Xt1,Xt2,[Xn,#imm] (non-temporal)
    {"stnp", "Data Movement", 3, false},       // Wt1,Wt2,[Xn,#imm] | Xt1,Xt2,[Xn,#imm] (non-temporal)
    
    // Exclusive load/store
    {"ldxr", "Data Movement", 2, false},       // Wt,[Xn] | Xt,[Xn] (load exclusive register)
    {"ldxrb", "Data Movement", 2, false},      // Wt,[Xn]
    {"ldxrh", "Data Movement", 2, false},      // Wt,[Xn]
    {"stxr", "Data Movement", 3, false},       // Ws,Wt,[Xn] | Ws,Xt,[Xn] (store exclusive register)
    {"stxrb", "Data Movement", 3, false},      // Ws,Wt,[Xn]
    {"stxrh", "Data Movement", 3, false},      // Ws,Wt,[Xn]
    {"ldxp", "Data Movement", 3, false},       // Wt1,Wt2,[Xn] | Xt1,Xt2,[Xn] (load exclusive pair)
    {"stxp", "Data Movement", 4, false},       // Ws,Wt1,Wt2,[Xn] | Ws,Xt1,Xt2,[Xn] (store exclusive pair)
    
    // Acquire/release exclusive
    {"ldaxr", "Data Movement", 2, false},      // Wt,[Xn] | Xt,[Xn] (load acquire exclusive register)
    {"ldaxrb", "Data Movement", 2, false},     // Wt,[Xn]
    {"ldaxrh", "Data Movement", 2, false},     // Wt,[Xn]
    {"stlxr", "Data Movement", 3, false},      // Ws,Wt,[Xn] | Ws,Xt,[Xn] (store release exclusive register)
    {"stlxrb", "Data Movement", 3, false},     // Ws,Wt,[Xn]
    {"stlxrh", "Data Movement", 3, false},     // Ws,Wt,[Xn]
    {"ldaxp", "Data Movement", 3, false},      // Wt1,Wt2,[Xn] | Xt1,Xt2,[Xn] (load acquire exclusive pair)
    {"stlxp", "Data Movement", 4, false},      // Ws,Wt1,Wt2,[Xn] | Ws,Xt1,Xt2,[Xn] (store release exclusive pair)
    
    // Acquire/release
    {"ldar", "Data Movement", 2, false},       // Wt,[Xn] | Xt,[Xn] (load acquire register)
    {"ldarb", "Data Movement", 2, false},      // Wt,[Xn]
    {"ldarh", "Data Movement", 2, false},      // Wt,[Xn]
    {"stlr", "Data Movement", 2, false},       // Wt,[Xn] | Xt,[Xn] (store release register)
    {"stlrb", "Data Movement", 2, false},      // Wt,[Xn]
    {"stlrh", "Data Movement", 2, false},      // Wt,[Xn]
    
    // Prefetch
    {"prfm", "Data Movement", 2, false},       // prfop,[Xn] | prfop,[Xn,#imm] | prfop,[Xn,Xm]
    {"prfum", "Data Movement", 2, false},      // prfop,[Xn,#imm] (unscaled immediate)
    
    // Address generation
    {"adr", "Data Movement", 2, false},        // Xd,label (address of label)
    {"adrp", "Data Movement", 2, false}        // Xd,label (address of page of label)
};

// Control Flow Instructions (comprehensive operand support)
static const instruction_def_t arm64_control_flow[] = {
    // Unconditional branches
    {"b", "Control Flow", 1, false},           // label (branch)
    {"bl", "Control Flow", 1, false},          // label (branch with link)
    {"br", "Control Flow", 1, false},          // Xn (branch to register)
    {"blr", "Control Flow", 1, false},         // Xn (branch with link to register)
    {"ret", "Control Flow", 0, false},         // none | Xn (return from subroutine)
    
    // Conditional branches
    {"b.eq", "Control Flow", 1, false},        // label (branch if equal)
    {"b.ne", "Control Flow", 1, false},        // label (branch if not equal)
    {"b.cs", "Control Flow", 1, false},        // label (branch if carry set)
    {"b.hs", "Control Flow", 1, false},        // label (branch if higher or same)
    {"b.cc", "Control Flow", 1, false},        // label (branch if carry clear)
    {"b.lo", "Control Flow", 1, false},        // label (branch if lower)
    {"b.mi", "Control Flow", 1, false},        // label (branch if minus)
    {"b.pl", "Control Flow", 1, false},        // label (branch if plus)
    {"b.vs", "Control Flow", 1, false},        // label (branch if overflow set)
    {"b.vc", "Control Flow", 1, false},        // label (branch if overflow clear)
    {"b.hi", "Control Flow", 1, false},        // label (branch if higher)
    {"b.ls", "Control Flow", 1, false},        // label (branch if lower or same)
    {"b.ge", "Control Flow", 1, false},        // label (branch if greater or equal)
    {"b.lt", "Control Flow", 1, false},        // label (branch if less than)
    {"b.gt", "Control Flow", 1, false},        // label (branch if greater than)
    {"b.le", "Control Flow", 1, false},        // label (branch if less or equal)
    {"b.al", "Control Flow", 1, false},        // label (branch always)
    {"b.nv", "Control Flow", 1, false},        // label (branch never)
    
    // Aliases for conditional branches
    {"beq", "Control Flow", 1, false},         // label (alias for b.eq)
    {"bne", "Control Flow", 1, false},         // label (alias for b.ne)
    {"bcs", "Control Flow", 1, false},         // label (alias for b.cs)
    {"bhs", "Control Flow", 1, false},         // label (alias for b.hs)
    {"bcc", "Control Flow", 1, false},         // label (alias for b.cc)
    {"blo", "Control Flow", 1, false},         // label (alias for b.lo)
    {"bmi", "Control Flow", 1, false},         // label (alias for b.mi)
    {"bpl", "Control Flow", 1, false},         // label (alias for b.pl)
    {"bvs", "Control Flow", 1, false},         // label (alias for b.vs)
    {"bvc", "Control Flow", 1, false},         // label (alias for b.vc)
    {"bhi", "Control Flow", 1, false},         // label (alias for b.hi)
    {"bls", "Control Flow", 1, false},         // label (alias for b.ls)
    {"bge", "Control Flow", 1, false},         // label (alias for b.ge)
    {"blt", "Control Flow", 1, false},         // label (alias for b.lt)
    {"bgt", "Control Flow", 1, false},         // label (alias for b.gt)
    {"ble", "Control Flow", 1, false},         // label (alias for b.le)
    
    // Compare and branch
    {"cbz", "Control Flow", 2, false},         // Wt,label | Xt,label (compare and branch if zero)
    {"cbnz", "Control Flow", 2, false},        // Wt,label | Xt,label (compare and branch if not zero)
    
    // Test bit and branch
    {"tbz", "Control Flow", 3, false},         // Wt,#imm,label | Xt,#imm,label (test bit and branch if zero)
    {"tbnz", "Control Flow", 3, false},        // Wt,#imm,label | Xt,#imm,label (test bit and branch if not zero)
    
    // Exception generation
    {"svc", "Control Flow", 1, false},         // #imm16 (supervisor call)
    {"hvc", "Control Flow", 1, false},         // #imm16 (hypervisor call)
    {"smc", "Control Flow", 1, false},         // #imm16 (secure monitor call)
    {"brk", "Control Flow", 1, false},         // #imm16 (breakpoint)
    {"hlt", "Control Flow", 1, false},         // #imm16 (halt)
    
    // Exception return
    {"eret", "Control Flow", 0, false},        // none (exception return)
    {"drps", "Control Flow", 0, false}         // none (debug restore process state)
};

// System Instructions (comprehensive system-level operations)
static const instruction_def_t arm64_system[] = {
    // Memory barriers
    {"dmb", "System", 1, false},               // option (data memory barrier)
    {"dsb", "System", 1, false},               // option (data synchronization barrier)
    {"isb", "System", 0, false},               // none | option (instruction synchronization barrier)
    
    // System register access
    {"mrs", "System", 2, false},               // Xt,systemreg (move from system register)
    {"msr", "System", 2, false},               // systemreg,Xt | pstatefield,#imm (move to system register)
    
    // Cache maintenance
    {"ic", "System", 2, false},                // op,Xt (instruction cache operation)
    {"dc", "System", 2, false},                // op,Xt (data cache operation)
    {"at", "System", 2, false},                // op,Xt (address translate operation)
    {"tlbi", "System", 1, false},              // op | op,Xt (TLB invalidate operation)
    
    // Hints
    {"nop", "System", 0, false},               // none (no operation)
    {"yield", "System", 0, false},             // none (yield hint)
    {"wfe", "System", 0, false},               // none (wait for event)
    {"wfi", "System", 0, false},               // none (wait for interrupt)
    {"sev", "System", 0, false},               // none (send event)
    {"sevl", "System", 0, false},              // none (send event local)
    
    // Implementation defined
    {"sys", "System", 5, false},               // #op1,Cn,Cm,#op2,Xt (system instruction)
    {"sysl", "System", 5, false},              // Xt,#op1,Cn,Cm,#op2 (system instruction with result)
    
    // Crypto instructions (optional)
    {"aese", "System", 2, true},               // Vd.16B,Vn.16B (AES encrypt)
    {"aesd", "System", 2, true},               // Vd.16B,Vn.16B (AES decrypt)
    {"aesmc", "System", 2, true},              // Vd.16B,Vn.16B (AES mix columns)
    {"aesimc", "System", 2, true},             // Vd.16B,Vn.16B (AES inverse mix columns)
    {"sha1c", "System", 3, true},              // Qd,Sn,Vm.4S (SHA1 hash update C)
    {"sha1p", "System", 3, true},              // Qd,Sn,Vm.4S (SHA1 hash update P)
    {"sha1m", "System", 3, true},              // Qd,Sn,Vm.4S (SHA1 hash update M)
    {"sha1h", "System", 2, true},              // Sd,Sn (SHA1 fixed rotate)
    {"sha1su0", "System", 3, true},            // Vd.4S,Vn.4S,Vm.4S (SHA1 schedule update 0)
    {"sha1su1", "System", 2, true},            // Vd.4S,Vn.4S (SHA1 schedule update 1)
    {"sha256h", "System", 3, true},            // Qd,Qn,Vm.4S (SHA256 hash update part 1)
    {"sha256h2", "System", 3, true},           // Qd,Qn,Vm.4S (SHA256 hash update part 2)
    {"sha256su0", "System", 2, true},          // Vd.4S,Vn.4S (SHA256 schedule update 0)
    {"sha256su1", "System", 3, true}           // Vd.4S,Vn.4S,Vm.4S (SHA256 schedule update 1)
};

static const instruction_category_t arm64_categories[] = {
    {"Arithmetic", arm64_arithmetic, sizeof(arm64_arithmetic)/sizeof(instruction_def_t)},
    {"Logical", arm64_logical, sizeof(arm64_logical)/sizeof(instruction_def_t)},
    {"Data Movement", arm64_data_movement, sizeof(arm64_data_movement)/sizeof(instruction_def_t)},
    {"Control Flow", arm64_control_flow, sizeof(arm64_control_flow)/sizeof(instruction_def_t)},
    {"System", arm64_system, sizeof(arm64_system)/sizeof(instruction_def_t)}
};

const arch_instruction_set_t* get_arm64_instruction_set(void) {
    static const arch_instruction_set_t arm64_set = {
        "arm64", 
        arm64_categories, 
        sizeof(arm64_categories)/sizeof(instruction_category_t)
    };
    return &arm64_set;
}
