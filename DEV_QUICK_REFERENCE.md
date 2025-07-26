# STAS Developer Quick Reference Card

**📋 DEVELOPMENT PRINCIPLES**: CPU Accuracy + AT&T Syntax = Success

---

## 🎯 Core Rules (FROM MANIFEST)

### **1. CPU ACCURACY & Architecture Completeness**
- x86_16: **100%** functional ✅ COMPLETE
- x86_32: **52.1%** functional (112/215) **85.1% recognized** (183/215) 🚀💥 **PHASE 2 COMPLETE** - Intel i386 documentation validated!
- x86_64: **28.1%** functional 
- ARM64: **13.8%** functional
- RISC-V: **15.7%** functional
- ✅ Real CPU behavior takes absolute precedence
- ✅ Hardware documentation is the ultimate authority
- ✅ If tests are wrong, fix the tests
- ❌ Never implement "convenient" behavior that differs from real CPUs

### **2. AT&T SYNTAX ADHERENCE**
- ✅ Operand order: `source, destination` (opposite of Intel)
- ✅ Register prefix: `%eax`, `%rdi`, `%x0`
- ✅ Immediate prefix: `$5`, `$0x1000`
- ✅ Directive prefix: `.section`, `.global`

---

## 🔤 AT&T Syntax Quick Examples

```assembly
# CORRECT AT&T SYNTAX (source, destination)
movl %eax, %ebx     # Move EAX to EBX ✅
addl $5, %eax       # Add 5 to EAX ✅
shl $1, %eax        # Shift EAX left by 1 ✅
shl %cl, %eax       # Shift EAX left by CL ✅

# WRONG (Intel-style or incorrect)
movl %ebx, %eax     # Wrong operand order ❌
add 5, %eax         # Missing $ prefix ❌
shl %ebx, %eax      # Wrong register (only CL allowed) ❌
mov eax, ebx        # Missing % prefix ❌
```

---

## 🧪 Test Philosophy

**When a test fails, ask:**
1. ✅ Is my implementation CPU-accurate?
2. ✅ Does it follow AT&T syntax perfectly?
3. ✅ Does it match official CPU documentation?
4. ❌ Can I modify the test to make it pass?

**Golden Rule**: Fix tests, not implementations (unless implementation is wrong)

## 🔬 Instruction Completeness Testing

**Basic Usage:**
```bash
# Test all architectures
./testbin/instruction_completeness

# Test specific architecture  
./testbin/instruction_completeness x86_32

# Get detailed failure reports
./testbin/instruction_completeness x86_32 -v

# Compact output for CI
./testbin/instruction_completeness x86_32 -c
```

**Verbose Mode Output:**
- ❌ **UNRECOGNIZED**: Instructions not parsed at all
- ⚠️ **NON-FUNCTIONAL**: Parsed but encoding fails
- Focus on UNRECOGNIZED first, then NON-FUNCTIONAL

---

## 🚨 Error Message Standards

**Template**:
```
Line X, Column Y: [CLEAR PROBLEM DESCRIPTION]
Found: [WHAT WAS ACTUALLY PROVIDED]
Expected: [WHAT SHOULD BE PROVIDED]
Suggestion: [HOW TO FIX IT]
```

**Good Example**:
```
Line 23, Column 15: Invalid operand combination for 'shl'
Found: %ebx (general register)
Expected: immediate value ($1-$31) or %cl register
Suggestion: Use 'shl $1, %eax' or 'shl %cl, %eax'
```

**Bad Example**: ❌ `Error: Invalid operand`

---

## 🏗️ Architecture Separation

```
src/arch/x86_16/    # 16-bit x86 ONLY
src/arch/x86_32/    # 32-bit x86 ONLY  
src/arch/x86_64/    # 64-bit x86 ONLY
src/arch/arm64/     # ARM64 ONLY
src/arch/riscv/     # RISC-V ONLY
```

**FORBIDDEN**: Cross-architecture code contamination!

---

## 📖 Reference Sources (When In Doubt)

### **x86 Family**
- Intel 64 and IA-32 Architectures Software Developer's Manual
- AMD64 Architecture Programmer's Manual
- GNU AS manual for AT&T syntax verification

### **ARM64**
- ARM Architecture Reference Manual for A-profile architecture
- ARM64 ABI documentation

### **RISC-V**
- RISC-V Instruction Set Manual (Volume I & II)
- RISC-V ABI Specification

---

## ⚡ Quick Decision Tree

```
Implementation Question?
├── Does it match real CPU behavior?
│   ├── YES → Check AT&T syntax compliance
│   │   ├── YES → Implement it ✅
│   │   └── NO → Fix syntax, then implement ✅
│   └── NO → Don't implement, research real CPU behavior ❌
└── Test failing?
    ├── Is implementation CPU-accurate? 
    │   ├── YES → Fix the test ✅
    │   └── NO → Fix implementation ✅
```

---

## 🎛️ Architecture-Specific Notes

### **x86 Family**
- Shift operations: Only immediate or `%cl` register for count
- Memory addressing: `offset(%base,%index,scale)`
- Size suffixes: `b` (byte), `w` (word), `l` (long), `q` (quad)

### **ARM64**
- Fixed 32-bit instruction width
- Register types: `w0-w30` (32-bit), `x0-x30` (64-bit)
- Immediate encoding limitations are strict

### **RISC-V**
- Instruction types: R, I, S, B, U, J
- Register naming: `x0-x31` (standard ABI names like `ra`, `sp` also valid)
- Immediate constraints vary by instruction type

---

## 🔧 Common Fixes

### **Test Operand Setup**
```c
// CORRECT: Shift operations need immediate or CL
if (is_shift_op) {
    operands[0].type = OPERAND_IMMEDIATE;
    operands[0].value.immediate = 1;  // Valid shift count
}

// WRONG: Random register for shift count
operands[0].type = OPERAND_REGISTER;
operands[0].value.reg.name = "ebx";  // Not valid for x86 shifts
```

### **AT&T Operand Order**
```c
// CORRECT: source first, destination second
parse_operand(inst->operands[0]);  // source
parse_operand(inst->operands[1]);  // destination

// Generate: mov source, destination
```

---

## 🏆 Success Metrics

### **Architecture Completeness**
- x86_16: **100%** functional ✅ COMPLETE
- x86_32: **69.8%** functional (150/215) **85.1% recognized** (183/215) 🚀💥 **PUSHING TO 100%** - **Arithmetic: 100% ✅** String: 66.7%, Logical: 93.8%, I/O & Advanced Data Movement Added
- x86_64: **28.1%** functional 
- ARM64: **13.8%** functional
- RISC-V: **15.7%** functional

### **Quality Gates**
- [ ] CPU documentation verified
- [ ] AT&T syntax compliant
- [ ] Test cases realistic
- [ ] Error messages helpful
- [ ] No architecture cross-contamination
- [ ] All tests pass before finishing a task / before preparing commit

---

**📞 Emergency Contact**: See `DEVELOPMENT_MANIFEST.md` for complete principles
**🔗 User Reference**: See `QUICK_REFERENCE.md` for user command examples
