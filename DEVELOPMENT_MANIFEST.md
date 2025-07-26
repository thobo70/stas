# STAS Development Manifest

**Project**: STAS (Simple Target Assembler System)  
**Date**: July 26, 2025  
**Version**: 1.0  
**Status**: BINDING DECLARATION

---

## Core Development Principles

This manifest establishes **non-negotiable principles** that must be followed in all STAS development work. These principles take precedence over convenience, compatibility, or expedient solutions.

### 1. **CPU ACCURACY IS PARAMOUNT** 🎯

**PRINCIPLE**: STAS must behave **exactly like real CPUs**, not like other assemblers or convenience tools.

**IMPLEMENTATION RULES**:
- ✅ **Real CPU behavior takes absolute precedence** over test compatibility
- ✅ **Hardware documentation is the ultimate authority** (Intel manuals, ARM reference, RISC-V spec)
- ✅ **If tests are wrong, fix the tests** - never implement incorrect CPU behavior to pass tests
- ✅ **Instruction encoding must match real hardware** bit-for-bit
- ✅ **Operand constraints must match real CPU limitations** (e.g., x86 shifts only use CL register or immediate)
- ❌ **Never implement "convenient" behavior** that differs from real CPUs
- ❌ **Never accept "close enough" instruction encoding**

**VALIDATION**: Every instruction implementation must be verified against:
1. Official CPU documentation
2. Real hardware behavior (when possible)
3. Bit-exact instruction encoding verification

---

### 2. **AT&T SYNTAX ADHERENCE** 🔤

**PRINCIPLE**: STAS uses **AT&T assembler syntax exclusively** with complete fidelity.

**SYNTAX REQUIREMENTS**:
- ✅ **Operand Order**: `source, destination` (opposite of Intel syntax)
  - Correct: `mov %eax, %ebx` (move EAX to EBX)
  - Wrong: `mov %ebx, %eax` (Intel-style)
- ✅ **Register Prefix**: All registers use `%` prefix (`%eax`, `%rdi`, `%x0`)
- ✅ **Immediate Prefix**: All immediates use `$` prefix (`$5`, `$0x1000`)
- ✅ **Size Suffixes**: Instruction size indicated by suffix (`movb`, `movw`, `movl`, `movq`)
- ✅ **Memory Addressing**: `offset(%base,%index,scale)` format
- ✅ **Directive Prefix**: All directives use `.` prefix (`.section`, `.global`)

**EXAMPLES**:
```assembly
# Correct AT&T Syntax
movl $5, %eax           # Move immediate 5 to EAX
addl %ebx, %eax         # Add EBX to EAX
shl $1, %eax            # Shift EAX left by 1
movl 8(%esp), %eax      # Load from stack
```

**VALIDATION**: All syntax must pass validation against GNU AS (gas) compatibility.

---

### 3. **ARCHITECTURAL PRECISION** 🏗️

**PRINCIPLE**: Each architecture implementation must be **architecturally accurate** and complete.

**ARCHITECTURE-SPECIFIC RULES**:

#### **x86 Family (x86_16, x86_32, x86_64)**:
- ✅ **Instruction Encoding**: Use official Intel/AMD opcode tables
- ✅ **Addressing Modes**: Support all legitimate x86 addressing modes
- ✅ **Operand Sizes**: Respect byte/word/dword/qword distinctions
- ✅ **Segment Handling**: Proper segment prefix support for x86_16
- ✅ **Register Encodings**: Use correct register encoding values

#### **ARM64 (AArch64)**:
- ✅ **Instruction Format**: 32-bit fixed-width instructions
- ✅ **Register Types**: Distinguish W (32-bit) vs X (64-bit) registers
- ✅ **Immediate Encoding**: Respect ARM64 immediate encoding limitations
- ✅ **Condition Codes**: Proper condition code handling

#### **RISC-V**:
- ✅ **Instruction Types**: R-type, I-type, S-type, B-type, U-type, J-type
- ✅ **Register ABI**: Use standard RISC-V register naming
- ✅ **Immediate Encoding**: Respect RISC-V immediate constraints
- ✅ **Extensions**: Clear separation of base ISA vs extensions

---

### 4. **TEST FRAMEWORK INTEGRITY** 🧪

**PRINCIPLE**: Tests must validate **real-world assembly scenarios**, not accommodate implementation shortcuts.

**TESTING RULES**:
- ✅ **Realistic Operands**: Tests use operand combinations that real programs would use
- ✅ **CPU-Accurate Constraints**: Test operand constraints match real CPU limitations
- ✅ **Functional Verification**: Test both parsing AND encoding accuracy
- ✅ **Error Case Testing**: Invalid operand combinations must be rejected
- ❌ **No Accommodation Testing**: Don't modify tests to make broken implementations pass
- ❌ **No Synthetic Scenarios**: Avoid test cases that would never occur in real assembly

**TEST CATEGORIES**:
1. **Functional Tests**: Verify correct instruction encoding
2. **Syntax Tests**: Verify AT&T syntax compliance
3. **Error Tests**: Verify proper rejection of invalid constructs
4. **Integration Tests**: Verify multi-instruction program assembly

---

### 5. **CODE QUALITY STANDARDS** 💎

**PRINCIPLE**: STAS code must be **maintainable, readable, and architecturally sound**.

**CODE STANDARDS**:
- ✅ **Clear Architecture Separation**: Each architecture in separate, self-contained modules
- ✅ **Consistent Naming**: Use consistent naming conventions across all modules
- ✅ **Comprehensive Documentation**: Every function documents its purpose and constraints
- ✅ **Error Handling**: Proper error reporting with specific failure reasons
- ✅ **Memory Management**: No memory leaks, proper cleanup
- ✅ **Thread Safety**: Code should be thread-safe where applicable

**FORBIDDEN PRACTICES**:
- ❌ **Architecture Cross-Contamination**: x86 code in ARM modules, etc.
- ❌ **Magic Numbers**: Use named constants for all opcodes and encodings
- ❌ **Silent Failures**: Every error must be reported with context
- ❌ **Copy-Paste Programming**: Duplicate code should be refactored

---

### 6. **OUTPUT FORMAT PRECISION** 📁

**PRINCIPLE**: Generated object files must be **bit-perfect** and standards-compliant.

**FORMAT REQUIREMENTS**:
- ✅ **Standards Compliance**: ELF, COM, Intel HEX, etc. must match official specifications
- ✅ **Endianness Handling**: Proper little/big-endian handling per format requirements
- ✅ **Section Management**: Correct section types, flags, and alignment
- ✅ **Symbol Tables**: Accurate symbol table generation
- ✅ **Relocation Records**: Proper relocation entry generation

**VALIDATION**: Output files must be accepted by standard linkers and loaders.

---

### 7. **BACKWARD COMPATIBILITY** 🔄

**PRINCIPLE**: STAS maintains **strict backward compatibility** within major versions.

**COMPATIBILITY RULES**:
- ✅ **Syntax Stability**: AT&T syntax interpretation never changes
- ✅ **API Stability**: Public APIs remain stable within major versions
- ✅ **Output Stability**: Generated object files remain compatible
- ✅ **Configuration Stability**: Command-line options remain consistent

**EXCEPTIONS**: Security fixes and CPU accuracy corrections override compatibility.

---

### 8. **PERFORMANCE REQUIREMENTS** ⚡

**PRINCIPLE**: STAS must be **fast enough for practical use** without sacrificing accuracy.

**PERFORMANCE TARGETS**:
- ✅ **Assembly Speed**: >10,000 lines/second on modern hardware
- ✅ **Memory Usage**: <100MB for typical projects
- ✅ **Startup Time**: <100ms cold start
- ✅ **Incremental Assembly**: Support for fast incremental builds

**MEASUREMENT**: Performance must be measured and tracked across releases.

---

### 9. **ERROR REPORTING EXCELLENCE** 🚨

**PRINCIPLE**: Error messages must be **helpful, specific, and actionable**.

**ERROR MESSAGE REQUIREMENTS**:
- ✅ **Specific Location**: Line and column number for all errors
- ✅ **Clear Description**: Plain English explanation of the problem
- ✅ **Suggested Fix**: When possible, suggest how to fix the error
- ✅ **Context Information**: Show relevant source code context
- ✅ **Error Categories**: Classify errors (syntax, semantic, encoding, etc.)

**EXAMPLES**:
```
Good: "Line 23, Column 15: Invalid operand combination for 'shl' - 
       x86 shift count must be immediate value or %cl register.
       Found: %ebx (general register not allowed)
       Suggestion: Use 'shl $1, %eax' or 'shl %cl, %eax'"

Bad:  "Error: Invalid operand"
```

---

### 10. **DOCUMENTATION REQUIREMENTS** 📚

**PRINCIPLE**: STAS must be **thoroughly documented** for users and developers.

**DOCUMENTATION STANDARDS**:
- ✅ **User Manual**: Complete AT&T syntax guide with examples
- ✅ **Architecture Guides**: Detailed guides for each supported architecture
- ✅ **API Documentation**: Complete function and structure documentation
- ✅ **Examples**: Working examples for all major use cases
- ✅ **Troubleshooting**: Common problems and solutions

---

## Implementation Priorities

### **Priority 1: CPU Accuracy** 🎯
All instruction implementations must be CPU-accurate before moving to new features.

### **Priority 2: AT&T Syntax Compliance** 🔤
Syntax must be perfectly compatible with GNU AS wherever applicable.

### **Priority 3: Completeness** 📊
Achieve high functional coverage within each architecture before adding new architectures.

### **Priority 4: Performance** ⚡
Optimize only after correctness is established.

---

## Violation Consequences

**ANY VIOLATION** of these principles requires:
1. **Immediate correction** of the violation
2. **Test case addition** to prevent future violations
3. **Documentation update** if applicable
4. **Review of related code** for similar violations

---

## Manifest Approval

This manifest is **binding** for all STAS development work and takes precedence over:
- Personal preferences
- Convenience considerations
- "Quick fix" temptations
- Compatibility with broken tools
- Time pressure

**Signed**: me  
**Date**: July 26, 2025  
**Version**: 1.0

---

## Quick Reference

### ✅ **ALWAYS DO**:
- Follow AT&T syntax exactly (`source, destination`)
- Verify against real CPU behavior
- Fix tests when they're wrong, not the implementation
- Use proper register prefixes (`%eax`, not `eax`)
- Use proper immediate prefixes (`$5`, not `5`)
- Document CPU-specific constraints
- Report specific, actionable errors

### ❌ **NEVER DO**:
- Implement Intel syntax operand order
- Create "convenient" behavior that differs from real CPUs
- Modify implementation to pass wrong tests
- Use magic numbers instead of named constants
- Silent failure or generic error messages
- Mix architecture code between modules
- Sacrifice CPU accuracy for convenience

### 🔍 **WHEN IN DOUBT**:
1. Check official CPU documentation
2. Test against real hardware (when possible)
3. Verify AT&T syntax compliance
4. Ask: "What would a real CPU do?"
5. Choose accuracy over convenience

---

**Remember**: The goal is to create an assembler that behaves **exactly like real hardware**, not like other assemblers or convenient tools.
