# Phase 7: Advanced Language Features - COMPLETE

This directory demonstrates all Phase 7 features of the STAS assembler:

## 1. Include Directives ✅
- Support for `.include "filename"` directives
- File inclusion with proper path resolution
- Constant and label sharing across files

Example:
```assembly
.include "common_defs.inc"   # Includes constant definitions
movq $INCLUDED_VALUE, %rax   # Uses constant from included file
```

## 2. Advanced Expressions ✅
- Complex arithmetic and bitwise expressions
- Proper operator precedence
- Shared macro and symbol namespaces across included files

Example:
```assembly
.include "common_defs.inc"   # Includes constant definitions
movq $INCLUDED_VALUE, %rax   # Uses constant from included file
```

## 3. Advanced Expressions ✅
- Complex constant expression evaluation
- Symbol arithmetic and constant evaluation
- Operator precedence parsing

Example:
```assembly
BASE = 0x1000
OFFSET = 0x100
movq $(BASE + OFFSET), %rax  # Complex expression evaluation
```

## Test Files:
- `phase7_complete_demo.s` - Comprehensive demonstration of all features
- `common_defs.inc` - Example include file with constant definitions

## Verification:
All Phase 7 features have been implemented and tested successfully. The assembler now supports:
- File inclusion system with proper path resolution  
- Advanced expression evaluation with operator precedence

**Status: PHASE 7 COMPLETE ✅**
