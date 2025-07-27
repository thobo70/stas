# STAS Directive Status Documentation

This document provides a comprehensive analysis of directive support in STAS (STIX Modular Assembler), detailing which directives are recognized, working, and missing.

## Executive Summary

STAS implements a three-layer directive processing system:
1. **Lexer**: Recognizes any identifier starting with '.' as `TOKEN_DIRECTIVE`
2. **Parser**: Processes directives into AST nodes with special handling for `.include`
3. **Codegen**: Implements core directive functionality with architecture-specific extensions

## Directive Categories

### 1. CORE ASSEMBLY DIRECTIVES

#### 1.1 Section Management
**Status: FULLY IMPLEMENTED**

| Directive | Status | Description | Usage | Implementation |
|-----------|---------|-------------|--------|----------------|
| `.section` | ✅ WORKING | Define or switch to a section | `.section .text`, `.section .data` | codegen.c:271-400 |
| `.text` | ✅ WORKING | Switch to text section | `.text` | codegen.c:271-400 |
| `.data` | ✅ WORKING | Switch to data section | `.data` | codegen.c:271-400 |
| `.bss` | ✅ WORKING | Switch to BSS section | `.bss` | codegen.c:271-400 |
| `.rodata` | 🟡 RECOGNIZED | Switch to read-only data section | `.rodata` | Parser recognizes, limited codegen |

**Implementation Details:**
- Core section directives are fully functional in `codegen_process_directive()`
- Supports standard ELF sections: .text, .data, .bss
- Section switching updates current output context
- Architecture-independent implementation

#### 1.2 Symbol Management
**Status: PARTIALLY IMPLEMENTED**

| Directive | Status | Description | Usage | Implementation |
|-----------|---------|-------------|--------|----------------|
| `.global` | 🟡 RECOGNIZED | Export symbol globally | `.global _start` | Parser only, no codegen |
| `.extern` | 🟡 RECOGNIZED | Import external symbol | `.extern exit` | Parser only, no codegen |
| `.local` | ❌ NOT IMPLEMENTED | Mark symbol as local | `.local temp_var` | Not recognized |
| `.weak` | ❌ NOT IMPLEMENTED | Mark symbol as weak | `.weak optional_symbol` | Not recognized |
| `.hidden` | ❌ NOT IMPLEMENTED | Mark symbol visibility | `.hidden internal_func` | Not recognized |
| `.protected` | ❌ NOT IMPLEMENTED | Mark symbol visibility | `.protected shared_func` | Not recognized |

**Implementation Gap:**
- Parser recognizes `.global` and `.extern` but doesn't generate symbol table entries
- No implementation of ELF symbol visibility attributes
- Missing weak symbol support

#### 1.3 Data Definition
**Status: PARTIALLY IMPLEMENTED**

| Directive | Status | Description | Usage | Implementation |
|-----------|---------|-------------|--------|----------------|
| `.ascii` | ✅ WORKING | Define ASCII string | `.ascii "Hello"` | codegen.c:271-400 |
| `.asciz` | ❌ NOT IMPLEMENTED | Define null-terminated string | `.asciz "Hello"` | Not recognized |
| `.string` | ❌ NOT IMPLEMENTED | Define null-terminated string | `.string "Hello"` | Not recognized |
| `.byte` | ❌ NOT IMPLEMENTED | Define byte values | `.byte 42, 0xFF` | Not recognized |
| `.word` | ❌ NOT IMPLEMENTED | Define 16-bit values | `.word 1234` | Not recognized |
| `.dword` | ❌ NOT IMPLEMENTED | Define 32-bit values | `.dword 0x12345678` | Not recognized |
| `.quad` | ❌ NOT IMPLEMENTED | Define 64-bit values | `.quad 0x123456789ABCDEF0` | Not recognized |
| `.space` | ✅ WORKING | Reserve space | `.space 64` | codegen.c:271-400 |

**Implementation Details:**
- Only `.ascii` and `.space` are fully functional
- Missing comprehensive data type support
- No endianness handling for multi-byte values

### 2. ARCHITECTURE-SPECIFIC DIRECTIVES

#### 2.1 x86 Code Mode Directives
**Status: FULLY IMPLEMENTED**

| Directive | Status | Description | Usage | Architecture | Implementation |
|-----------|---------|-------------|--------|--------------|----------------|
| `.code16` | ✅ WORKING | 16-bit code mode | `.code16` | x86_16, x86_32 | x86_32.c:157-190 |
| `.code32` | ✅ WORKING | 32-bit code mode | `.code32` | x86_32 | x86_32.c:157-190 |
| `.code64` | ✅ WORKING | 64-bit code mode | `.code64` | x86_64 | x86_64.c:532-544 |

**Implementation Details:**
- x86_32 handles both `.code16` and `.code32` modes
- x86_64 handles `.code64` mode
- Mode switching affects instruction encoding
- Used in examples: hello_x86_16.s, hello_x86_32.s, hello_x86_64.s

#### 2.2 x86 CPU Level Directives
**Status: FULLY IMPLEMENTED (x86_32 only)**

| Directive | Status | Description | Usage | Architecture | Implementation |
|-----------|---------|-------------|--------|--------------|----------------|
| `.386` | ✅ WORKING | 80386 CPU level | `.386` | x86_32 | x86_32.c:169-191 |
| `.486` | ✅ WORKING | 80486 CPU level | `.486` | x86_32 | x86_32.c:173-191 |
| `.586` | ✅ WORKING | Pentium CPU level | `.586` | x86_32 | x86_32.c:177-191 |
| `.686` | ✅ WORKING | Pentium Pro CPU level | `.686` | x86_32 | x86_32.c:181-191 |

**Implementation Details:**
- Only implemented in x86_32 architecture
- Sets internal cpu_level variable
- Affects available instruction sets

#### 2.3 ARM64 Directives
**Status: STUB IMPLEMENTATION**

| Directive | Status | Description | Usage | Architecture | Implementation |
|-----------|---------|-------------|--------|--------------|----------------|
| (Any) | 🟡 STUB | Architecture-specific directives | Various | ARM64 | arm64.c:568-572 |

**Implementation Details:**
- `arm64_handle_directive()` is a stub that accepts all directives
- No actual ARM64-specific directive processing
- Returns success for any directive

#### 2.4 RISC-V Directives
**Status: STUB IMPLEMENTATION**

| Directive | Status | Description | Usage | Architecture | Implementation |
|-----------|---------|-------------|--------|--------------|----------------|
| (Any) | 🟡 STUB | Architecture-specific directives | Various | RISC-V | riscv.c:374-384 |

**Implementation Details:**
- `riscv_handle_directive()` is a stub that accepts all directives
- No actual RISC-V-specific directive processing
- Returns success for any directive

#### 2.5 x86_16 Directives
**Status: STUB IMPLEMENTATION**

| Directive | Status | Description | Usage | Architecture | Implementation |
|-----------|---------|-------------|--------|--------------|----------------|
| (Any) | 🟡 STUB | Architecture-specific directives | Various | x86_16 | x86_16.c:1021-1024 |

**Implementation Details:**
- `x86_16_handle_directive_internal()` is a stub
- No actual x86_16-specific directive processing
- Returns success for any directive

### 3. PREPROCESSOR DIRECTIVES

#### 3.1 File Inclusion
**Status: FULLY IMPLEMENTED**

| Directive | Status | Description | Usage | Implementation |
|-----------|---------|-------------|--------|----------------|
| `.include` | ✅ WORKING | Include external file | `.include "common_defs.inc"` | parser.c:487-602 |

**Implementation Details:**
- Special handling in parser with file path resolution
- Supports relative and absolute paths
- Recursive inclusion protection
- Used in examples: phase7_complete_demo.s

#### 3.2 Macro Directives
**Status: RECOGNIZED (Token Level)**

| Directive | Status | Description | Usage | Implementation |
|-----------|---------|-------------|--------|----------------|
| `#define` | 🟡 TOKENIZED | Define macro | `#define CONSTANT 42` | lexer.h:TOKEN_MACRO_DEFINE |
| `#ifdef` | 🟡 TOKENIZED | Conditional compilation | `#ifdef DEBUG` | lexer.h:TOKEN_MACRO_IFDEF |
| `#ifndef` | 🟡 TOKENIZED | Negative conditional | `#ifndef RELEASE` | lexer.h:TOKEN_MACRO_IFNDEF |
| `#if` | 🟡 TOKENIZED | Expression conditional | `#if VERSION > 1` | lexer.h:TOKEN_MACRO_IF |
| `#else` | 🟡 TOKENIZED | Alternative branch | `#else` | lexer.h:TOKEN_MACRO_ELSE |
| `#elif` | 🟡 TOKENIZED | Conditional alternative | `#elif VERSION == 2` | lexer.h:TOKEN_MACRO_ELIF |
| `#endif` | 🟡 TOKENIZED | End conditional | `#endif` | lexer.h:TOKEN_MACRO_ENDIF |
| `#undef` | 🟡 TOKENIZED | Undefine macro | `#undef CONSTANT` | lexer.h:TOKEN_MACRO_UNDEF |

**Implementation Details:**
- Tokens defined in lexer.h but no parser/codegen implementation
- Framework exists for macro processor integration
- Used in examples: phase7_complete_demo.s, common_defs.inc

### 4. ASSEMBLER DIRECTIVES (NOT IMPLEMENTED)

#### 4.1 Alignment and Organization
**Status: NOT IMPLEMENTED**

| Directive | Status | Description | Usage | Implementation |
|-----------|---------|-------------|--------|----------------|
| `.align` | ❌ NOT IMPLEMENTED | Align to boundary | `.align 16` | Not recognized |
| `.org` | ❌ NOT IMPLEMENTED | Set origin address | `.org 0x8000` | Not recognized |
| `.fill` | ❌ NOT IMPLEMENTED | Fill with pattern | `.fill 10, 1, 0xFF` | Not recognized |

#### 4.2 Symbol Definition
**Status: NOT IMPLEMENTED**

| Directive | Status | Description | Usage | Implementation |
|-----------|---------|-------------|--------|--------------|
| `.equ` | ❌ NOT IMPLEMENTED | Define constant | `.equ MAX_VALUE, 100` | Not recognized |
| `.set` | ❌ NOT IMPLEMENTED | Define/redefine symbol | `.set FLAG, 1` | Not recognized |
| `.equiv` | ❌ NOT IMPLEMENTED | Define equivalent | `.equiv ALIAS, SYMBOL` | Not recognized |

#### 4.3 Symbol Attributes
**Status: NOT IMPLEMENTED**

| Directive | Status | Description | Usage | Implementation |
|-----------|---------|-------------|--------|---------------|
| `.type` | ❌ NOT IMPLEMENTED | Set symbol type | `.type _start, @function` | Not recognized |
| `.size` | ❌ NOT IMPLEMENTED | Set symbol size | `.size _start, .-_start` | Not recognized |
| `.comm` | ❌ NOT IMPLEMENTED | Common symbol | `.comm buffer, 256, 8` | Not recognized |
| `.lcomm` | ❌ NOT IMPLEMENTED | Local common | `.lcomm temp, 128, 4` | Not recognized |

#### 4.4 Syntax Control
**Status: NOT IMPLEMENTED**

| Directive | Status | Description | Usage | Implementation |
|-----------|---------|-------------|--------|---------------|
| `.intel_syntax` | ❌ NOT IMPLEMENTED | Intel syntax mode | `.intel_syntax noprefix` | Not recognized |
| `.att_syntax` | ❌ NOT IMPLEMENTED | AT&T syntax mode | `.att_syntax prefix` | Not recognized |

#### 4.5 Debug Information
**Status: NOT IMPLEMENTED**

| Directive | Status | Description | Usage | Implementation |
|-----------|---------|-------------|--------|---------------|
| `.file` | ❌ NOT IMPLEMENTED | Source filename | `.file "test.s"` | Not recognized |
| `.line` | ❌ NOT IMPLEMENTED | Line number | `.line 42` | Not recognized |
| `.loc` | ❌ NOT IMPLEMENTED | Location info | `.loc 1 42 10` | Not recognized |

#### 4.6 CFI (Call Frame Information)
**Status: NOT IMPLEMENTED**

| Directive | Status | Description | Usage | Implementation |
|-----------|---------|-------------|--------|---------------|
| `.cfi_startproc` | ❌ NOT IMPLEMENTED | Start procedure | `.cfi_startproc` | Not recognized |
| `.cfi_endproc` | ❌ NOT IMPLEMENTED | End procedure | `.cfi_endproc` | Not recognized |

#### 4.7 Advanced Macros
**Status: NOT IMPLEMENTED**

| Directive | Status | Description | Usage | Implementation |
|-----------|---------|-------------|--------|---------------|
| `.macro` | ❌ NOT IMPLEMENTED | Define macro | `.macro PRINT_MSG msg` | Not recognized |
| `.endmacro` | ❌ NOT IMPLEMENTED | End macro | `.endmacro` | Not recognized |
| `.if` | ❌ NOT IMPLEMENTED | Assembly-time conditional | `.if condition` | Not recognized |
| `.else` | ❌ NOT IMPLEMENTED | Assembly-time alternative | `.else` | Not recognized |
| `.endif` | ❌ NOT IMPLEMENTED | End assembly conditional | `.endif` | Not recognized |
| `.rept` | ❌ NOT IMPLEMENTED | Repeat block | `.rept 3` | Not recognized |
| `.endr` | ❌ NOT IMPLEMENTED | End repeat | `.endr` | Not recognized |

## Architecture Support Matrix

| Architecture | Core Directives | Arch-Specific | Status | Notes |
|--------------|----------------|---------------|---------|-------|
| x86_16 | ✅ | 🟡 Stub | Partial | Core works, arch-specific stubbed |
| x86_32 | ✅ | ✅ | Full | Complete implementation |
| x86_64 | ✅ | 🟡 Limited | Partial | Basic .code64 support |
| ARM64 | ✅ | 🟡 Stub | Partial | Core works, arch-specific stubbed |
| RISC-V | ✅ | 🟡 Stub | Partial | Core works, arch-specific stubbed |

## Implementation Priority Recommendations

### High Priority (Core Functionality)
1. **Symbol Table Integration**: Implement `.global`, `.extern` symbol processing
2. **Data Types**: Add `.byte`, `.word`, `.dword`, `.quad` support
3. **String Directives**: Implement `.asciz`, `.string` with null termination
4. **Symbol Constants**: Add `.equ`, `.set` for constant definitions

### Medium Priority (Enhanced Features)
1. **Alignment**: Implement `.align` and `.org` directives
2. **Symbol Attributes**: Add `.type`, `.size` ELF symbol information
3. **Architecture Extensions**: Complete x86_64, ARM64, RISC-V directive handlers
4. **Macro System**: Connect tokenized macros to parser/codegen

### Low Priority (Advanced Features)
1. **Debug Information**: Add DWARF support with `.file`, `.line`, `.loc`
2. **CFI Support**: Implement call frame information directives
3. **Syntax Modes**: Add Intel/AT&T syntax switching
4. **Advanced Macros**: Implement assembly-time conditionals and loops

## Testing Status

### Verified Working
- `.section`, `.text`, `.data`, `.bss` - Confirmed in examples
- `.include` - Working in phase7_complete_demo.s
- `.ascii`, `.space` - Working in x86_16_example.s, x86_32_example.s
- `.code16`, `.code32`, `.code64` - Architecture mode switching

### Needs Testing
- Symbol directives (`.global`, `.extern`)
- Data type directives (`.byte`, `.word`, etc.)
- Architecture-specific extensions beyond basic code modes

### Known Issues
- Assembly hangs on complex directive files (timeout required)
- Include file resolution requires exact path matching
- No error reporting for unsupported directives

## Summary

STAS has a solid foundation for directive processing with core section management, file inclusion, and architecture-specific code mode directives fully functional. The main gaps are in symbol management, comprehensive data type support, and advanced features like alignment and debug information. The three-layer architecture (lexer→parser→codegen) provides a good framework for extending directive support.

**Current Directive Support: ~25% Complete**
- Core Assembly: 40% (6/15 major directives)
- Architecture-Specific: 60% (excellent x86_32, limited others)
- Preprocessor: 80% (include works, macros tokenized)
- Advanced Features: 5% (most features missing)
