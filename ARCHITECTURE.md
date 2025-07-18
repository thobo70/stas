# STAS - STIX Modular Assembler Architecture

## Overview

STAS (STIX Assembler) is a modular, multi-architecture assembler designed to support various CPU architectures while maintaining a consistent AT&T syntax style. The assembler follows a plugin-based architecture that allows easy extension for new target architectures.

## Design Principles

1. **Modularity**: Each CPU architecture is implemented as a separate module
2. **Extensibility**: New architectures can be added without modifying core code
3. **AT&T Syntax**: Consistent AT&T-style assembly syntax across all architectures
4. **Performance**: Efficient parsing and code generation
5. **Standards Compliance**: Follows established assembly language conventions

## Architecture Overview

```
┌─────────────────────────────────────────────────────────────┐
│                     STAS Frontend                           │
├─────────────────────────────────────────────────────────────┤
│  Command Line Interface │ Configuration │ Error Reporting   │
└─────────────────────────────────────────────────────────────┘
                                │
┌─────────────────────────────────────────────────────────────┐
│                      Core Engine                            │
├─────────────────────────────────────────────────────────────┤
│  Lexer │ Parser │ Symbol Table │ Expression Evaluator      │
└─────────────────────────────────────────────────────────────┘
                                │
┌─────────────────────────────────────────────────────────────┐
│                  Architecture Interface                     │
├─────────────────────────────────────────────────────────────┤
│  Instruction Set │ Register Map │ Addressing Modes │ ABI    │
└─────────────────────────────────────────────────────────────┘
                                │
┌─────────────────────────────────────────────────────────────┐
│                 Architecture Modules                        │
├─────────────┬─────────────┬─────────────┬─────────────────────┤
│ x86-16 Mod. │ x86-32 Mod. │ x86-64 Mod. │ ARM64/RISC-V...     │
│             │             │             │                     │
│ • 8086/286  │ • 386+ IA32 │ • AMD64     │ • Instructions      │
│ • 16-bit    │ • 32-bit    │ • 64-bit    │ • Registers         │
│ • Segmented │ • Protected │ • Long Mode │ • Encoding          │
│ • Real Mode │ • Flat Mem  │ • Paging    │ • Validation        │
└─────────────┴─────────────┴─────────────┴─────────────────────┘
                                │
┌─────────────────────────────────────────────────────────────┐
│                   Output Generator                          │
├─────────────────────────────────────────────────────────────┤
│  Object Files │ Relocations │ Debug Info │ Listing Files   │
└─────────────────────────────────────────────────────────────┘
```

## Core Components

### 1. Frontend Layer

#### Command Line Interface
- Target architecture selection (`--arch=x86_64`, `--arch=arm64`, etc.)
- Input/output file handling
- Assembly options and flags
- Verbose and debug modes

#### Configuration System
- Architecture-specific configuration files
- User preferences and defaults
- Build-time feature selection

### 2. Core Engine

#### Lexical Analyzer (Lexer)
```c
typedef enum {
    TOKEN_INSTRUCTION,
    TOKEN_REGISTER,
    TOKEN_IMMEDIATE,
    TOKEN_LABEL,
    TOKEN_DIRECTIVE,
    TOKEN_SYMBOL,
    TOKEN_OPERATOR,
    TOKEN_NEWLINE,
    TOKEN_EOF
} token_type_t;

typedef struct {
    token_type_t type;
    char *value;
    size_t line;
    size_t column;
} token_t;
```

#### Parser
- AT&T syntax parser with architecture-agnostic design
- Handles common assembly constructs (labels, directives, expressions)
- Builds Abstract Syntax Tree (AST) for architecture modules

#### Symbol Table
```c
typedef enum {
    SYMBOL_LABEL,
    SYMBOL_CONSTANT,
    SYMBOL_EXTERNAL,
    SYMBOL_SECTION
} symbol_type_t;

typedef struct symbol {
    char *name;
    symbol_type_t type;
    uint64_t value;
    uint32_t section;
    struct symbol *next;
} symbol_t;
```

#### Expression Evaluator
- Handles arithmetic expressions in operands
- Supports forward references
- Manages relocations for external symbols

### 3. Architecture Interface

#### Abstract Architecture API
```c
typedef struct arch_ops {
    const char *name;
    
    // Architecture initialization
    int (*init)(void);
    void (*cleanup)(void);
    
    // Instruction processing
    int (*parse_instruction)(const char *mnemonic, operand_t *operands, 
                           instruction_t *inst);
    int (*encode_instruction)(instruction_t *inst, uint8_t *buffer, 
                            size_t *length);
    
    // Register handling
    int (*parse_register)(const char *reg_name, register_t *reg);
    bool (*is_valid_register)(register_t reg);
    
    // Addressing modes
    int (*parse_addressing)(const char *addr_str, addressing_mode_t *mode);
    bool (*validate_addressing)(addressing_mode_t *mode, instruction_t *inst);
    
    // Architecture-specific directives
    int (*handle_directive)(const char *directive, const char *args);
    
    // Size and alignment information
    size_t (*get_instruction_size)(instruction_t *inst);
    size_t (*get_alignment)(section_type_t section);
} arch_ops_t;
```

### 4. Architecture Modules

#### x86-16 Module
```c
// x86-16 specific structures
typedef enum {
    X86_16_REG_AX, X86_16_REG_BX, X86_16_REG_CX, X86_16_REG_DX,
    X86_16_REG_SI, X86_16_REG_DI, X86_16_REG_BP, X86_16_REG_SP,
    X86_16_REG_AL, X86_16_REG_BL, X86_16_REG_CL, X86_16_REG_DL,
    X86_16_REG_AH, X86_16_REG_BH, X86_16_REG_CH, X86_16_REG_DH,
    X86_16_REG_CS, X86_16_REG_DS, X86_16_REG_ES, X86_16_REG_SS,
    // ... more registers
} x86_16_register_t;

typedef enum {
    X86_16_ADDR_REGISTER,    // %ax
    X86_16_ADDR_IMMEDIATE,   // $0x1234
    X86_16_ADDR_DIRECT,      // 0x1234
    X86_16_ADDR_INDIRECT,    // (%bx)
    X86_16_ADDR_INDEXED,     // 4(%bx,%si)
    X86_16_ADDR_SEGMENT      // %ds:0x1234
} x86_16_addressing_mode_t;
```

#### x86-32 Module
```c
typedef enum {
    X86_32_REG_EAX, X86_32_REG_EBX, X86_32_REG_ECX, X86_32_REG_EDX,
    X86_32_REG_ESI, X86_32_REG_EDI, X86_32_REG_EBP, X86_32_REG_ESP,
    X86_32_REG_AX,  X86_32_REG_BX,  X86_32_REG_CX,  X86_32_REG_DX,
    // ... MMX and SSE registers
    X86_32_REG_MM0, X86_32_REG_MM1, X86_32_REG_MM2, X86_32_REG_MM3,
    X86_32_REG_XMM0, X86_32_REG_XMM1, X86_32_REG_XMM2, X86_32_REG_XMM3,
} x86_32_register_t;
```

#### x86-64 Module
```c
// x86-64 specific structures
typedef enum {
    X86_REG_RAX, X86_REG_RBX, X86_REG_RCX, X86_REG_RDX,
    X86_REG_RSI, X86_REG_RDI, X86_REG_RSP, X86_REG_RBP,
    X86_REG_R8,  X86_REG_R9,  X86_REG_R10, X86_REG_R11,
    X86_REG_R12, X86_REG_R13, X86_REG_R14, X86_REG_R15,
    // ... more registers
} x86_register_t;

typedef enum {
    X86_ADDR_REGISTER,      // %rax
    X86_ADDR_IMMEDIATE,     // $0x1234
    X86_ADDR_DIRECT,        // 0x1234
    X86_ADDR_INDIRECT,      // (%rax)
    X86_ADDR_INDEXED,       // 8(%rax,%rbx,2)
    X86_ADDR_RIP_RELATIVE   // symbol(%rip)
} x86_addressing_mode_t;
```

#### ARM64 Module
```c
typedef enum {
    ARM64_REG_X0,  ARM64_REG_X1,  ARM64_REG_X2,  ARM64_REG_X3,
    ARM64_REG_X4,  ARM64_REG_X5,  ARM64_REG_X6,  ARM64_REG_X7,
    // ... more registers
    ARM64_REG_W0,  ARM64_REG_W1,  ARM64_REG_W2,  ARM64_REG_W3,
    // ... vector registers
    ARM64_REG_V0,  ARM64_REG_V1,  ARM64_REG_V2,  ARM64_REG_V3,
} arm64_register_t;
```

#### RISC-V Module
```c
typedef enum {
    RISCV_REG_X0,  RISCV_REG_RA,  RISCV_REG_SP,  RISCV_REG_GP,
    RISCV_REG_TP,  RISCV_REG_T0,  RISCV_REG_T1,  RISCV_REG_T2,
    // ... more registers
} riscv_register_t;
```

## AT&T Syntax Support

### Common Syntax Elements

1. **Register Prefixes**: All registers prefixed with `%`
   - x86-64: `%rax`, `%rbx`, `%rcx`
   - ARM64: `%x0`, `%x1`, `%w0`, `%w1`
   - RISC-V: `%x0`, `%ra`, `%sp`

2. **Immediate Values**: Prefixed with `$`
   - `$0x1234` (hexadecimal)
   - `$1234` (decimal)
   - `$symbol` (symbol reference)

3. **Memory Addressing**: Consistent across architectures
   - Direct: `symbol`
   - Indirect: `(%register)`
   - Indexed: `offset(%base,%index,scale)`

4. **Instruction Format**: `mnemonic source, destination`
   - `movq %rax, %rbx`
   - `addq $10, %rax`

### Architecture-Specific Adaptations

#### x86-16 AT&T Syntax
```assembly
.code16
.section .text
.global _start

_start:
    movw $0x1000, %ax      # Load immediate into 16-bit register
    movw %ax, %ds          # Set data segment
    movw $message, %si     # Load address into source index
    movb (%si), %al        # Load byte from memory
    
    # BIOS interrupt for character output
    movb $0x0E, %ah        # BIOS teletype function
    int $0x10              # BIOS video interrupt
    
    # Function call with 16-bit stack
    pushw %ax              # Push 16-bit value
    call my_function       # Call function
    popw %ax               # Pop 16-bit value

.section .data
message: .ascii "Hello, 16-bit!\0"
```

#### x86-32 AT&T Syntax
```assembly
.code32
.section .text
.global _start

_start:
    movl $message, %esi    # Load 32-bit address
    movl $msg_len, %ecx    # Load 32-bit immediate
    
    # Linux system call
    movl $4, %eax          # sys_write
    movl $1, %ebx          # stdout
    int $0x80              # System call interrupt
    
    # 32-bit addressing with SIB
    movl (%esi,%ebx,4), %eax  # Complex addressing mode
    
    # PUSHAD/POPAD for all registers
    pushad                 # Push all 32-bit registers
    call function
    popad                  # Pop all 32-bit registers

.section .data
message: .ascii "Hello, 32-bit!\n"
msg_len = . - message
```

#### x86-64 AT&T Style
```assembly
.section .text
.global _start

_start:
    movq $1, %rax          # 64-bit immediate
    movq $1, %rdi          # 64-bit register
    movq $message, %rsi    # 64-bit address
    movq $14, %rdx         # 64-bit length
    syscall                # 64-bit system call
    
    # RIP-relative addressing
    movq message(%rip), %rax  # Load relative to instruction pointer
    
    movq $60, %rax         # sys_exit
    movq $0, %rdi          # exit status
    syscall

.section .data
message: .ascii "Hello, 64-bit!\n"
```

#### ARM64 AT&T Style
```assembly
.section .text
.global _start

_start:
    movq $1, %x8           // sys_write
    movq $1, %x0           // stdout
    ldr  %x1, =message     // message address
    movq $14, %x2          // message length
    svc  $0                // system call
    
    movq $93, %x8          // sys_exit
    movq $0, %x0           // exit status
    svc  $0

.section .data
message: .ascii "Hello, World!\n"
```

## File Structure

```
src/
├── core/
│   ├── lexer.c/.h         # Lexical analysis
│   ├── parser.c/.h        # AT&T syntax parser
│   ├── symbols.c/.h       # Symbol table management
│   ├── expressions.c/.h   # Expression evaluation
│   └── output.c/.h        # Object file generation
├── arch/
│   ├── arch_interface.h   # Architecture abstraction
│   ├── x86_16/
│   │   ├── x86_16.c/.h    # x86-16 implementation
│   │   ├── instructions.c # Instruction encoding
│   │   ├── registers.c    # Register handling
│   │   └── addressing.c   # Addressing modes
│   ├── x86_32/
│   │   ├── x86_32.c/.h    # x86-32 implementation
│   │   ├── instructions.c # IA-32 instruction set
│   │   ├── registers.c    # 32-bit register handling
│   │   └── addressing.c   # SIB addressing modes
│   ├── x86_64/
│   │   ├── x86_64.c/.h    # x86-64 implementation
│   │   ├── instructions.c # 64-bit instruction encoding
│   │   ├── registers.c    # Register handling
│   │   └── addressing.c   # Addressing modes
│   ├── arm64/
│   │   ├── arm64.c/.h     # ARM64 implementation
│   │   ├── instructions.c
│   │   ├── registers.c
│   │   └── addressing.c
│   └── riscv/
│       ├── riscv.c/.h     # RISC-V implementation
│       ├── instructions.c
│       ├── registers.c
│       └── addressing.c
├── formats/
│   ├── elf.c/.h          # ELF object format
│   ├── mach_o.c/.h       # Mach-O object format
│   ├── pe.c/.h           # PE object format
│   └── coff.c/.h         # COFF object format (16/32-bit)
├── utils/
│   ├── error.c/.h        # Error reporting
│   ├── config.c/.h       # Configuration system
│   └── memory.c/.h       # Memory management
└── main.c                # Main entry point
```

## Plugin System

### Dynamic Loading
```c
typedef struct arch_plugin {
    void *handle;              // dlopen handle
    arch_ops_t *ops;          // Architecture operations
    char *name;               // Architecture name
    struct arch_plugin *next; // Linked list
} arch_plugin_t;

// Plugin loading
int load_architecture_plugin(const char *arch_name);
arch_ops_t *get_architecture(const char *name);
void unload_all_plugins(void);
```

### Plugin Registration
```c
// Each architecture module exports this function
__attribute__((visibility("default")))
arch_ops_t *get_arch_ops(void) {
    static arch_ops_t x86_64_ops = {
        .name = "x86_64",
        .init = x86_64_init,
        .cleanup = x86_64_cleanup,
        .parse_instruction = x86_64_parse_instruction,
        .encode_instruction = x86_64_encode_instruction,
        // ... other function pointers
    };
    return &x86_64_ops;
}
```

## Error Handling

### Error Reporting System
```c
typedef enum {
    ERROR_SYNTAX,
    ERROR_UNKNOWN_INSTRUCTION,
    ERROR_INVALID_REGISTER,
    ERROR_INVALID_OPERAND,
    ERROR_SYMBOL_UNDEFINED,
    ERROR_RELOCATION,
    ERROR_IO
} error_type_t;

typedef struct {
    error_type_t type;
    char *message;
    char *filename;
    size_t line;
    size_t column;
} error_t;

void report_error(error_type_t type, const char *format, ...);
void report_warning(const char *format, ...);
```

## Build System Integration

### Updated Makefile
The Makefile will be updated to support the modular architecture:

```makefile
# Architecture modules to build
ARCHS = x86_64 arm64 riscv

# Build architecture-specific object files
ARCH_OBJECTS = $(foreach arch,$(ARCHS),$(OBJ_DIR)/arch_$(arch).o)

# Plugin shared libraries
PLUGINS = $(foreach arch,$(ARCHS),$(BIN_DIR)/arch_$(arch).so)

# Main target now includes plugins
$(TARGET): $(OBJECTS) $(PLUGINS)
```

## Testing Strategy

### Unit Tests
- Individual architecture module testing
- Parser and lexer validation
- Symbol table operations
- Expression evaluation

### Integration Tests
- Cross-architecture assembly
- Object file generation
- Error handling verification

### Test Assembly Files
```
tests/
├── common/
│   ├── basic_syntax.s
│   ├── symbols.s
│   └── expressions.s
├── x86_64/
│   ├── instructions.s
│   ├── addressing.s
│   └── system_calls.s
├── arm64/
│   └── ... similar structure
└── riscv/
    └── ... similar structure
```

## Future Extensions

1. **Additional Architectures**: MIPS, PowerPC, SPARC, 68000
2. **x86 Variants**: 8080/Z80 compatibility mode, x86-64 with AVX-512
3. **Optimization Passes**: Peephole optimization, instruction scheduling
4. **Macro System**: Advanced macro processing capabilities
5. **Debugging Support**: DWARF debug information generation
6. **Linker Integration**: Direct object file linking capabilities
7. **Cross-Architecture**: Support for mixed-mode binaries

## Conclusion

This modular architecture provides a solid foundation for STAS, allowing it to support multiple CPU architectures while maintaining consistent AT&T syntax. The plugin-based design ensures extensibility, while the clean separation of concerns makes the codebase maintainable and testable.
