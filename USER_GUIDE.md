# STAS User Guide

**STAS (STIX Modular Assembler)** - Comprehensive User Guide

Version: 0.7.0 (Phase 7 Complete - Advanced Language Features)

---

## Table of Contents

1. [Command Line Interface](#command-line-interface)
2. [Advanced Language Features](#advanced-language-features) **NEW**
3. [Architecture Support](#architecture-support)
4. [Mnemonic Reference](#mnemonic-reference)
5. [Output Format Details](#output-format-details)
6. [Syntax Examples](#syntax-examples)
7. [Advanced Usage](#advanced-usage)
8. [Testing and Validation](#testing-and-validation) **NEW**
9. [Error Handling](#error-handling)

---

## Command Line Interface

### Basic Syntax
```bash
stas [options] input.s
```

### Command Line Options

| Option | Long Form | Description | Example |
|--------|-----------|-------------|---------|
| `-a` | `--arch=ARCH` | Target architecture | `-a x86_64` |
| `-o` | `--output=FILE` | Output file name | `-o program.bin` |
| `-f` | `--format=FORMAT` | Output format | `-f elf64` |
| `-b` | `--base=ADDR` | Base address (hex) | `-b 0x1000` |
| `-v` | `--verbose` | Verbose output | `-v` |
| `-d` | `--debug` | Debug mode | `-d` |
| `-l` | `--list-archs` | List architectures | `-l` |
| `-h` | `--help` | Show help | `-h` |

### Architecture Selection

| Architecture | ID | Description |
|-------------|-------|-------------|
| **x86_16** | `x86_16` | Intel 8086/80286 16-bit |
| **x86_32** | `x86_32` | Intel 80386+ 32-bit (IA-32) |
| **x86_64** | `x86_64` | Intel/AMD 64-bit |
| **ARM64** | `arm64` | ARM 64-bit (AArch64) |
| **RISC-V** | `riscv` | RISC-V 64-bit |

### Output Formats

| Format | ID | Description | Compatible Architectures |
|--------|-------|-------------|-------------------------|
| **Flat Binary** | `bin` | Raw machine code (default) | All |
| **DOS .COM** | `com` | MS-DOS executable | x86_16 only |
| **ELF32** | `elf32` | 32-bit ELF object file | x86_32, arm64 |
| **ELF64** | `elf64` | 64-bit ELF object file | x86_64, arm64 |
| **Intel HEX** | `hex` | Embedded programming format | All |
| **Motorola S-Record** | `srec` | Microcontroller programming | All |

---

## Advanced Language Features

STAS Phase 7 introduces comprehensive advanced language features including macro processing, file inclusion, conditional assembly, and complex expression evaluation.

### Macro Processing

Define and use C-style macros with `#define`:

```assembly
# Simple value macros
#define BUFFER_SIZE 1024
#define MAX_USERS 100
#define SUCCESS 0

# Use macros in code
movq $BUFFER_SIZE, %rax     # Expands to: movq $1024, %rax
movq $MAX_USERS, %rbx       # Expands to: movq $100, %rbx
movq $SUCCESS, %rcx         # Expands to: movq $0, %rcx

# Macros in data sections
.section .data
buffer_size: .quad BUFFER_SIZE    # Expands to: .quad 1024
```

#### Macro Features:
- **Numeric Values**: Decimal and hexadecimal constants
- **String Replacement**: Exact text substitution
- **Redefinition**: Later definitions override earlier ones
- **Case Sensitive**: Macro names are case-sensitive

### Include Directives

Include external files using `.include`:

```assembly
# Include common definitions
.include "constants.inc"
.include "macros.inc"

# Use included content
movq $COMMON_BUFFER_SIZE, %rax    # From constants.inc
```

#### Include Features:
- **Path Resolution**: Supports relative paths
- **Recursive Inclusion**: Included files can include other files
- **Error Prevention**: Circular inclusion detection
- **Content Integration**: Macros and labels from included files are available

### Conditional Assembly

Use preprocessor conditionals to include/exclude code:

```assembly
#define DEBUG_BUILD
#define OPTIMIZATION_LEVEL 2

# Basic conditional inclusion
#ifdef DEBUG_BUILD
    movq $1, %rax           # Only included if DEBUG_BUILD is defined
    call debug_function
#endif

# Conditional with alternative
#ifdef RELEASE_BUILD
    movq $0, %rbx           # Release build code
#else
    movq $1, %rbx           # Debug build code
#endif

# Negative conditional
#ifndef PRODUCTION
    call development_init    # Only in non-production builds
#endif

# Nested conditionals
#ifdef DEBUG_BUILD
    #ifdef ARM_TARGET
        call arm_debug_init
    #endif
#endif
```

#### Conditional Features:
- **`#ifdef MACRO`**: Include if macro is defined
- **`#ifndef MACRO`**: Include if macro is NOT defined  
- **`#else`**: Alternative code path
- **`#endif`**: End conditional block
- **Nesting Support**: Conditionals can be nested arbitrarily deep

### Advanced Expressions

Complex expressions in immediate values and operands:

```assembly
#define BASE_ADDR 0x1000
#define OFFSET 0x100
#define MULTIPLIER 4

# Arithmetic expressions
movq $(BASE_ADDR + OFFSET), %rax        # 0x1000 + 0x100 = 0x1100
movq $(BASE_ADDR - OFFSET), %rbx        # 0x1000 - 0x100 = 0xF00
movq $(OFFSET * MULTIPLIER), %rcx       # 0x100 * 4 = 0x400

# Complex expressions with precedence
movq $(BASE_ADDR + OFFSET * MULTIPLIER), %rdx   # 0x1000 + (0x100 * 4) = 0x1400

# Parentheses for precedence override
movq $((BASE_ADDR + OFFSET) * 2), %rsi          # (0x1000 + 0x100) * 2 = 0x2200

# Bitwise operations
movq $(BASE_ADDR | OFFSET), %rdi        # Bitwise OR
movq $(BASE_ADDR & 0xF000), %r8         # Bitwise AND

# Expressions in data declarations
.section .data
calculated_value: .quad (BASE_ADDR + OFFSET * MULTIPLIER)
```

#### Expression Features:
- **Arithmetic**: `+`, `-`, `*`, `/`
- **Bitwise**: `|` (OR), `&` (AND), `^` (XOR)
- **Shift**: `<<` (left), `>>` (right)
- **Precedence**: Standard operator precedence
- **Parentheses**: Explicit precedence control
- **Mixed Values**: Combine macros, constants, and expressions

### Combined Example

Complete example using all Phase 7 features:

```assembly
# Include common definitions
.include "system_config.inc"

# Build configuration
#define FEATURE_DEBUGGING
#define BUFFER_COUNT 8

# Advanced macro with expression
#define TOTAL_BUFFER_SIZE (BUFFER_SIZE * BUFFER_COUNT)

.section .text
.global _start

_start:
    # Use included constants with expressions
    movq $(SYSTEM_BASE + CONFIG_OFFSET), %rax
    
    # Conditional compilation
    #ifdef FEATURE_DEBUGGING
        movq $DEBUG_MODE, %rbx
        call debug_init
    #else
        movq $RELEASE_MODE, %rbx
    #endif
    
    # Complex expression using multiple macros
    movq $TOTAL_BUFFER_SIZE, %rcx
    
    # Conditional data based on architecture
    #ifdef X86_64_TARGET
        movq $64, %rdx          # 64-bit specific value
    #endif
    
    ret

.section .data
    #ifdef FEATURE_DEBUGGING
    debug_buffer: .space TOTAL_BUFFER_SIZE
    #endif
    
    system_config: .quad (SYSTEM_BASE | CONFIG_FLAGS)
```

---

## Architecture Support

### x86_16 (16-bit Intel 8086/80286)

**Syntax**: AT&T syntax with 16-bit registers  
**Directive**: `.code16`

#### Supported Instructions
- **Data Movement**: `mov`, `movw`
- **Arithmetic**: `add`, `sub`, `inc`, `dec`
- **Stack Operations**: `push`, `pop`
- **Control Flow**: `jmp`, `call`, `ret`
- **Comparison**: `cmp`, `test`
- **Conditional Jumps**: `je`, `jne`, `jl`, `jg`, etc.

#### Register Set
| 16-bit | 8-bit High | 8-bit Low | Purpose |
|--------|------------|-----------|---------|
| `%ax` | `%ah` | `%al` | Accumulator |
| `%bx` | `%bh` | `%bl` | Base |
| `%cx` | `%ch` | `%cl` | Counter |
| `%dx` | `%dh` | `%dl` | Data |
| `%si` | - | - | Source Index |
| `%di` | - | - | Destination Index |
| `%bp` | - | - | Base Pointer |
| `%sp` | - | - | Stack Pointer |

### x86_32 (32-bit Intel 80386+)

**Syntax**: AT&T syntax with 32-bit registers  
**Directive**: `.code32`

#### Supported Instructions
- **Data Movement**: `movl`, `mov`
- **Arithmetic**: `addl`, `subl`, `incl`, `decl`
- **Stack Operations**: `pushl`, `popl`
- **Control Flow**: `jmp`, `call`, `ret`
- **Comparison**: `cmpl`, `testl`
- **Conditional Jumps**: `je`, `jne`, `jl`, `jg`, etc.

#### Register Set
| 32-bit | 16-bit | 8-bit High | 8-bit Low |
|--------|--------|------------|-----------|
| `%eax` | `%ax` | `%ah` | `%al` |
| `%ebx` | `%bx` | `%bh` | `%bl` |
| `%ecx` | `%cx` | `%ch` | `%cl` |
| `%edx` | `%dx` | `%dh` | `%dl` |
| `%esi` | `%si` | - | - |
| `%edi` | `%di` | - | - |
| `%ebp` | `%bp` | - | - |
| `%esp` | `%sp` | - | - |

### x86_64 (64-bit Intel/AMD)

**Syntax**: AT&T syntax with 64-bit registers  
**Directive**: `.code64`

#### Supported Instructions
- **Data Movement**: `movq`, `mov`
- **Arithmetic**: `addq`, `subq`, `incq`, `decq`
- **Stack Operations**: `pushq`, `popq`
- **Control Flow**: `jmp`, `call`, `ret`
- **System**: `syscall`, `nop`
- **Comparison**: `cmpq`, `testq`

#### Register Set
| 64-bit | 32-bit | 16-bit | 8-bit |
|--------|--------|--------|--------|
| `%rax` | `%eax` | `%ax` | `%al` |
| `%rbx` | `%ebx` | `%bx` | `%bl` |
| `%rcx` | `%ecx` | `%cx` | `%cl` |
| `%rdx` | `%edx` | `%dx` | `%dl` |
| `%rsi` | `%esi` | `%si` | `%sil` |
| `%rdi` | `%edi` | `%di` | `%dil` |
| `%rbp` | `%ebp` | `%bp` | `%bpl` |
| `%rsp` | `%esp` | `%sp` | `%spl` |
| `%r8` | `%r8d` | `%r8w` | `%r8b` |
| `%r9` | `%r9d` | `%r9w` | `%r9b` |
| `%r10` | `%r10d` | `%r10w` | `%r10b` |
| `%r11` | `%r11d` | `%r11w` | `%r11b` |
| `%r12` | `%r12d` | `%r12w` | `%r12b` |
| `%r13` | `%r13d` | `%r13w` | `%r13b` |
| `%r14` | `%r14d` | `%r14w` | `%r14b` |
| `%r15` | `%r15d` | `%r15w` | `%r15b` |

### ARM64 (AArch64)

**Syntax**: ARM64 assembly syntax  
**No directive needed**

#### Supported Instructions
- **Data Movement**: `mov`, `movz`, `movk`, `movn`
- **Arithmetic**: `add`, `sub`, `mul`
- **Logical**: `and`, `orr`, `eor`
- **Comparison**: `cmp`, `cmn`
- **Memory**: `ldr`, `str`, `ldp`, `stp`
- **Control Flow**: `b`, `bl`, `br`, `blr`, `ret`
- **Conditional**: `b.eq`, `b.ne`, `b.lt`, `b.gt`, etc.

#### Register Set
| Type | Registers | Description |
|------|-----------|-------------|
| **General Purpose (64-bit)** | `x0`-`x30` | General registers |
| **General Purpose (32-bit)** | `w0`-`w30` | 32-bit views of x registers |
| **Stack Pointer** | `sp` | Stack pointer |
| **Program Counter** | `pc` | Program counter |
| **Zero Register** | `xzr`/`wzr` | Always reads as zero |

### RISC-V (RV64I)

**Syntax**: RISC-V assembly syntax  
**No directive needed**

#### Supported Instructions
- **Arithmetic Immediate**: `addi`, `slti`, `sltiu`, `xori`, `ori`, `andi`
- **Shift Immediate**: `slli`, `srli`, `srai`
- **Register Arithmetic**: `add`, `sub`, `sll`, `slt`, `sltu`
- **Register Logical**: `xor`, `srl`, `sra`, `or`, `and`
- **Upper Immediate**: `lui`, `auipc`
- **Memory**: `lb`, `lh`, `lw`, `ld`, `lbu`, `lhu`, `lwu`
- **Store**: `sb`, `sh`, `sw`, `sd`
- **Branches**: `beq`, `bne`, `blt`, `bge`, `bltu`, `bgeu`
- **Jump**: `jal`, `jalr`
- **System**: `ecall`, `ebreak`

#### Register Set
| Register | ABI Name | Description |
|----------|----------|-------------|
| `x0` | `zero` | Hard-wired zero |
| `x1` | `ra` | Return address |
| `x2` | `sp` | Stack pointer |
| `x3` | `gp` | Global pointer |
| `x4` | `tp` | Thread pointer |
| `x5-x7` | `t0-t2` | Temporaries |
| `x8` | `s0/fp` | Saved register/frame pointer |
| `x9` | `s1` | Saved register |
| `x10-x11` | `a0-a1` | Function arguments/return values |
| `x12-x17` | `a2-a7` | Function arguments |
| `x18-x27` | `s2-s11` | Saved registers |
| `x28-x31` | `t3-t6` | Temporaries |

---

## Mnemonic Reference

### Cross-Architecture Mnemonic Comparison

| Operation | x86_16 | x86_32 | x86_64 | ARM64 | RISC-V |
|-----------|--------|--------|--------|-------|--------|
| **Move Register** | `mov %ax, %bx` | `movl %eax, %ebx` | `movq %rax, %rbx` | `mov x1, x0` | `add x1, x0, zero` |
| **Move Immediate** | `mov $10, %ax` | `movl $10, %eax` | `movq $10, %rax` | `mov x0, #10` | `addi x0, zero, 10` |
| **Add Registers** | `add %ax, %bx` | `addl %eax, %ebx` | `addq %rax, %rbx` | `add x2, x0, x1` | `add x2, x0, x1` |
| **Add Immediate** | `add $5, %ax` | `addl $5, %eax` | `addq $5, %rax` | `add x0, x0, #5` | `addi x0, x0, 5` |
| **Subtract** | `sub %ax, %bx` | `subl %eax, %ebx` | `subq %rax, %rbx` | `sub x2, x1, x0` | `sub x2, x1, x0` |
| **Compare** | `cmp %ax, %bx` | `cmpl %eax, %ebx` | `cmpq %rax, %rbx` | `cmp x0, x1` | `sub x0, x0, x1` (discard) |
| **Jump** | `jmp label` | `jmp label` | `jmp label` | `b label` | `jal zero, label` |
| **Call Function** | `call func` | `call func` | `call func` | `bl func` | `jal ra, func` |
| **Return** | `ret` | `ret` | `ret` | `ret` | `jalr zero, ra, 0` |
| **Push** | `push %ax` | `pushl %eax` | `pushq %rax` | `str x0, [sp, #-16]!` | `addi sp, sp, -8; sd x0, 0(sp)` |
| **Pop** | `pop %ax` | `popl %eax` | `popq %rax` | `ldr x0, [sp], #16` | `ld x0, 0(sp); addi sp, sp, 8` |

### Immediate Value Syntax

| Architecture | Syntax | Example |
|-------------|---------|---------|
| **x86 Family** | `$value` | `$42`, `$0x1000`, `$0b1010` |
| **ARM64** | `#value` | `#42`, `#0x1000` |
| **RISC-V** | `value` | `42`, `0x1000` |

### Register Syntax

| Architecture | Prefix | Example |
|-------------|---------|---------|
| **x86 Family** | `%` | `%rax`, `%ebx`, `%cl` |
| **ARM64** | None | `x0`, `w1`, `sp` |
| **RISC-V** | None | `x0`, `ra`, `sp` |

---

## Output Format Details

### 1. Flat Binary (`bin`)

**Purpose**: Raw machine code with no headers or metadata  
**Use Cases**: Bootloaders, embedded systems, direct memory loading  
**Compatible**: All architectures

**Features**:
- No file headers or metadata
- Pure machine code bytes
- Configurable base address with `-b` option
- Default base address: 0x0000

**Example**:
```bash
stas -a x86_64 -f bin -o program.bin input.s
stas -a arm64 -f bin -b 0x8000 -o boot.bin boot.s
```

### 2. DOS .COM Format (`com`)

**Purpose**: MS-DOS executable format  
**Use Cases**: DOS programs, retro computing  
**Compatible**: x86_16 only

**Features**:
- 64KB size limit
- Loads at 0x0100 in DOS memory model
- Direct execution on DOS systems
- No relocation information

**Example**:
```bash
stas -a x86_16 -f com -o hello.com hello16.s
```

### 3. ELF32 Format (`elf32`)

**Purpose**: 32-bit Executable and Linkable Format  
**Use Cases**: Linux object files, relocatable code  
**Compatible**: x86_32, arm64

**Features**:
- Standard Unix/Linux object format
- Symbol tables and relocation information
- Compatible with system linkers (`ld`)
- Debugger-friendly with section information

**Example**:
```bash
stas -a x86_32 -f elf32 -o program.o input.s
ld program.o -o executable
```

### 4. ELF64 Format (`elf64`)

**Purpose**: 64-bit Executable and Linkable Format  
**Use Cases**: Modern Linux systems, 64-bit applications  
**Compatible**: x86_64, arm64

**Features**:
- 64-bit addressing support
- Modern system compatibility
- Full debugging information
- Professional development workflow

**Example**:
```bash
stas -a x86_64 -f elf64 -o program.o input.s
ld program.o -o executable
```

### 5. Intel HEX Format (`hex`)

**Purpose**: Embedded programming and ROM programming  
**Use Cases**: Microcontrollers, EEPROM programming, embedded development  
**Compatible**: All architectures

**Features**:
- ASCII text format for safe transmission
- Built-in checksum validation
- Extended addressing for programs > 64KB
- Industry standard for embedded systems

**Record Types**:
- `:LLAAAATT[DD...]CC` format
- `00`: Data records (16-byte chunks)
- `01`: End of File record
- `04`: Extended Linear Address (upper 16 bits)

**Example**:
```bash
stas -a arm64 -f hex -o firmware.hex embedded.s
# Output: :10000000B8010000008BC3C300000000000000001C
#         :00000001FF
```

### 6. Motorola S-Record Format (`srec`)

**Purpose**: Microcontroller programming and embedded systems  
**Use Cases**: Motorola/Freescale MCUs, automotive, industrial  
**Compatible**: All architectures

**Features**:
- ASCII format with multiple address sizes
- Header records with identification
- Automatic S1/S2/S3 selection based on address range
- Termination records for validation

**Record Types**:
- `S0`: Header record with identifier
- `S1`: Data with 16-bit addresses (≤ 64KB)
- `S2`: Data with 24-bit addresses (≤ 16MB) 
- `S3`: Data with 32-bit addresses (full range)
- `S7/S8/S9`: Termination records

**Example**:
```bash
stas -a riscv -f srec -o program.srec input.s
# Output: S007000053544153BD
#         S10900060C6382550500A5
```

---

## Syntax Examples

### x86_16 Example
```gas
# DOS Hello World (x86_16)
.code16

start:
    mov $0x0900, %ax     # DOS write string function
    mov $hello, %dx      # String address
    int $0x21            # DOS interrupt
    
    mov $0x4C00, %ax     # DOS exit function
    int $0x21            # DOS interrupt

hello:
    .ascii "Hello, World!$"
```

### x86_32 Example
```gas
# Linux system call (x86_32)
.code32

_start:
    movl $4, %eax        # sys_write
    movl $1, %ebx        # stdout
    movl $msg, %ecx      # message
    movl $13, %edx       # length
    int $0x80            # system call
    
    movl $1, %eax        # sys_exit
    movl $0, %ebx        # exit status
    int $0x80            # system call

msg:
    .ascii "Hello, World!"
```

### x86_64 Example
```gas
# Linux system call (x86_64)
.code64

_start:
    movq $1, %rax        # sys_write
    movq $1, %rdi        # stdout
    movq $msg, %rsi      # message
    movq $13, %rdx       # length
    syscall              # system call
    
    movq $60, %rax       # sys_exit
    movq $0, %rdi        # exit status
    syscall              # system call

msg:
    .ascii "Hello, World!"
```

### ARM64 Example
```gas
# ARM64 basic arithmetic
_start:
    mov x0, #10          # Load immediate 10
    mov x1, #5           # Load immediate 5
    add x2, x0, x1       # x2 = x0 + x1 = 15
    sub x3, x0, x1       # x3 = x0 - x1 = 5
    
    # System call exit
    mov x0, #0           # exit status
    mov x8, #93          # sys_exit
    svc #0               # system call
```

### RISC-V Example
```gas
# RISC-V basic operations
_start:
    addi x1, x0, 10      # x1 = 0 + 10
    addi x2, x0, 5       # x2 = 0 + 5
    add x3, x1, x2       # x3 = x1 + x2
    sub x4, x1, x2       # x4 = x1 - x2
    
    # Load upper immediate
    lui x5, 0x10000      # x5 = 0x10000000
    
    # System call exit
    addi x10, x0, 0      # exit status
    addi x17, x0, 93     # sys_exit
    ecall                # system call
```

---

## Advanced Usage

### Base Address Configuration

For embedded systems, you can specify a custom base address:

```bash
# ARM Cortex-M4 typical flash address
stas -a arm64 -f hex -b 0x08000000 -o firmware.hex app.s

# x86 bootloader
stas -a x86_16 -f bin -b 0x7C00 -o bootloader.bin boot.s
```

### Verbose Output

Use `-v` for detailed assembly information:

```bash
stas -a x86_64 -f elf64 -o test.o -v test.s
```

Output includes:
- Architecture loading information
- Instruction encoding details
- Section information
- Code generation statistics

### Debug Mode

Use `-d` for troubleshooting:

```bash
stas -a riscv -f bin -o debug.bin -d -v program.s
```

Debug output includes:
- Token parsing details
- AST construction information
- Symbol resolution steps
- Error context

### Multi-Format Builds

Generate multiple output formats from the same source:

```bash
# Generate all formats for x86_64
stas -a x86_64 -f bin -o program.bin program.s
stas -a x86_64 -f elf64 -o program.o program.s
stas -a x86_64 -f hex -o program.hex program.s
stas -a x86_64 -f srec -o program.srec program.s
```

---

## Error Handling

### Common Errors and Solutions

#### Parse Errors
```
Error: Unexpected token in operand: NUMBER
```
**Solution**: Check immediate value syntax ($ for x86, # for ARM64)

#### Architecture Errors
```
Error: Failed to encode instruction 'addl'
```
**Solution**: Verify instruction is supported on target architecture

#### Format Compatibility
```
Error: COM format only supports x86_16 architecture
```
**Solution**: Use compatible architecture or different format

#### Missing Input
```
Error: No input file specified
```
**Solution**: Provide assembly source file as argument

### Best Practices

1. **Always specify architecture**: Use `-a` flag explicitly
2. **Use verbose mode**: Add `-v` when debugging
3. **Check format compatibility**: Verify architecture supports chosen format
4. **Validate syntax**: Each architecture has specific syntax requirements
5. **Test with simple examples**: Start with basic instructions before complex programs

---

## Integration Examples

### Makefile Integration
```makefile
# Multi-architecture build
AS = stas
ASFLAGS = -v

x86_64_program: program_x86_64.s
	$(AS) -a x86_64 -f elf64 -o $@ $<

arm64_program: program_arm64.s
	$(AS) -a arm64 -f elf64 -o $@ $<

embedded.hex: embedded.s
	$(AS) -a arm64 -f hex -b 0x08000000 -o $@ $<
```

### Development Workflow
```bash
# 1. Write assembly source
vim program.s

# 2. Assemble with verbose output
stas -a x86_64 -f elf64 -o program.o -v program.s

# 3. Link with system linker
ld program.o -o program

# 4. Test execution
./program
```

---

## Testing and Validation

STAS includes comprehensive testing frameworks to validate both the assembler functionality and the generated machine code.

### Unit Testing Framework

Run comprehensive unit tests using the Unity testing framework:

```bash
# Run all format unit tests (117 tests across 5 formats)
make test-unit-formats

# Results: 
# ELF Format: 29/29 tests passing ✅
# Flat Binary: 20/20 tests passing ✅
# Intel HEX: 21/21 tests passing ✅
# COM Format: 23/23 tests passing ✅
# Motorola S-Record: 24/24 tests passing ✅
```

### CPU Execution Testing

Validate generated machine code using Unicorn Engine CPU emulation:

```bash
# Install Unicorn Engine (required for execution testing)
sudo apt-get install libunicorn-dev

# Run architecture-specific execution tests
make test-execution-x86_16    # 16-bit real mode testing
make test-execution-x86_32    # 32-bit + boot sequence simulation  
make test-execution-x86_64    # 64-bit instruction validation
make test-execution-arm64     # ARM64 cross-platform testing
make test-execution-riscv     # RISC-V alternative architecture

# Run all execution tests
make test-execution-all
```

### Advanced Boot Sequence Testing

Test complete i386 PC boot simulation (real mode → protected mode):

```bash
# Run advanced x86_32 boot sequence test
./testbin/execution_test_x86_32_real_to_protected

# This test demonstrates:
# 1. Real mode operations (16-bit segmented addressing)
# 2. Global Descriptor Table (GDT) setup
# 3. Protected mode transition (CR0.PE bit manipulation)
# 4. Memory model validation (segmented vs flat)
# 5. Interrupt vector table configuration
```

### Test Integration

Run complete test suite covering all components:

```bash
# Run everything: unit tests + execution tests + integration
make test-all

# Individual test categories
make test              # Basic functionality tests
make test-unit-all     # All Unity-based unit tests
make test-execution-all # All Unicorn-based execution tests
make test-phase7       # Advanced language feature tests
```

### Testing Output Example

```
=== Format Unit Testing Results ===
ELF Format Tests:           29 tests, 0 failures ✅
Flat Binary Format Tests:  20 tests, 0 failures ✅  
Intel HEX Format Tests:     21 tests, 0 failures ✅
COM Format Tests:           23 tests, 0 failures ✅
Motorola S-Record Tests:    24 tests, 0 failures ✅
TOTAL:                     117 tests, 0 failures ✅

=== CPU Execution Testing Results ===
x86_16 Basic Tests:         8 tests, 0 failures ✅
x86_32 Comprehensive:      14 tests, 0 failures ✅
x86_64 Basic Tests:        10 tests, 0 failures ✅
Boot Sequence Simulation:   4 tests, 0 failures ✅
```

---

**For more information, see:**
- [Project Status](PROJECT_STATUS.md) - Technical implementation details
- [Architecture Design](ARCHITECTURE.md) - Internal design documentation
- [Testing Strategy](TESTING_STRATEGY.md) - Comprehensive testing framework documentation
- [Unicorn Installation](UNICORN_INSTALLATION.md) - CPU emulation testing setup
- [Examples Directory](examples/) - Sample assembly programs for each architecture
