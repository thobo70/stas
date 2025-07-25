# STAS Quick Reference

## Command Line
```bash
stas -a <arch> -f <format> -o <output> [options] input.s
```

## Architectures
| ID | Description |
|----|-------------|
| `x86_16` | Intel 8086/80286 16-bit |
| `x86_32` | Intel 80386+ 32-bit |
| `x86_64` | Intel/AMD 64-bit |
| `arm64` | ARM 64-bit (AArch64) |
| `riscv` | RISC-V 64-bit |

## Output Formats
| ID | Description | Architectures |
|----|-------------|---------------|
| `bin` | Flat binary | All |
| `com` | DOS .COM | x86_16 only |
| `elf32` | ELF 32-bit | x86_32, arm64 |
| `elf64` | ELF 64-bit | x86_64, arm64 |
| `hex` | Intel HEX | All |
| `srec` | Motorola S-Record | All |

## Basic Instructions

### x86 Family
```gas
# x86_16
mov %ax, %bx          # 16-bit move
add $10, %ax          # Add immediate

# x86_32  
movl %eax, %ebx       # 32-bit move
addl $10, %eax        # Add immediate

# x86_64
movq %rax, %rbx       # 64-bit move
addq $10, %rax        # Add immediate
```

### ARM64
```gas
mov x0, #10           # Move immediate
add x2, x0, x1        # Add registers
ldr x0, [x1]          # Load from memory
str x0, [x1]          # Store to memory
```

### RISC-V
```gas
addi x1, x0, 10       # Add immediate
add x3, x1, x2        # Add registers
ld x1, 0(x2)          # Load doubleword
sd x1, 0(x2)          # Store doubleword
```

## Examples
```bash
# x86_64 ELF object
stas -a x86_64 -f elf64 -o program.o program.s

# ARM64 embedded firmware  
stas -a arm64 -f hex -b 0x8000 -o firmware.hex app.s

# RISC-V flat binary
stas -a riscv -f bin -o kernel.bin kernel.s

# DOS program
stas -a x86_16 -f com -o hello.com hello.s
```

## Testing Commands

### Unit Testing
```bash
# All format unit tests (117 tests)
make test-unit-formats

# Individual format tests  
make testbin/unit_test_elf
make testbin/unit_test_intel_hex
make testbin/unit_test_com_format
```

### Execution Testing  
```bash
# CPU emulation validation
make test-execution-all

# Architecture-specific tests
make test-execution-x86_16    # Real mode testing
make test-execution-x86_32    # Boot sequence simulation
make test-execution-x86_64    # 64-bit validation
```

### Advanced Testing
```bash
# Complete test suite (164+ tests)
make test-all

# Boot sequence simulation
./testbin/execution_test_x86_32_real_to_protected

# Build variant testing
make test-build-variants
```

## Test Results Summary
```
Format Unit Tests:      117/117 ✅ (0 failures)
Execution Tests:        32+/32+ ✅ (multi-architecture)  
Build Variants:         15/15 ✅ (all configurations)
Boot Sequence:          4/4 ✅ (real→protected mode)
```
