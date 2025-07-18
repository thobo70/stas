# Example x86-32 assembly (32-bit mode)
# AT&T syntax for 80386+ (IA-32) architecture

.code32                     # Assemble in 32-bit mode

.section .text
.global _start

_start:
    # Set up segments (in protected mode, these are selectors)
    movw $0x10, %ax        # Data segment selector
    movw %ax, %ds
    movw %ax, %es
    movw %ax, %fs
    movw %ax, %gs
    
    # Example of 32-bit operations
    movl $message, %esi     # Load message address into ESI
    movl $msg_len, %ecx     # Load message length into ECX
    
    # System call example (Linux)
    movl $4, %eax          # sys_write system call number
    movl $1, %ebx          # File descriptor (stdout)
    movl $message, %ecx    # Message buffer
    movl $msg_len, %edx    # Message length
    int $0x80              # Software interrupt for system call
    
    # Demonstrate 32-bit arithmetic
    movl $0x12345678, %eax # Load 32-bit immediate
    addl $0x1000, %eax     # Add immediate to register
    movl %eax, result      # Store result in memory
    
    # Use different addressing modes
    movl result, %ebx      # Direct addressing
    movl (%esi), %ecx      # Indirect addressing
    movl 4(%esi), %edx     # Displacement addressing
    movl (%esi,%ebx,2), %eax # Indexed addressing with scale
    
    # Demonstrate PUSH/POP with 32-bit registers
    pushl %eax
    pushl %ebx
    pushl %ecx
    pushl %edx
    
    # PUSHAD - push all 32-bit general registers
    pushad
    
    # POPAD - pop all 32-bit general registers
    popad
    
    # Restore individual registers
    popl %edx
    popl %ecx
    popl %ebx
    popl %eax
    
    # Exit system call
    movl $1, %eax          # sys_exit system call
    movl $0, %ebx          # Exit status
    int $0x80              # Software interrupt

# Function demonstrating 32-bit calling convention
calculate_sum:
    pushl %ebp             # Save caller's frame pointer
    movl %esp, %ebp        # Set up new frame pointer
    
    # Function parameters (assuming cdecl calling convention):
    # 8(%ebp)  = first parameter
    # 12(%ebp) = second parameter
    # 16(%ebp) = third parameter, etc.
    
    movl 8(%ebp), %eax     # Load first parameter
    addl 12(%ebp), %eax    # Add second parameter
    addl 16(%ebp), %eax    # Add third parameter
    
    # Result is returned in EAX
    
    movl %ebp, %esp        # Restore stack pointer
    popl %ebp              # Restore caller's frame pointer
    ret                    # Return to caller

# Example of conditional operations
conditional_example:
    movl $10, %eax
    movl $20, %ebx
    
    cmpl %ebx, %eax        # Compare EAX with EBX
    jl less_than           # Jump if EAX < EBX
    jge greater_equal      # Jump if EAX >= EBX
    
less_than:
    movl $1, %ecx          # Set flag to 1
    jmp end_conditional
    
greater_equal:
    movl $0, %ecx          # Set flag to 0
    
end_conditional:
    ret

.section .data
message: .ascii "Hello from x86-32 (IA-32)!\n"
msg_len = . - message

# 32-bit data examples
numbers: .long 0x12345678, 0x9ABCDEF0, 0xFEDCBA98
float_val: .float 3.14159
double_val: .double 2.71828

# String data
string1: .asciz "Null-terminated string"
string2: .ascii "Non-terminated string"

.section .bss
result: .space 4           # 32-bit result storage
buffer: .space 256         # 256-byte buffer
temp_vars: .space 16       # Temporary variables

# Example of advanced 32-bit features
.section .text

# String operations example
string_operations:
    cld                    # Clear direction flag (forward)
    movl $string1, %esi    # Source string
    movl $buffer, %edi     # Destination buffer
    movl $20, %ecx         # Number of bytes to copy
    
    rep movsb              # Repeat move string bytes
    
    # String comparison
    movl $string1, %esi
    movl $string2, %edi
    movl $10, %ecx
    repe cmpsb             # Repeat compare string bytes while equal
    
    ret

# Bit manipulation example
bit_operations:
    movl $0b11110000, %eax # Binary literal
    
    # Shift operations
    shll $2, %eax          # Shift left logical by 2 positions
    shrl $1, %eax          # Shift right logical by 1 position
    sarl $1, %eax          # Shift right arithmetic by 1 position
    
    # Rotate operations
    roll $4, %eax          # Rotate left by 4 positions
    rorl $2, %eax          # Rotate right by 2 positions
    
    # Logical operations
    andl $0xFF00, %eax     # Mask operation
    orl $0x000F, %eax      # Set bits
    xorl $0xFFFF, %eax     # Toggle bits
    
    ret
