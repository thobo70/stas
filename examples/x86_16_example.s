# Example x86-16 assembly (16-bit mode)
# AT&T syntax for 8086/80286 architecture

.code16                     # Assemble in 16-bit mode

.section .text
.global _start

_start:
    # Set up data segment
    movw $data_segment, %ax
    movw %ax, %ds
    
    # Load message address and length
    movw $message, %si      # Source index for string operations
    movw $msg_len, %cx      # Counter register for loop
    
    # Simple character output loop (BIOS interrupt)
print_loop:
    lodsb                   # Load byte from DS:SI into AL, increment SI
    cmpb $0, %al           # Check for null terminator
    je done                # Jump if equal (zero)
    
    # BIOS teletype output
    movb $0x0E, %ah        # BIOS teletype function
    movb $0x07, %bl        # Text attribute (white on black)
    int $0x10              # BIOS video interrupt
    
    loop print_loop        # Decrement CX and loop if not zero

done:
    # Exit to DOS
    movb $0x4C, %ah        # DOS terminate function
    movb $0x00, %al        # Exit code
    int $0x21              # DOS interrupt

.section .data
data_segment: .word 0x1000  # Data segment address

message: .ascii "Hello from x86-16!\r\n\0"
msg_len = . - message       # Calculate message length

# Example of 16-bit addressing modes
numbers: .word 1234, 5678, 9012

.section .bss
buffer: .space 64           # 64-byte buffer

# Example function demonstrating 16-bit stack operations
.section .text
my_function:
    pushw %bp              # Save old base pointer
    movw %sp, %bp          # Set up new stack frame
    
    # Function parameters accessible via stack:
    # 4(%bp) = return address
    # 6(%bp) = first parameter
    # 8(%bp) = second parameter
    
    movw 6(%bp), %ax       # Load first parameter
    addw 8(%bp), %ax       # Add second parameter
    
    popw %bp               # Restore base pointer
    ret                    # Return (result in AX)

# Segment override examples
segment_demo:
    movw %ds:numbers, %ax   # Load from data segment
    movw %es:buffer, %bx    # Load from extra segment (if set up)
    movw %ax, %ss:(%bp)     # Store to stack segment
