# Example AT&T syntax assembly for x86-64
# This demonstrates various features of the STAS assembler

.section .data
    message:    .ascii "Hello from STAS!\n"
    msg_len:    .quad 18
    number:     .quad 42

.section .bss
    buffer:     .space 64

.section .text
.global _start

_start:
    # System call to write
    movq $1, %rax           # sys_write system call
    movq $1, %rdi           # file descriptor (stdout)
    movq $message, %rsi     # message to write
    movq msg_len(%rip), %rdx # message length
    syscall
    
    # Load and manipulate data
    movq number(%rip), %rbx  # Load number into %rbx
    addq $10, %rbx          # Add 10 to the number
    
    # Use different addressing modes
    movq %rbx, buffer(%rip) # Store result in buffer
    movq buffer(%rip), %rcx # Load it back
    
    # Conditional jump example
    cmpq $50, %rcx          # Compare with 50
    jge exit_success        # Jump if greater or equal
    
    # Exit with error
    movq $60, %rax          # sys_exit
    movq $1, %rdi           # exit status = 1
    syscall

exit_success:
    # Exit successfully
    movq $60, %rax          # sys_exit
    movq $0, %rdi           # exit status = 0
    syscall

# Function example
.type my_function, @function
my_function:
    pushq %rbp              # Save old frame pointer
    movq %rsp, %rbp         # Set up new frame pointer
    
    # Function body would go here
    
    popq %rbp               # Restore frame pointer
    ret                     # Return to caller
