# Simple test assembly
.text
_start:
    nop
    movq $1, %rax
    movq $0, %rdi
    syscall
