# Simple x86-64 test program
.section .text
.global _start

_start:
    movq $42, %rax
    movq $1, %rbx
    addq %rbx, %rax
    # Result should be 43 in %rax
    movq $60, %rax  # sys_exit
    movq $0, %rdi   # exit status
    syscall
