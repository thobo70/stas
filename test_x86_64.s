.section .text
.global _start

_start:
    mov $60, %rax      # system call for exit
    mov $0, %rdi       # exit status
    syscall           # call kernel

.section .data
message:
    .ascii "Hello, World!"
