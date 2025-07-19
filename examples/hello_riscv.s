# RISC-V test program
# Simple arithmetic operations

# Load immediate values
addi x1, x0, 10     # x1 = 0 + 10 = 10
addi x2, x0, 5      # x2 = 0 + 5 = 5

# Register arithmetic
add x3, x1, x2      # x3 = x1 + x2 = 15
sub x4, x1, x2      # x4 = x1 - x2 = 5

# Load upper immediate
lui x5, 0x10000     # x5 = 0x10000000

# System call exit
addi x10, x0, 0     # x10 (a0) = exit status 0
addi x17, x0, 93    # x17 (a7) = sys_exit
ecall               # system call
