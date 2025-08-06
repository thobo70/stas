# =============================================================================
# PHASE 7 COMPLETE DEMONSTRATION
# Advanced Language Features: Includes and Expressions
# =============================================================================

.include "common_defs.inc"

# Constants with complex expressions
STACK_START = 0x8000
# =============================================================================
# PHASE 7 COMPLETE DEMONSTRATION
# Advanced Language Features: Includes and Expressions
# Target: x86_64 (Compatible with modern systems)
# =============================================================================

.include "common_defs.inc"

# Constants with complex expressions
STACK_START = 0x8000
STACK_OFFSET = 0x400
VERSION_MAJOR = 1
VERSION_MINOR = 2

.section .text
.global _start

_start:
    # =========================================================================
    # Expression and Include Tests (x86_64 syntax)
    # =========================================================================
    
    # Using included definitions
    movq $COMMON_BUFFER_SIZE, %rax    # From included file: 1024
    movq $COMMON_SUCCESS, %rbx        # From included file: 0
    movq $COMMON_ERROR, %rcx          # From included file: -1
    
    # Using local constants
    movq $STACK_START, %rdx           # 0x8000
    movq $STACK_OFFSET, %rsi          # 0x400
    movq $VERSION_MAJOR, %rdi         # 1
    
    # Complex expression evaluation
    movq $(STACK_START + STACK_OFFSET), %r8    # 0x8000 + 0x400 = 0x8400
    movq $(VERSION_MAJOR * 100 + VERSION_MINOR), %r9  # 1 * 100 + 2 = 102
    
    # =========================================================================
    # Exit (Linux x86_64 system call)
    # =========================================================================
    
    movq $60, %rax                   # sys_exit
    movq $0, %rdi                    # exit status
    syscall                          # Linux system call
