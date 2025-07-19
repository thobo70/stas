# =============================================================================
# PHASE 7 COMPLETE DEMONSTRATION
# Advanced Language Features: Macros, Includes, Conditionals, Expressions
# =============================================================================

.include "common_defs.inc"

# Advanced macro definitions with complex expressions
#define STACK_START 0x8000
#define STACK_OFFSET 0x400
#define VERSION_MAJOR 1
#define VERSION_MINOR 2

# Conditional compilation based on build mode
#define RELEASE_BUILD

.section .text
.global _start

_start:
    # =========================================================================
    # Macro Expansion Tests
    # =========================================================================
    
    # Simple macro expansion
    movq $BUFFER_SIZE, %rax      # From included file: 1024
    movq $SUCCESS, %rbx          # From included file: 0
    movq $FAILURE, %rcx          # From included file: 1
    
    # Advanced macro expressions
    movq $STACK_START, %rdx      # 0x8000
    movq $STACK_OFFSET, %rsi     # 0x400
    movq $VERSION_MAJOR, %rdi    # 1
    movq $VERSION_MINOR, %r8     # 2
    
    # =========================================================================
    # Conditional Compilation Tests
    # =========================================================================
    
    #ifdef RELEASE_BUILD
    movq $0x12345678, %r9        # Should be included
    #endif
    
    #ifdef DEBUG_BUILD
    movq $0xDEADBEEF, %r10       # Should NOT be included
    #endif
    
    #ifndef DEBUG_BUILD  
    movq $0xCAFEBABE, %r11       # Should be included
    #endif
    
    # =========================================================================
    # System Exit
    # =========================================================================
    
    movq $60, %rax               # Exit system call
    movq $SUCCESS, %rdi          # Exit with success code
    syscall
