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

# =============================================================================
# PHASE 7 COMPLETE DEMONSTRATION
# Advanced Language Features: Macros, Includes, Conditionals, Expressions
# Target: x86_16 (DOS/Boot sector compatible)
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
    # Macro Expansion Tests (x86_16 syntax)
    # =========================================================================
    
    # Simple macro expansion using included definitions
    movw $COMMON_BUFFER_SIZE, %ax    # From included file: 1024
    movw $COMMON_SUCCESS, %bx        # From included file: 0
    movw $COMMON_ERROR, %cx          # From included file: -1
    
    # Advanced macro expressions
    movw $STACK_START, %dx           # 0x8000
    movw $STACK_OFFSET, %si          # 0x400
    movw $VERSION_MAJOR, %di         # 1
    
    # =========================================================================
    # Conditional Compilation Tests
    # =========================================================================
    
    #ifdef RELEASE_BUILD
    movw $0x1234, %sp                # Should be included
    #endif
    
    #ifdef DEBUG_BUILD
    movw $0xDEAD, %bp                # Should NOT be included
    #endif
    
    #ifndef DEBUG_BUILD  
    movw $0xCAFE, %ax                # Should be included
    #endif
    
    # =========================================================================
    # DOS Exit
    # =========================================================================
    
    movw $0x4C00, %ax                # DOS exit function
    int $0x21                        # DOS interrupt
