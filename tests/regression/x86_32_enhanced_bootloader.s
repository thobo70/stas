; Enhanced x86_32 Mixed-Mode Bootloader Test
; Tests comprehensive i386 instruction set including real/protected/V86 modes
; Supports .code16 and .code32 directives

.code16                          ; Start in 16-bit real mode (like BIOS boot)

; =============================================================================
; STAGE 1: Real Mode Initialization (16-bit)
; =============================================================================

bootloader_start:
    cli                          ; Disable interrupts for setup
    
    ; Set up segment registers for real mode
    movw $0x9000, %ax           ; Load segment base
    movw %ax, %ds               ; Data segment
    movw %ax, %es               ; Extra segment  
    movw %ax, %ss               ; Stack segment
    movw $0x7C00, %sp           ; Set stack pointer
    
    ; Clear direction flag for string operations
    cld
    
    ; Test 16-bit arithmetic in real mode
    movw $100, %ax              ; Load test value
    addw $50, %ax               ; Add immediate
    movw %ax, %bx               ; Copy result
    
    ; Test 8-bit operations in real mode
    movb $0x42, %al             ; Load 8-bit value
    movb $0x24, %bl             ; Load another 8-bit value
    addb %bl, %al               ; Add 8-bit values
    
    ; Test stack operations in real mode
    pushw %ax                   ; Push 16-bit value
    pushw %bx                   ; Push another value
    popw %dx                    ; Pop values back
    popw %cx
    
real_mode_complete:
    ; Prepare for protected mode transition
    ; Load 32-bit value into 32-bit register (requires operand prefix in 16-bit mode)
    movl $0x80000001, %eax      ; PE bit + arbitrary high bit
    
    ; Set up basic GDT pointer (simulation)
    movl $0x00100000, %ebx      ; GDT base address
    
; =============================================================================  
; STAGE 2: Protected Mode Transition
; =============================================================================

enter_protected_mode:
    ; Critical: Switch to 32-bit code mode
    .code32                     ; Now generating 32-bit code
    
    ; =============================================================================
    ; STAGE 3: Protected Mode Operations (32-bit)
    ; =============================================================================
    
protected_mode_start:
    ; Set up 32-bit segments
    movl $0x10, %ebx            ; Data segment selector
    mov %ebx, %ds              ; Load data segment
    mov %ebx, %es              ; Load extra segment
    mov %ebx, %ss              ; Load stack segment
    
    ; Set up 32-bit stack
    movl $0x00200000, %esp      ; 32-bit stack pointer
    
    ; Test comprehensive 32-bit arithmetic
    movl $1000, %eax            ; Load 32-bit immediate
    movl $500, %ebx             ; Load another value
    addl %ebx, %eax             ; Add 32-bit registers
    subl $250, %eax             ; Subtract immediate
    
    ; Test 32-bit register-to-register operations
    movl %eax, %ecx             ; Copy EAX to ECX
    movl %ebx, %edx             ; Copy EBX to EDX
    addl %ecx, %edx             ; Add registers
    
    ; Test comparison and control flow
    cmpl $1250, %eax            ; Compare with expected result
    je calculation_correct       ; Jump if equal
    
    ; Error handling (if calculation wrong)
    movl $0xDEADBEEF, %eax      ; Error marker
    jmp protected_mode_end
    
calculation_correct:
    ; Test stack operations in 32-bit mode
    pushl $0x12345678           ; Push 32-bit immediate
    pushl %eax                  ; Push register
    pushad                      ; Push all registers
    
    ; Test more complex operations
    incl %eax                   ; Increment
    decl %ebx                   ; Decrement
    
    ; Restore registers
    popad                       ; Pop all registers
    popl %eax                   ; Pop register
    addl $4, %esp               ; Adjust stack (skip immediate)
    
    ; Test logical operations
    movl $0xFF00FF00, %eax      ; Test pattern
    movl $0x00FF00FF, %ebx      ; Inverse pattern
    andl %ebx, %eax             ; AND operation
    orl $0x0000FFFF, %eax       ; OR operation
    xorl %ebx, %eax             ; XOR operation
    
protected_mode_end:
    ; Enable interrupts in protected mode
    sti
    
    ; =============================================================================
    ; STAGE 4: Virtual 8086 Mode Simulation
    ; =============================================================================
    
    ; Simulate entering V86 mode by switching back to 16-bit operations
    ; In real implementation, this would involve setting up TSS and EFLAGS.VM
    
    ; For this test, we'll simulate V86 by using 16-bit instructions in 32-bit mode
    movw $0x1234, %ax           ; 16-bit operation (uses operand prefix)
    movw %ax, %bx               ; 16-bit register copy
    
    ; Test V86 mode interrupt (simulation)
    ; int $0x21 would be handled by V86 monitor in real system
    
    ; =============================================================================
    ; STAGE 5: System Management
    ; =============================================================================
    
system_management:
    ; Test system control instructions
    clc                         ; Clear carry flag
    stc                         ; Set carry flag
    cld                         ; Clear direction flag
    std                         ; Set direction flag
    
    ; Test conditional jumps
    movl $5, %eax
    cmpl $5, %eax
    je equal_test               ; Should jump
    movl $0xDEADBEEF, %eax      ; Should not execute
    
equal_test:
    movl $10, %eax
    cmpl $5, %eax
    jne not_equal_test          ; Should jump
    movl $0xBADC0DE1, %eax      ; Should not execute
    
not_equal_test:
    ; Test more conditional jumps
    movl $10, %eax
    cmpl $5, %eax
    jg greater_test             ; Should jump (10 > 5)
    movl $0xBADC0DE2, %eax      ; Should not execute
    
greater_test:
    movl $3, %eax
    cmpl $5, %eax
    jl less_test                ; Should jump (3 < 5)
    movl $0xBADC0DE3, %eax      ; Should not execute
    
less_test:
    ; Test call and return simulation
    call subroutine
    jmp final_stage
    
subroutine:
    ; Simple subroutine
    movl $0xCAFEBABE, %eax      ; Subroutine marker
    ret                         ; Return to caller
    
final_stage:
    ; =============================================================================
    ; STAGE 6: Final Testing and Cleanup  
    ; =============================================================================
    
    ; Test final instruction combinations
    movl $0x1000, %eax
    movl $0x2000, %ebx
    movl $0x3000, %ecx
    movl $0x4000, %edx
    
    ; Test all basic arithmetic
    addl %ebx, %eax             ; EAX = 0x3000
    subl %ecx, %eax             ; EAX = 0x0000
    addl %edx, %eax             ; EAX = 0x4000
    
    ; Final result check
    cmpl $0x4000, %eax
    je success
    
    ; Failure path
    movl $0xFAE1ED, %eax
    hlt                         ; Halt on failure
    
success:
    ; Success - clean shutdown
    movl $0x00CCEE55, %eax       ; Success marker
    
    ; Test final system operations
    cli                         ; Disable interrupts
    
    ; Simulate system shutdown or reset
    hlt                         ; Halt processor
    
; =============================================================================
; Data section (would be in a real bootloader)
; =============================================================================

; In a real bootloader, we'd have:
; - GDT (Global Descriptor Table)
; - IDT (Interrupt Descriptor Table)  
; - Page tables for protected mode
; - Boot signature (0xAA55)

; Boot signature for MBR (Master Boot Record)
; .org 510
; .word 0xAA55                  ; Boot signature

; =============================================================================
; End of bootloader
; =============================================================================
