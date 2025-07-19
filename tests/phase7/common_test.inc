# Common definitions for include testing
# This file should be included by test_includes.s

# Constants
#define COMMON_BUFFER_SIZE 512
#define COMMON_SUCCESS 0
#define COMMON_FAILURE -1

# Shared macros
#define SAVE_CONTEXT(base) str r0, [base]; str r1, [base, #4]; str r2, [base, #8]
#define RESTORE_CONTEXT(base) ldr r0, [base]; ldr r1, [base, #4]; ldr r2, [base, #8]

# Function declarations (labels to be referenced)
.global common_init
.global common_cleanup

.section .text
common_init:
    mov r0, #COMMON_SUCCESS
    bx lr

common_cleanup:
    mov r0, #COMMON_SUCCESS
    bx lr

.section .data
common_buffer: .space COMMON_BUFFER_SIZE
common_status: .word COMMON_SUCCESS
