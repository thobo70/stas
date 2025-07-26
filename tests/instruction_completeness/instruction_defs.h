// Common definitions for instruction completeness testing
#ifndef INSTRUCTION_DEFS_H
#define INSTRUCTION_DEFS_H

#include <stdbool.h>
#include <stdio.h>
#include <string.h>

typedef struct {
    const char *name;
    const char *category;
    int operand_count;
    bool optional;
} instruction_def_t;

typedef struct {
    const instruction_def_t *instructions;
    int count;
    const char *name;
} instruction_set_t;

// Function declarations
void test_arm64_completeness();
void test_riscv_completeness();

#endif
