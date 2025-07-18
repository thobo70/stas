#ifndef X86_32_H
#define X86_32_H

#include "../arch_interface.h"

// x86-32 specific definitions
// This is a simplified implementation for the modular structure

// Function declarations
arch_ops_t *x86_32_get_arch_ops(void);
int x86_32_init(void);
void x86_32_cleanup(void);

// Placeholder implementations
int x86_32_parse_instruction(const char *mnemonic, operand_t *operands, 
                           size_t operand_count, instruction_t *inst);
int x86_32_encode_instruction(instruction_t *inst, uint8_t *buffer, size_t *length);
int x86_32_parse_register(const char *reg_name, asm_register_t *reg);
bool x86_32_is_valid_register(asm_register_t reg);
const char *x86_32_get_register_name(asm_register_t reg);

#endif // X86_32_H
