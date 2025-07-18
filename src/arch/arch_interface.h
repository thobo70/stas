#ifndef ARCH_INTERFACE_H
#define ARCH_INTERFACE_H

#include <stdint.h>
#include <stdbool.h>
#include <stddef.h>

// Section types
typedef enum {
    SECTION_TEXT,
    SECTION_DATA,
    SECTION_BSS,
    SECTION_RODATA,
    SECTION_DEBUG
} section_type_t;

// Operand types
typedef enum {
    OPERAND_REGISTER,
    OPERAND_IMMEDIATE,
    OPERAND_MEMORY,
    OPERAND_SYMBOL
} operand_type_t;

// Register information
typedef struct {
    uint32_t id;
    char *name;
    uint8_t size;  // Size in bytes
    uint8_t encoding;  // Architecture-specific encoding
} asm_register_t;

// Addressing mode structure
typedef struct {
    enum {
        ADDR_DIRECT,      // symbol
        ADDR_INDIRECT,    // (%register)
        ADDR_INDEXED,     // offset(%base,%index,scale)
        ADDR_RIP_RELATIVE // symbol(%rip) - x86-64 specific
    } type;
    
    int64_t offset;
    asm_register_t base;
    asm_register_t index;
    uint8_t scale;  // 1, 2, 4, 8
    char *symbol;
} addressing_mode_t;

// Operand structure
typedef struct {
    operand_type_t type;
    union {
        asm_register_t reg;
        int64_t immediate;
        addressing_mode_t memory;
        char *symbol;
    } value;
    size_t size;  // Size in bytes (1, 2, 4, 8)
} operand_t;

// Instruction structure
typedef struct {
    char *mnemonic;
    operand_t *operands;
    size_t operand_count;
    uint8_t *encoding;
    size_t encoding_length;
    uint32_t line_number;
} instruction_t;

// Architecture operations interface
typedef struct arch_ops {
    const char *name;
    
    // Architecture initialization
    int (*init)(void);
    void (*cleanup)(void);
    
    // Instruction processing
    int (*parse_instruction)(const char *mnemonic, operand_t *operands, 
                           size_t operand_count, instruction_t *inst);
    int (*encode_instruction)(instruction_t *inst, uint8_t *buffer, 
                            size_t *length);
    
    // Register handling
    int (*parse_register)(const char *reg_name, asm_register_t *reg);
    bool (*is_valid_register)(asm_register_t reg);
    const char *(*get_register_name)(asm_register_t reg);
    
    // Addressing modes
    int (*parse_addressing)(const char *addr_str, addressing_mode_t *mode);
    bool (*validate_addressing)(addressing_mode_t *mode, instruction_t *inst);
    
    // Architecture-specific directives
    int (*handle_directive)(const char *directive, const char *args);
    
    // Size and alignment information
    size_t (*get_instruction_size)(instruction_t *inst);
    size_t (*get_alignment)(section_type_t section);
    
    // Validation
    bool (*validate_instruction)(instruction_t *inst);
    bool (*validate_operand_combination)(const char *mnemonic, 
                                       operand_t *operands, 
                                       size_t operand_count);
} arch_ops_t;

// Plugin management
typedef struct arch_plugin {
    void *handle;              // dlopen handle
    arch_ops_t *ops;          // Architecture operations
    char *name;               // Architecture name
    struct arch_plugin *next; // Linked list
} arch_plugin_t;

// Plugin API
int load_architecture_plugin(const char *arch_name);
arch_ops_t *get_architecture(const char *name);
void unload_all_plugins(void);
int register_architecture(arch_ops_t *ops);

// Each architecture plugin must export this function
arch_ops_t *get_arch_ops(void);

#endif // ARCH_INTERFACE_H
