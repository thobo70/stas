/*
 * STAS Code Generation Implementation
 * Converts parsed AST to machine code using architecture-specific encoders
 */

#define _GNU_SOURCE  // For strdup
#include "codegen.h"
#include "parser.h"
#include "output_format.h"
#include "formats/smof.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

// Forward declarations
static int codegen_process_instruction(codegen_ctx_t *ctx, ast_node_t *inst_node);
static int codegen_process_directive(codegen_ctx_t *ctx, ast_node_t *dir_node);
static int codegen_process_label(codegen_ctx_t *ctx, ast_node_t *label_node);
static int flush_current_section(codegen_ctx_t *ctx);

codegen_ctx_t *codegen_create(arch_ops_t *arch, output_context_t *output, symbol_table_t *symbols) {
    if (!arch || !output) {
        return NULL;
    }
    
    codegen_ctx_t *ctx = calloc(1, sizeof(codegen_ctx_t));
    if (!ctx) {
        return NULL;
    }
    
    ctx->arch = arch;
    ctx->output = output;
    ctx->symbols = symbols;
    ctx->current_address = output->base_address;
    ctx->current_section = ".text";
    ctx->verbose = output->verbose;
    ctx->total_code_size = 0; // Track total bytes generated
    ctx->relocations = NULL;  // Initialize relocation list
    
    // Initialize code buffer
    ctx->code_capacity = 1024;
    ctx->code_buffer = malloc(ctx->code_capacity);
    if (!ctx->code_buffer) {
        free(ctx);
        return NULL;
    }
    
    return ctx;
}

void codegen_destroy(codegen_ctx_t *ctx) {
    if (!ctx) {
        return;
    }
    
    // Free relocation list
    relocation_t *reloc = ctx->relocations;
    while (reloc) {
        relocation_t *next = reloc->next;
        free((void*)reloc->symbol_name);
        free(reloc);
        reloc = next;
    }
    
    free(ctx->code_buffer);
    free(ctx);
}

int codegen_generate(codegen_ctx_t *ctx, ast_node_t *ast) {
    if (!ctx || !ast) {
        return -1;
    }
    
    if (ctx->verbose) {
        printf("Code generation starting...\n");
    }
    
    // Process AST nodes
    ast_node_t *current = ast;
    while (current) {
        switch (current->type) {
            case AST_INSTRUCTION:
                if (codegen_process_instruction(ctx, current) != 0) {
                    return -1;
                }
                break;
                
            case AST_DIRECTIVE:
                if (codegen_process_directive(ctx, current) != 0) {
                    return -1;
                }
                break;
                
            case AST_LABEL:
                if (codegen_process_label(ctx, current) != 0) {
                    return -1;
                }
                break;
                
            default:
                if (ctx->verbose) {
                    printf("Warning: Skipping unknown AST node type %d\n", current->type);
                }
                break;
        }
        
        current = current->next;
    }
    
    // Resolve relocations before flushing the final section
    if (ctx->verbose) {
        printf("Resolving relocations before final section flush...\n");
    }
    if (codegen_resolve_relocations(ctx) != 0) {
        if (ctx->verbose) {
            printf("Warning: Some relocations could not be resolved\n");
        }
    }
    
    // Flush the final section
    if (flush_current_section(ctx) != 0) {
        return -1;
    }
    
    if (ctx->verbose) {
        printf("Code generation complete: %zu bytes generated\n", ctx->total_code_size);
    }
    
    return 0;
}

static int codegen_process_instruction(codegen_ctx_t *ctx, ast_node_t *inst_node) {
    if (!ctx || !inst_node || inst_node->type != AST_INSTRUCTION) {
        return -1;
    }
    
    // Convert AST instruction node to instruction_t
    ast_instruction_t *ast_inst = (ast_instruction_t *)inst_node->data;
    if (!ast_inst) {
        return -1;
    }

    instruction_t inst = {0};
    inst.mnemonic = ast_inst->mnemonic;
    inst.operands = ast_inst->operands;
    inst.operand_count = ast_inst->operand_count;
    
    // FIRST: Check for jump instructions with symbols and prepare relocations
    // This must happen before any operand type conversions
    bool has_jump_relocations = false;
    const char *jump_symbol_names[8] = {0}; // Support up to 8 operands with symbols
    size_t jump_symbol_count = 0;
    
    for (size_t i = 0; i < inst.operand_count; i++) {
        if (inst.operands[i].type == OPERAND_SYMBOL) {
            const char *symbol_name = inst.operands[i].value.symbol;
            
            // Check if this is a jump instruction
            bool is_jump_instruction = (
                strcmp(inst.mnemonic, "jmp") == 0 ||
                strcmp(inst.mnemonic, "je") == 0 || strcmp(inst.mnemonic, "jz") == 0 ||
                strcmp(inst.mnemonic, "jne") == 0 || strcmp(inst.mnemonic, "jnz") == 0 ||
                strcmp(inst.mnemonic, "ja") == 0 || strcmp(inst.mnemonic, "jae") == 0 ||
                strcmp(inst.mnemonic, "jb") == 0 || strcmp(inst.mnemonic, "jbe") == 0 ||
                strcmp(inst.mnemonic, "jg") == 0 || strcmp(inst.mnemonic, "jge") == 0 ||
                strcmp(inst.mnemonic, "jl") == 0 || strcmp(inst.mnemonic, "jle") == 0 ||
                strcmp(inst.mnemonic, "jc") == 0 || strcmp(inst.mnemonic, "jnc") == 0 ||
                strcmp(inst.mnemonic, "jo") == 0 || strcmp(inst.mnemonic, "jno") == 0 ||
                strcmp(inst.mnemonic, "js") == 0 || strcmp(inst.mnemonic, "jns") == 0 ||
                strcmp(inst.mnemonic, "jp") == 0 || strcmp(inst.mnemonic, "jnp") == 0 ||
                strcmp(inst.mnemonic, "jna") == 0 || strcmp(inst.mnemonic, "jnae") == 0 ||
                strcmp(inst.mnemonic, "jnb") == 0 || strcmp(inst.mnemonic, "jnbe") == 0 ||
                strcmp(inst.mnemonic, "jng") == 0 || strcmp(inst.mnemonic, "jnge") == 0 ||
                strcmp(inst.mnemonic, "jnl") == 0 || strcmp(inst.mnemonic, "jnle") == 0
            );
            
            if (is_jump_instruction && symbol_name) {
                // Skip register names
                if (!(strcmp(symbol_name, "eax") == 0 || strcmp(symbol_name, "ebx") == 0 ||
                      strcmp(symbol_name, "ecx") == 0 || strcmp(symbol_name, "edx") == 0 ||
                      strcmp(symbol_name, "esi") == 0 || strcmp(symbol_name, "edi") == 0 ||
                      strcmp(symbol_name, "esp") == 0 || strcmp(symbol_name, "ebp") == 0 ||
                      strcmp(symbol_name, "ax") == 0 || strcmp(symbol_name, "bx") == 0 ||
                      strcmp(symbol_name, "cx") == 0 || strcmp(symbol_name, "dx") == 0)) {
                    
                    has_jump_relocations = true;
                    
                    // Store symbol name for later relocation
                    if (jump_symbol_count < 8) {
                        jump_symbol_names[jump_symbol_count++] = symbol_name;
                    }
                    
                    if (ctx->verbose) {
                        printf("Preparing jump relocation for '%s' -> '%s'\n", 
                               inst.mnemonic, symbol_name);
                    }
                    
                    // Convert to immediate 0 for encoding, but we'll add relocation after encoding
                    inst.operands[i].type = OPERAND_IMMEDIATE;
                    inst.operands[i].value.immediate = 0;
                    inst.operands[i].size = 1; // 8-bit displacement
                }
            }
        }
    }
    
    // Track internal jump relocations before operand conversion
    for (size_t i = 0; i < inst.operand_count; i++) {
        if (inst.operands[i].type == OPERAND_SYMBOL) {
            const char *symbol_name = inst.operands[i].value.symbol;
            
            // Check if this is a jump instruction that needs internal relocation
            bool is_jump_instruction = (
                strcmp(inst.mnemonic, "jmp") == 0 ||
                strcmp(inst.mnemonic, "je") == 0 || strcmp(inst.mnemonic, "jz") == 0 ||
                strcmp(inst.mnemonic, "jne") == 0 || strcmp(inst.mnemonic, "jnz") == 0 ||
                strcmp(inst.mnemonic, "ja") == 0 || strcmp(inst.mnemonic, "jae") == 0 ||
                strcmp(inst.mnemonic, "jb") == 0 || strcmp(inst.mnemonic, "jbe") == 0 ||
                strcmp(inst.mnemonic, "jg") == 0 || strcmp(inst.mnemonic, "jge") == 0 ||
                strcmp(inst.mnemonic, "jl") == 0 || strcmp(inst.mnemonic, "jle") == 0 ||
                strcmp(inst.mnemonic, "jc") == 0 || strcmp(inst.mnemonic, "jnc") == 0 ||
                strcmp(inst.mnemonic, "jo") == 0 || strcmp(inst.mnemonic, "jno") == 0 ||
                strcmp(inst.mnemonic, "js") == 0 || strcmp(inst.mnemonic, "jns") == 0 ||
                strcmp(inst.mnemonic, "jp") == 0 || strcmp(inst.mnemonic, "jnp") == 0 ||
                strcmp(inst.mnemonic, "jna") == 0 || strcmp(inst.mnemonic, "jnae") == 0 ||
                strcmp(inst.mnemonic, "jnb") == 0 || strcmp(inst.mnemonic, "jnbe") == 0 ||
                strcmp(inst.mnemonic, "jng") == 0 || strcmp(inst.mnemonic, "jnge") == 0 ||
                strcmp(inst.mnemonic, "jnl") == 0 || strcmp(inst.mnemonic, "jnle") == 0
            );
            
            if (is_jump_instruction && symbol_name) {
                // Skip register names misclassified as symbols
                if (!(strcmp(symbol_name, "eax") == 0 || strcmp(symbol_name, "ebx") == 0 ||
                      strcmp(symbol_name, "ecx") == 0 || strcmp(symbol_name, "edx") == 0 ||
                      strcmp(symbol_name, "esi") == 0 || strcmp(symbol_name, "edi") == 0 ||
                      strcmp(symbol_name, "esp") == 0 || strcmp(symbol_name, "ebp") == 0 ||
                      strcmp(symbol_name, "ax") == 0 || strcmp(symbol_name, "bx") == 0 ||
                      strcmp(symbol_name, "cx") == 0 || strcmp(symbol_name, "dx") == 0)) {
                    
                    // Store current address for relocation calculation
                    uint32_t instruction_address = ctx->current_address;
                    
                    // Replace symbol with immediate 0 for encoding
                    inst.operands[i].type = OPERAND_IMMEDIATE;
                    inst.operands[i].value.immediate = 0;
                    inst.operands[i].size = 1; // Assume 8-bit displacement for now
                    
                    // We'll add the relocation after encoding when we know the displacement offset
                    // For now, just note that we need to track this
                    
                    if (ctx->verbose) {
                        printf("Jump instruction '%s' with symbol '%s' at address 0x%X\n", 
                               inst.mnemonic, symbol_name, instruction_address);
                    }
                }
            }
        }
    }
    
    // Continue with existing logic for non-jump relocations
    for (size_t i = 0; i < inst.operand_count; i++) {
        if (inst.operands[i].type == OPERAND_SYMBOL) {
            const char *symbol_name = inst.operands[i].value.symbol;
            
            // Skip if this is actually a register name (parser bug workaround)
            if (symbol_name && (
                // x86_64 registers
                strcmp(symbol_name, "rax") == 0 || strcmp(symbol_name, "rbx") == 0 ||
                strcmp(symbol_name, "rcx") == 0 || strcmp(symbol_name, "rdx") == 0 ||
                strcmp(symbol_name, "rsi") == 0 || strcmp(symbol_name, "rdi") == 0 ||
                strcmp(symbol_name, "rsp") == 0 || strcmp(symbol_name, "rbp") == 0 ||
                strcmp(symbol_name, "r8") == 0 || strcmp(symbol_name, "r9") == 0 ||
                strcmp(symbol_name, "r10") == 0 || strcmp(symbol_name, "r11") == 0 ||
                strcmp(symbol_name, "r12") == 0 || strcmp(symbol_name, "r13") == 0 ||
                strcmp(symbol_name, "r14") == 0 || strcmp(symbol_name, "r15") == 0 ||
                // x86_32 registers
                strcmp(symbol_name, "eax") == 0 || strcmp(symbol_name, "ebx") == 0 ||
                strcmp(symbol_name, "ecx") == 0 || strcmp(symbol_name, "edx") == 0 ||
                strcmp(symbol_name, "esi") == 0 || strcmp(symbol_name, "edi") == 0 ||
                strcmp(symbol_name, "esp") == 0 || strcmp(symbol_name, "ebp") == 0 ||
                // x86_16 registers
                strcmp(symbol_name, "ax") == 0 || strcmp(symbol_name, "bx") == 0 ||
                strcmp(symbol_name, "cx") == 0 || strcmp(symbol_name, "dx") == 0 ||
                strcmp(symbol_name, "si") == 0 || strcmp(symbol_name, "di") == 0 ||
                strcmp(symbol_name, "sp") == 0 || strcmp(symbol_name, "bp") == 0 ||
                // 8-bit registers
                strcmp(symbol_name, "al") == 0 || strcmp(symbol_name, "bl") == 0 ||
                strcmp(symbol_name, "cl") == 0 || strcmp(symbol_name, "dl") == 0 ||
                strcmp(symbol_name, "ah") == 0 || strcmp(symbol_name, "bh") == 0 ||
                strcmp(symbol_name, "ch") == 0 || strcmp(symbol_name, "dh") == 0)) {
                continue; // Skip register names misclassified as symbols
            }
            
            // Create relocation entry
            output_format_ops_t *format_ops = get_output_format(ctx->output->format);
            if (format_ops && format_ops->add_relocation) {
                // Determine relocation type based on instruction and operand
                uint8_t reloc_type = SMOF_RELOC_ABS32; // Default to 32-bit absolute
                
                // For x86_64, determine if we need PC-relative or absolute addressing
                if (strcmp(inst.mnemonic, "mov") == 0 || strcmp(inst.mnemonic, "movq") == 0) {
                    reloc_type = SMOF_RELOC_ABS32; // mov uses absolute addressing
                } else if (strcmp(inst.mnemonic, "call") == 0 || strcmp(inst.mnemonic, "jmp") == 0 ||
                          strncmp(inst.mnemonic, "j", 1) == 0) { // All conditional jumps start with 'j'
                    reloc_type = SMOF_RELOC_REL32; // branches use PC-relative addressing
                } else if (strcmp(inst.mnemonic, "lea") == 0) {
                    reloc_type = SMOF_RELOC_REL32; // LEA often uses PC-relative for symbols
                }
                
                // Calculate relocation offset - for most x86_64 instructions,
                // the displacement field comes after the opcode and ModRM byte
                uint32_t reloc_offset = ctx->code_size;
                
                // For instructions with immediate operands, the relocation typically
                // points to the immediate field, not the instruction start
                if (i > 0) { // If symbol is not the first operand
                    reloc_offset += 1; // Add typical opcode size
                    if (inst.operand_count > 1) {
                        reloc_offset += 1; // Add ModRM byte if multiple operands
                    }
                }
                
                // Create relocation at calculated offset
                int result = format_ops->add_relocation(ctx->output, reloc_offset, 
                                                       symbol_name, reloc_type, 0);
                if (result != 0) {
                    fprintf(stderr, "Warning: Failed to create relocation for symbol '%s'\n", symbol_name);
                } else {
                    // Add symbol to symbol table if not already present
                    if (format_ops->add_symbol) {
                        // Add as undefined symbol (will be resolved by linker)
                        format_ops->add_symbol(ctx->output, symbol_name, 0, 0, 
                                             SMOF_SYM_NOTYPE, SMOF_BIND_GLOBAL);
                    }
                }
            }
            
            // Replace symbol operand with immediate 0 for encoding
            inst.operands[i].type = OPERAND_IMMEDIATE;
            inst.operands[i].value.immediate = 0;
            inst.operands[i].size = 8; // 64-bit placeholder
            
            if (ctx->verbose) {
                printf("Created relocation for symbol '%s', replaced with immediate 0\n", symbol_name);
            }
        }
    }
    
    // Parse instruction using architecture-specific parser to set up encoding
    if (ctx->arch->parse_instruction) {
        int result = ctx->arch->parse_instruction(inst.mnemonic, inst.operands, 
                                                inst.operand_count, &inst);
        if (result != 0) {
            fprintf(stderr, "Error: Failed to parse instruction '%s'\n", inst.mnemonic);
            return -1;
        }
    }
    
    // Ensure we have enough buffer space
    size_t needed_space = ctx->code_size + 16; // Assume max 16 bytes per instruction
    if (needed_space > ctx->code_capacity) {
        size_t new_capacity = ctx->code_capacity * 2;
        while (new_capacity < needed_space) {
            new_capacity *= 2;
        }
        
        uint8_t *new_buffer = realloc(ctx->code_buffer, new_capacity);
        if (!new_buffer) {
            return -1;
        }
        
        ctx->code_buffer = new_buffer;
        ctx->code_capacity = new_capacity;
    }
    
    // Encode instruction using architecture-specific encoder
    uint8_t *encode_buffer = ctx->code_buffer + ctx->code_size;
    size_t encode_length = 0;

    if (ctx->arch->encode_instruction) {
        int result = ctx->arch->encode_instruction(&inst, encode_buffer, &encode_length);
        if (result != 0) {
            fprintf(stderr, "Error: Failed to encode instruction '%s'\n", inst.mnemonic);
            return -1;
        }
        
        // After encoding, add relocations for jump instructions that were identified earlier
        if (has_jump_relocations) {
            // Add relocations for each stored jump symbol
            for (size_t i = 0; i < jump_symbol_count; i++) {
                const char *symbol_name = jump_symbol_names[i];
                if (symbol_name) {
                    // For x86 short jumps (both x86_16 and x86_32), displacement is at offset 1 (after opcode byte)
                    uint32_t displacement_offset = ctx->code_size + 1;  // +1 to skip opcode byte
                    uint32_t reloc_type = RELOC_REL8; // 8-bit displacement
                    
                    // Add relocation for this jump
                    if (codegen_add_relocation(ctx, symbol_name, displacement_offset, 
                                              reloc_type, 0) != 0) {
                        fprintf(stderr, "Warning: Failed to add relocation for jump to '%s'\n", 
                               symbol_name);
                    }
                }
            }
        }
        
        ctx->code_size += encode_length;
        ctx->current_address += encode_length;
        
        if (ctx->verbose) {
            printf("Encoded '%s': ", inst.mnemonic);
            for (size_t i = 0; i < encode_length; i++) {
                printf("%02X ", encode_buffer[i]);
            }
            printf("(%zu bytes)\n", encode_length);
        }
        
        return 0;
    }
    
    fprintf(stderr, "Error: Architecture does not support instruction encoding\n");
    return -1;
}

static int codegen_process_directive(codegen_ctx_t *ctx, ast_node_t *dir_node) {
    if (!ctx || !dir_node || dir_node->type != AST_DIRECTIVE) {
        return -1;
    }
    
    ast_directive_t *ast_dir = (ast_directive_t *)dir_node->data;
    if (!ast_dir) {
        return -1;
    }
    
    const char *directive = ast_dir->name;
    
    if (ctx->verbose) {
        printf("Processing directive: %s\n", directive);
    }
    
    // Handle .section directive with argument
    if (strcmp(directive, ".section") == 0 || strcmp(directive, "section") == 0) {
        if (ast_dir->args && ast_dir->arg_count > 0) {
            const char *section_name = ast_dir->args[0];
            const char *new_section;
            
            if (strcmp(section_name, ".text") == 0 || strcmp(section_name, "text") == 0) {
                new_section = ".text";
            } else if (strcmp(section_name, ".data") == 0 || strcmp(section_name, "data") == 0) {
                new_section = ".data";
            } else if (strcmp(section_name, ".bss") == 0 || strcmp(section_name, "bss") == 0) {
                new_section = ".bss";
            } else {
                new_section = section_name; // Use as-is for custom sections
            }
            
            // Flush current section if switching to a different one
            if (strcmp(ctx->current_section, new_section) != 0) {
                if (flush_current_section(ctx) != 0) {
                    return -1;
                }
                ctx->current_section = new_section;
            }
            
            if (ctx->verbose) {
                printf("Switched to section: %s\n", ctx->current_section);
            }
            return 0;
        }
    }
    
    // Handle section directives
    if (strcmp(directive, ".text") == 0 || strcmp(directive, "text") == 0) {
        ctx->current_section = ".text";
        return 0;
    }
    
    if (strcmp(directive, ".data") == 0 || strcmp(directive, "data") == 0) {
        ctx->current_section = ".data";
        return 0;
    }
    
    if (strcmp(directive, ".bss") == 0 || strcmp(directive, "bss") == 0) {
        ctx->current_section = ".bss";
        return 0;
    }
    
    // Handle data directives
    if (strcmp(directive, ".ascii") == 0 || strcmp(directive, "ascii") == 0) {
        if (ast_dir->args && ast_dir->arg_count > 0) {
            const char *str = ast_dir->args[0];
            size_t str_len = strlen(str);
            
            // Remove quotes if present
            if (str_len >= 2 && str[0] == '"' && str[str_len-1] == '"') {
                str++; // Skip opening quote
                str_len -= 2; // Remove both quotes
            }
            
            // Ensure we have enough buffer space
            size_t needed_space = ctx->code_size + str_len;
            if (needed_space > ctx->code_capacity) {
                size_t new_capacity = ctx->code_capacity * 2;
                while (new_capacity < needed_space) {
                    new_capacity *= 2;
                }
                
                uint8_t *new_buffer = realloc(ctx->code_buffer, new_capacity);
                if (!new_buffer) {
                    return -1;
                }
                
                ctx->code_buffer = new_buffer;
                ctx->code_capacity = new_capacity;
            }
            
            // Copy string data to buffer (without null terminator)
            memcpy(ctx->code_buffer + ctx->code_size, str, str_len);
            ctx->code_size += str_len;
            ctx->current_address += str_len;
            
            if (ctx->verbose) {
                printf("Added .ascii data: %zu bytes\n", str_len);
            }
            
            return 0;
        }
    }
    
    // Handle .asciz and .string directives (null-terminated strings)
    if (strcmp(directive, ".asciz") == 0 || strcmp(directive, "asciz") == 0 ||
        strcmp(directive, ".string") == 0 || strcmp(directive, "string") == 0) {
        if (ast_dir->args && ast_dir->arg_count > 0) {
            const char *str = ast_dir->args[0];
            size_t str_len = strlen(str);
            
            // Remove quotes if present
            if (str_len >= 2 && str[0] == '"' && str[str_len-1] == '"') {
                str++; // Skip opening quote
                str_len -= 2; // Remove both quotes
            }
            
            // Ensure we have enough buffer space (include null terminator)
            size_t needed_space = ctx->code_size + str_len + 1;
            if (needed_space > ctx->code_capacity) {
                size_t new_capacity = ctx->code_capacity * 2;
                while (new_capacity < needed_space) {
                    new_capacity *= 2;
                }
                
                uint8_t *new_buffer = realloc(ctx->code_buffer, new_capacity);
                if (!new_buffer) {
                    return -1;
                }
                
                ctx->code_buffer = new_buffer;
                ctx->code_capacity = new_capacity;
            }
            
            // Copy string data to buffer with null terminator
            memcpy(ctx->code_buffer + ctx->code_size, str, str_len);
            ctx->code_buffer[ctx->code_size + str_len] = '\0';
            ctx->code_size += str_len + 1;
            ctx->current_address += str_len + 1;
            
            if (ctx->verbose) {
                printf("Added %s data: %zu bytes (including null terminator)\n", directive, str_len + 1);
            }
            
            return 0;
        }
    }
    
    // Handle .byte directive
    if (strcmp(directive, ".byte") == 0 || strcmp(directive, "byte") == 0) {
        if (ast_dir->args && ast_dir->arg_count > 0) {
            // Process each byte argument
            for (size_t i = 0; i < ast_dir->arg_count; i++) {
                const char *value_str = ast_dir->args[i];
                if (!value_str) continue;
                
                // Parse byte value (supports hex with 0x prefix)
                char *endptr;
                long value = strtol(value_str, &endptr, 0);
                
                if (endptr == value_str || value < -128 || value > 255) {
                    fprintf(stderr, "Error: Invalid byte value '%s'\n", value_str);
                    return -1;
                }
                
                // Ensure we have enough buffer space
                if (ctx->code_size >= ctx->code_capacity) {
                    size_t new_capacity = ctx->code_capacity * 2;
                    uint8_t *new_buffer = realloc(ctx->code_buffer, new_capacity);
                    if (!new_buffer) {
                        return -1;
                    }
                    ctx->code_buffer = new_buffer;
                    ctx->code_capacity = new_capacity;
                }
                
                // Store byte value
                ctx->code_buffer[ctx->code_size] = (uint8_t)(value & 0xFF);
                ctx->code_size += 1;
                ctx->current_address += 1;
            }
            
            if (ctx->verbose) {
                printf("Added .byte data: %zu bytes\n", ast_dir->arg_count);
            }
            
            return 0;
        }
    }
    
    // Handle .word directive (16-bit values)
    if (strcmp(directive, ".word") == 0 || strcmp(directive, "word") == 0) {
        if (ast_dir->args && ast_dir->arg_count > 0) {
            // Process each word argument
            for (size_t i = 0; i < ast_dir->arg_count; i++) {
                const char *value_str = ast_dir->args[i];
                if (!value_str) continue;
                
                // Parse word value
                char *endptr;
                long value = strtol(value_str, &endptr, 0);
                
                if (endptr == value_str || value < -32768 || value > 65535) {
                    fprintf(stderr, "Error: Invalid word value '%s'\n", value_str);
                    return -1;
                }
                
                // Ensure we have enough buffer space
                size_t needed_space = ctx->code_size + 2;
                if (needed_space > ctx->code_capacity) {
                    size_t new_capacity = ctx->code_capacity * 2;
                    while (new_capacity < needed_space) {
                        new_capacity *= 2;
                    }
                    uint8_t *new_buffer = realloc(ctx->code_buffer, new_capacity);
                    if (!new_buffer) {
                        return -1;
                    }
                    ctx->code_buffer = new_buffer;
                    ctx->code_capacity = new_capacity;
                }
                
                // Store word value (little-endian)
                uint16_t word_val = (uint16_t)(value & 0xFFFF);
                ctx->code_buffer[ctx->code_size] = (uint8_t)(word_val & 0xFF);
                ctx->code_buffer[ctx->code_size + 1] = (uint8_t)((word_val >> 8) & 0xFF);
                ctx->code_size += 2;
                ctx->current_address += 2;
            }
            
            if (ctx->verbose) {
                printf("Added .word data: %zu words (%zu bytes)\n", ast_dir->arg_count, ast_dir->arg_count * 2);
            }
            
            return 0;
        }
    }
    
    // Handle .dword directive (32-bit values)
    if (strcmp(directive, ".dword") == 0 || strcmp(directive, "dword") == 0 ||
        strcmp(directive, ".long") == 0 || strcmp(directive, "long") == 0) {
        if (ast_dir->args && ast_dir->arg_count > 0) {
            // Process each dword argument
            for (size_t i = 0; i < ast_dir->arg_count; i++) {
                const char *value_str = ast_dir->args[i];
                if (!value_str) continue;
                
                // Parse dword value
                char *endptr;
                long long value = strtoll(value_str, &endptr, 0);
                
                if (endptr == value_str || value < -2147483648LL || value > 4294967295LL) {
                    fprintf(stderr, "Error: Invalid dword value '%s'\n", value_str);
                    return -1;
                }
                
                // Ensure we have enough buffer space
                size_t needed_space = ctx->code_size + 4;
                if (needed_space > ctx->code_capacity) {
                    size_t new_capacity = ctx->code_capacity * 2;
                    while (new_capacity < needed_space) {
                        new_capacity *= 2;
                    }
                    uint8_t *new_buffer = realloc(ctx->code_buffer, new_capacity);
                    if (!new_buffer) {
                        return -1;
                    }
                    ctx->code_buffer = new_buffer;
                    ctx->code_capacity = new_capacity;
                }
                
                // Store dword value (little-endian)
                uint32_t dword_val = (uint32_t)(value & 0xFFFFFFFF);
                ctx->code_buffer[ctx->code_size] = (uint8_t)(dword_val & 0xFF);
                ctx->code_buffer[ctx->code_size + 1] = (uint8_t)((dword_val >> 8) & 0xFF);
                ctx->code_buffer[ctx->code_size + 2] = (uint8_t)((dword_val >> 16) & 0xFF);
                ctx->code_buffer[ctx->code_size + 3] = (uint8_t)((dword_val >> 24) & 0xFF);
                ctx->code_size += 4;
                ctx->current_address += 4;
            }
            
            if (ctx->verbose) {
                printf("Added .dword data: %zu dwords (%zu bytes)\n", ast_dir->arg_count, ast_dir->arg_count * 4);
            }
            
            return 0;
        }
    }
    
    // Handle .quad directive (64-bit values)
    if (strcmp(directive, ".quad") == 0 || strcmp(directive, "quad") == 0) {
        if (ast_dir->args && ast_dir->arg_count > 0) {
            // Process each quad argument
            for (size_t i = 0; i < ast_dir->arg_count; i++) {
                const char *value_str = ast_dir->args[i];
                if (!value_str) continue;
                
                // Parse quad value
                char *endptr;
                long long value = strtoll(value_str, &endptr, 0);
                
                if (endptr == value_str) {
                    fprintf(stderr, "Error: Invalid quad value '%s'\n", value_str);
                    return -1;
                }
                
                // Ensure we have enough buffer space
                size_t needed_space = ctx->code_size + 8;
                if (needed_space > ctx->code_capacity) {
                    size_t new_capacity = ctx->code_capacity * 2;
                    while (new_capacity < needed_space) {
                        new_capacity *= 2;
                    }
                    uint8_t *new_buffer = realloc(ctx->code_buffer, new_capacity);
                    if (!new_buffer) {
                        return -1;
                    }
                    ctx->code_buffer = new_buffer;
                    ctx->code_capacity = new_capacity;
                }
                
                // Store quad value (little-endian)
                uint64_t quad_val = (uint64_t)value;
                for (int j = 0; j < 8; j++) {
                    ctx->code_buffer[ctx->code_size + j] = (uint8_t)((quad_val >> (j * 8)) & 0xFF);
                }
                ctx->code_size += 8;
                ctx->current_address += 8;
            }
            
            if (ctx->verbose) {
                printf("Added .quad data: %zu quads (%zu bytes)\n", ast_dir->arg_count, ast_dir->arg_count * 8);
            }
            
            return 0;
        }
    }
    
    // Handle symbol constant definition directives
    if (strcmp(directive, ".equ") == 0 || strcmp(directive, "equ") == 0 ||
        strcmp(directive, ".set") == 0 || strcmp(directive, "set") == 0) {
        if (ast_dir->args && ast_dir->arg_count >= 2) {
            const char *symbol_name = ast_dir->args[0];
            const char *value_str = ast_dir->args[1];
            
            // Parse the value
            char *endptr;
            long long value = strtoll(value_str, &endptr, 0);
            
            if (endptr == value_str) {
                fprintf(stderr, "Error: Invalid value '%s' for %s directive\n", value_str, directive);
                return -1;
            }
            
            // Create or update symbol in symbol table
            if (ctx->symbols) {
                // Check if symbol already exists
                symbol_t *existing = symbol_table_lookup(ctx->symbols, symbol_name);
                if (existing) {
                    if (strcmp(directive, ".set") == 0 || strcmp(directive, "set") == 0) {
                        // .set allows redefinition
                        symbol_set_value(existing, (uint64_t)value);
                        if (ctx->verbose) {
                            printf("Updated symbol '%s' = 0x%llX\n", symbol_name, (unsigned long long)value);
                        }
                    } else {
                        // .equ does not allow redefinition
                        fprintf(stderr, "Error: Symbol '%s' already defined\n", symbol_name);
                        return -1;
                    }
                } else {
                    // Create new constant symbol
                    symbol_t *symbol = symbol_create(symbol_name, SYMBOL_CONSTANT);
                    if (!symbol) {
                        fprintf(stderr, "Error: Failed to create symbol '%s'\n", symbol_name);
                        return -1;
                    }
                    
                    symbol_set_value(symbol, (uint64_t)value);
                    symbol_mark_defined(symbol);
                    
                    if (symbol_table_add(ctx->symbols, symbol) != 0) {
                        symbol_destroy(symbol);
                        fprintf(stderr, "Error: Failed to add symbol '%s'\n", symbol_name);
                        return -1;
                    }
                    
                    if (ctx->verbose) {
                        printf("Defined symbol '%s' = 0x%llX\n", symbol_name, (unsigned long long)value);
                    }
                }
            }
            
            return 0;
        } else {
            fprintf(stderr, "Error: %s directive requires symbol name and value\n", directive);
            return -1;
        }
    }
    
    // Handle symbol visibility directives
    if (strcmp(directive, ".global") == 0 || strcmp(directive, "global") == 0 ||
        strcmp(directive, ".globl") == 0 || strcmp(directive, "globl") == 0) {
        if (ast_dir->args && ast_dir->arg_count > 0) {
            // Process each symbol argument
            for (size_t i = 0; i < ast_dir->arg_count; i++) {
                const char *symbol_name = ast_dir->args[i];
                if (!symbol_name) continue;
                
                if (ctx->symbols) {
                    // Check if symbol already exists
                    symbol_t *existing = symbol_table_lookup(ctx->symbols, symbol_name);
                    if (existing) {
                        // Mark existing symbol as global
                        symbol_set_visibility(existing, VISIBILITY_GLOBAL);
                    } else {
                        // Create forward reference as global symbol
                        symbol_t *symbol = symbol_create(symbol_name, SYMBOL_UNDEFINED);
                        if (!symbol) {
                            fprintf(stderr, "Error: Failed to create global symbol '%s'\n", symbol_name);
                            return -1;
                        }
                        
                        symbol_set_visibility(symbol, VISIBILITY_GLOBAL);
                        
                        if (symbol_table_add(ctx->symbols, symbol) != 0) {
                            symbol_destroy(symbol);
                            fprintf(stderr, "Error: Failed to add global symbol '%s'\n", symbol_name);
                            return -1;
                        }
                    }
                    
                    if (ctx->verbose) {
                        printf("Marked symbol '%s' as global\n", symbol_name);
                    }
                }
            }
            
            return 0;
        }
    }
    
    // Handle external symbol declarations
    if (strcmp(directive, ".extern") == 0 || strcmp(directive, "extern") == 0 ||
        strcmp(directive, ".external") == 0 || strcmp(directive, "external") == 0) {
        if (ast_dir->args && ast_dir->arg_count > 0) {
            // Process each external symbol argument
            for (size_t i = 0; i < ast_dir->arg_count; i++) {
                const char *symbol_name = ast_dir->args[i];
                if (!symbol_name) continue;
                
                if (ctx->symbols) {
                    // Check if symbol already exists
                    symbol_t *existing = symbol_table_lookup(ctx->symbols, symbol_name);
                    if (existing && existing->defined) {
                        fprintf(stderr, "Warning: Symbol '%s' already defined, ignoring .extern\n", symbol_name);
                        continue;
                    }
                    
                    if (!existing) {
                        // Create external symbol
                        symbol_t *symbol = symbol_create(symbol_name, SYMBOL_EXTERNAL);
                        if (!symbol) {
                            fprintf(stderr, "Error: Failed to create external symbol '%s'\n", symbol_name);
                            return -1;
                        }
                        
                        symbol_set_visibility(symbol, VISIBILITY_GLOBAL);
                        
                        if (symbol_table_add(ctx->symbols, symbol) != 0) {
                            symbol_destroy(symbol);
                            fprintf(stderr, "Error: Failed to add external symbol '%s'\n", symbol_name);
                            return -1;
                        }
                    } else {
                        // Update existing undefined symbol to external
                        existing->type = SYMBOL_EXTERNAL;
                        symbol_set_visibility(existing, VISIBILITY_GLOBAL);
                    }
                    
                    if (ctx->verbose) {
                        printf("Declared external symbol '%s'\n", symbol_name);
                    }
                }
            }
            
            return 0;
        }
    }
    
    if (strcmp(directive, ".space") == 0 || strcmp(directive, "space") == 0) {
        if (ast_dir->args && ast_dir->arg_count > 0) {
            // Parse the space size argument
            const char *size_str = ast_dir->args[0];
            size_t space_size = (size_t)strtoul(size_str, NULL, 10);
            
            if (space_size > 0) {
                // Ensure we have enough buffer space
                size_t needed_space = ctx->code_size + space_size;
                if (needed_space > ctx->code_capacity) {
                    size_t new_capacity = ctx->code_capacity * 2;
                    while (new_capacity < needed_space) {
                        new_capacity *= 2;
                    }
                    
                    uint8_t *new_buffer = realloc(ctx->code_buffer, new_capacity);
                    if (!new_buffer) {
                        return -1;
                    }
                    
                    ctx->code_buffer = new_buffer;
                    ctx->code_capacity = new_capacity;
                }
                
                // Fill space with zeros
                memset(ctx->code_buffer + ctx->code_size, 0, space_size);
                ctx->code_size += space_size;
                ctx->current_address += space_size;
                
                if (ctx->verbose) {
                    printf("Added .space: %zu bytes\n", space_size);
                }
                
                return 0;
            }
        }
    }
    
    // Handle alignment directive
    if (strcmp(directive, ".align") == 0 || strcmp(directive, "align") == 0) {
        if (ast_dir->args && ast_dir->arg_count > 0) {
            // Parse alignment value
            const char *align_str = ast_dir->args[0];
            char *endptr;
            long alignment = strtol(align_str, &endptr, 0);
            
            if (endptr == align_str || alignment <= 0 || alignment > 4096) {
                fprintf(stderr, "Error: Invalid alignment value '%s'\n", align_str);
                return -1;
            }
            
            // Check if alignment is power of 2
            if ((alignment & (alignment - 1)) != 0) {
                fprintf(stderr, "Error: Alignment must be a power of 2, got %ld\n", alignment);
                return -1;
            }
            
            // Calculate padding needed
            uint32_t current_offset = ctx->current_address % alignment;
            if (current_offset != 0) {
                size_t padding = alignment - current_offset;
                
                // Ensure we have enough buffer space
                size_t needed_space = ctx->code_size + padding;
                if (needed_space > ctx->code_capacity) {
                    size_t new_capacity = ctx->code_capacity * 2;
                    while (new_capacity < needed_space) {
                        new_capacity *= 2;
                    }
                    uint8_t *new_buffer = realloc(ctx->code_buffer, new_capacity);
                    if (!new_buffer) {
                        return -1;
                    }
                    ctx->code_buffer = new_buffer;
                    ctx->code_capacity = new_capacity;
                }
                
                // Fill with zero bytes for alignment
                memset(ctx->code_buffer + ctx->code_size, 0, padding);
                ctx->code_size += padding;
                ctx->current_address += padding;
                
                if (ctx->verbose) {
                    printf("Added %zu bytes for .align %ld (aligned to 0x%08X)\n", 
                           padding, alignment, ctx->current_address);
                }
            } else if (ctx->verbose) {
                printf("Already aligned to %ld bytes\n", alignment);
            }
            
            return 0;
        } else {
            fprintf(stderr, "Error: .align directive requires alignment value\n");
            return -1;
        }
    }
    
    // Handle origin directive
    if (strcmp(directive, ".org") == 0 || strcmp(directive, "org") == 0) {
        if (ast_dir->args && ast_dir->arg_count > 0) {
            // Parse origin address
            const char *org_str = ast_dir->args[0];
            char *endptr;
            long long origin = strtoll(org_str, &endptr, 0);
            
            if (endptr == org_str || origin < 0) {
                fprintf(stderr, "Error: Invalid origin address '%s'\n", org_str);
                return -1;
            }
            
            uint32_t new_address = (uint32_t)origin;
            
            if (new_address < ctx->current_address) {
                fprintf(stderr, "Error: Origin address 0x%08X is before current address 0x%08X\n", 
                        new_address, ctx->current_address);
                return -1;
            }
            
            if (new_address > ctx->current_address) {
                // Fill gap with zeros
                size_t gap_size = new_address - ctx->current_address;
                
                // Ensure we have enough buffer space
                size_t needed_space = ctx->code_size + gap_size;
                if (needed_space > ctx->code_capacity) {
                    size_t new_capacity = ctx->code_capacity * 2;
                    while (new_capacity < needed_space) {
                        new_capacity *= 2;
                    }
                    uint8_t *new_buffer = realloc(ctx->code_buffer, new_capacity);
                    if (!new_buffer) {
                        return -1;
                    }
                    ctx->code_buffer = new_buffer;
                    ctx->code_capacity = new_capacity;
                }
                
                // Fill gap with zeros
                memset(ctx->code_buffer + ctx->code_size, 0, gap_size);
                ctx->code_size += gap_size;
            }
            
            ctx->current_address = new_address;
            
            if (ctx->verbose) {
                printf("Set origin to 0x%08X\n", ctx->current_address);
            }
            
            return 0;
        } else {
            fprintf(stderr, "Error: .org directive requires address value\n");
            return -1;
        }
    }
    
    // Try architecture-specific directive handler
    if (ctx->arch && ctx->arch->handle_directive) {
        // Extract first argument if available for simple directives
        const char *args = NULL;
        if (ast_dir->arg_count > 0 && ast_dir->args && ast_dir->args[0]) {
            args = ast_dir->args[0];
        }
        
        if (ctx->arch->handle_directive(directive, args) == 0) {
            return 0; // Successfully handled by architecture
        }
    }
    
    // Handle other directives as needed
    if (ctx->verbose) {
        printf("Warning: Ignoring unsupported directive '%s'\n", directive);
    }
    
    return 0;
}

static int codegen_process_label(codegen_ctx_t *ctx, ast_node_t *label_node) {
    if (!ctx || !label_node || label_node->type != AST_LABEL) {
        return -1;
    }
    
    ast_label_t *ast_label = (ast_label_t *)label_node->data;
    if (!ast_label) {
        return -1;
    }
    
    const char *label = ast_label->name;
    
    if (ctx->verbose) {
        printf("Label '%s' at address 0x%08X\n", label, ctx->current_address);
    }
    
    // Add or update symbol in symbol table
    if (ctx->symbols) {
        symbol_t *existing = symbol_table_lookup(ctx->symbols, label);
        
        if (existing) {
            // Update existing symbol with current address
            symbol_set_value(existing, ctx->current_address);
            symbol_mark_defined(existing);
            
            // Update type if needed
            if (strcmp(ctx->current_section, ".text") == 0) {
                existing->type = SYMBOL_LABEL;
            } else {
                existing->type = SYMBOL_VARIABLE;
            }
            
            if (ctx->verbose) {
                printf("Updated symbol '%s' at address 0x%08X\n", label, ctx->current_address);
            }
        } else {
            // Create new symbol
            symbol_t *symbol = symbol_create(label, 
                strcmp(ctx->current_section, ".text") == 0 ? SYMBOL_LABEL : SYMBOL_VARIABLE);
            
            if (!symbol) {
                fprintf(stderr, "Error: Failed to create symbol '%s'\n", label);
                return -1;
            }
            
            symbol_set_value(symbol, ctx->current_address);
            symbol_mark_defined(symbol);
            
            // Default visibility is local, but will be updated by .global if needed
            symbol_set_visibility(symbol, VISIBILITY_LOCAL);
            
            if (symbol_table_add(ctx->symbols, symbol) != 0) {
                symbol_destroy(symbol);
                fprintf(stderr, "Error: Failed to add symbol '%s'\n", label);
                return -1;
            }
            
            if (ctx->verbose) {
                printf("Created symbol '%s' at address 0x%08X\n", label, ctx->current_address);
            }
        }
    }
    
    // Add symbol to SMOF output format
    output_format_ops_t *format_ops = get_output_format(ctx->output->format);
    if (format_ops && format_ops->add_symbol) {
        // Determine symbol type and binding
        uint8_t symbol_type = SMOF_SYM_OBJECT;  // Default to data object
        uint8_t symbol_binding = SMOF_BIND_LOCAL;  // Default to local
        
        // Check if this is a function (in .text section)
        if (strcmp(ctx->current_section, ".text") == 0) {
            symbol_type = SMOF_SYM_FUNC;
        } else if (strcmp(ctx->current_section, ".data") == 0 || 
                   strcmp(ctx->current_section, ".bss") == 0) {
            symbol_type = SMOF_SYM_OBJECT;
        }
        
        // Check symbol table for visibility
        if (ctx->symbols) {
            symbol_t *symbol = symbol_table_lookup(ctx->symbols, label);
            if (symbol && symbol->visibility == VISIBILITY_GLOBAL) {
                symbol_binding = SMOF_BIND_GLOBAL;
            }
        }
        
        // Add symbol to output format
        int result = format_ops->add_symbol(ctx->output, label, ctx->current_address, 
                                          0, /* size - unknown for now */
                                          symbol_type, symbol_binding);
        if (result != 0) {
            if (ctx->verbose) {
                printf("Warning: Failed to add symbol '%s'\n", label);
            }
        } else if (ctx->verbose) {
            printf("Added symbol '%s': address=0x%08X, type=%d, binding=%d\n", 
                   label, ctx->current_address, symbol_type, symbol_binding);
        }
    }
    
    return 0;
}

static int flush_current_section(codegen_ctx_t *ctx) {
    if (!ctx || ctx->code_size == 0) {
        return 0; // Nothing to flush
    }
    
    output_format_ops_t *format_ops = get_output_format(ctx->output->format);
    if (format_ops && format_ops->add_section) {
        // Calculate section start address (current_address - code_size)
        uint32_t section_start_address = ctx->current_address - ctx->code_size;
        
        int result = format_ops->add_section(ctx->output, ctx->current_section, 
                                           ctx->code_buffer, ctx->code_size, 
                                           section_start_address);
        if (result != 0) {
            fprintf(stderr, "Error: Failed to add section '%s'\n", ctx->current_section);
            return -1;
        }
        
        if (ctx->verbose) {
            printf("Flushed section '%s': %zu bytes at 0x%08X\n", 
                   ctx->current_section, ctx->code_size, section_start_address);
        }
        
        // Track total size and reset code buffer for next section
        ctx->total_code_size += ctx->code_size;
        ctx->code_size = 0;
        
        return 0;
    }
    
    return -1;
}

// Relocation functions
int codegen_add_relocation(codegen_ctx_t *ctx, const char *symbol_name, 
                          uint32_t offset, uint32_t reloc_type, int64_t addend) {
    if (!ctx || !symbol_name) {
        return -1;
    }
    
    relocation_t *reloc = malloc(sizeof(relocation_t));
    if (!reloc) {
        return -1;
    }
    
    reloc->symbol_name = strdup(symbol_name);
    reloc->offset = offset;
    reloc->instruction_address = ctx->current_address;  // Current instruction start address
    reloc->reloc_type = reloc_type;
    reloc->addend = addend;
    reloc->next = ctx->relocations;
    ctx->relocations = reloc;
    
    if (ctx->verbose) {
        printf("Added relocation: '%s' at offset 0x%X (instruction addr 0x%X), type %d\n", 
               symbol_name, offset, reloc->instruction_address, reloc_type);
    }
    
    return 0;
}

int codegen_resolve_relocations(codegen_ctx_t *ctx) {
    if (!ctx) {
        return -1;
    }
    
    relocation_t *reloc = ctx->relocations;
    int resolved_count = 0;
    int failed_count = 0;
    
    if (ctx->verbose) {
        printf("=== Resolving relocations ===\n");
        printf("Starting relocation resolution with %s relocations\n", 
               reloc ? "pending" : "no");
    }
    
    while (reloc) {
        if (ctx->verbose) {
            printf("Processing relocation for symbol '%s' at offset 0x%X\n", 
                   reloc->symbol_name, reloc->offset);
        }
        
        // Look up symbol in symbol table
        symbol_t *symbol = symbol_table_lookup(ctx->symbols, reloc->symbol_name);
        if (!symbol || !symbol->defined) {
            if (ctx->verbose) {
                printf("Warning: Unresolved symbol '%s' (symbol %s, defined %s)\n", 
                       reloc->symbol_name,
                       symbol ? "found" : "not found",
                       (symbol && symbol->defined) ? "yes" : "no");
            }
            failed_count++;
            reloc = reloc->next;
            continue;
        }
        
        // Calculate displacement
        int64_t target_address = symbol->value + reloc->addend;
        
        // For relative jumps, displacement is from the address after the current instruction
        // We need to determine the instruction length to calculate the "next instruction" address
        // For now, assume 2-byte jump instructions (opcode + 8-bit displacement)
        uint32_t instruction_length = 2; // TODO: Make this more precise based on instruction type
        int64_t next_instruction_address = reloc->instruction_address + instruction_length;
        int64_t displacement = target_address - next_instruction_address;
        
        if (ctx->verbose) {
            printf("Symbol '%s': target=0x%lX, instruction=0x%X, next=0x%X, displacement=%ld\n",
                   reloc->symbol_name, target_address, reloc->instruction_address, 
                   (uint32_t)next_instruction_address, displacement);
        }
        
        // Apply relocation based on type
        uint8_t *patch_location = ctx->code_buffer + reloc->offset;
        
        if (reloc->reloc_type == RELOC_REL8) {
            // 8-bit relative displacement
            if (displacement < -128 || displacement > 127) {
                if (ctx->verbose) {
                    printf("Error: 8-bit displacement out of range for '%s': %ld\n", 
                           reloc->symbol_name, displacement);
                }
                failed_count++;
            } else {
                *patch_location = (uint8_t)(displacement & 0xFF);
                resolved_count++;
                
                if (ctx->verbose) {
                    printf("Resolved '%s': displacement = %ld (0x%02X)\n", 
                           reloc->symbol_name, displacement, (uint8_t)displacement);
                }
            }
        } else if (reloc->reloc_type == RELOC_REL32) {
            // 32-bit relative displacement
            if (displacement < -2147483648LL || displacement > 2147483647LL) {
                if (ctx->verbose) {
                    printf("Error: 32-bit displacement out of range for '%s': %ld\n", 
                           reloc->symbol_name, displacement);
                }
                failed_count++;
            } else {
                // Little-endian encoding
                patch_location[0] = (uint8_t)(displacement & 0xFF);
                patch_location[1] = (uint8_t)((displacement >> 8) & 0xFF);
                patch_location[2] = (uint8_t)((displacement >> 16) & 0xFF);
                patch_location[3] = (uint8_t)((displacement >> 24) & 0xFF);
                resolved_count++;
                
                if (ctx->verbose) {
                    printf("Resolved '%s': displacement = %ld (0x%08X)\n", 
                           reloc->symbol_name, displacement, (uint32_t)displacement);
                }
            }
        }
        
        reloc = reloc->next;
    }
    
    if (ctx->verbose) {
        printf("Relocation summary: %d resolved, %d failed\n", resolved_count, failed_count);
    }
    
    return failed_count == 0 ? 0 : -1;
}
