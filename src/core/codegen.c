/*
 * STAS Code Generation Implementation
 * Converts parsed AST to machine code using architecture-specific encoders
 */

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

codegen_ctx_t *codegen_create(arch_ops_t *arch, output_context_t *output) {
    if (!arch || !output) {
        return NULL;
    }
    
    codegen_ctx_t *ctx = calloc(1, sizeof(codegen_ctx_t));
    if (!ctx) {
        return NULL;
    }
    
    ctx->arch = arch;
    ctx->output = output;
    ctx->current_address = output->base_address;
    ctx->current_section = ".text";
    ctx->verbose = output->verbose;
    ctx->total_code_size = 0; // Track total bytes generated
    
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
    
    // Try architecture-specific directive handler
    if (ctx->arch && ctx->arch->handle_directive) {
        const char *args = NULL; // TODO: Extract args from AST if needed
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
        
        // TODO: Check for .global directive to set SMOF_BIND_GLOBAL
        // For now, assume _start is global
        if (strcmp(label, "_start") == 0) {
            symbol_binding = SMOF_BIND_GLOBAL;
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
