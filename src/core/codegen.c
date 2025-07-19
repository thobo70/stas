/*
 * STAS Code Generation Implementation
 * Converts parsed AST to machine code using architecture-specific encoders
 */

#include "codegen.h"
#include "parser.h"
#include "output_format.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

// Forward declarations
static int codegen_process_instruction(codegen_ctx_t *ctx, ast_node_t *inst_node);
static int codegen_process_directive(codegen_ctx_t *ctx, ast_node_t *dir_node);
static int codegen_process_label(codegen_ctx_t *ctx, ast_node_t *label_node);

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
    
    // Add generated code to output format
    if (ctx->code_size > 0) {
        output_format_ops_t *format_ops = get_output_format(ctx->output->format);
        if (format_ops && format_ops->add_section) {
            int result = format_ops->add_section(ctx->output, ctx->current_section, 
                                               ctx->code_buffer, ctx->code_size, 
                                               ctx->current_address);
            if (result != 0) {
                fprintf(stderr, "Error: Failed to add code section\n");
                return -1;
            }
            
            if (ctx->verbose) {
                printf("Added section '%s': %zu bytes at 0x%08X\n", 
                       ctx->current_section, ctx->code_size, ctx->current_address);
            }
        }
    }
    
    if (ctx->verbose) {
        printf("Code generation complete: %zu bytes generated\n", ctx->code_size);
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
    
    // Labels don't generate code, they just mark positions
    // In a full implementation, we'd update the symbol table here
    
    return 0;
}
