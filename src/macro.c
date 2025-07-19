#define _GNU_SOURCE  // For strdup, strndup
#include "macro.h"
#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <ctype.h>

#define MACRO_TABLE_SIZE 256
#define MAX_CONDITIONAL_DEPTH 64
#define MAX_INCLUDE_DEPTH 16

// Hash function for macro names
static size_t hash_string(const char *str) {
    size_t hash = 5381;
    while (*str) {
        hash = ((hash << 5) + hash) + *str++;
    }
    return hash % MACRO_TABLE_SIZE;
}

// Create a new macro processor
macro_processor_t *macro_processor_create(void) {
    macro_processor_t *processor = calloc(1, sizeof(macro_processor_t));
    if (!processor) return NULL;
    
    processor->macro_table = calloc(MACRO_TABLE_SIZE, sizeof(macro_t*));
    if (!processor->macro_table) {
        free(processor);
        return NULL;
    }
    
    processor->table_size = MACRO_TABLE_SIZE;
    
    processor->conditional_stack = malloc(MAX_CONDITIONAL_DEPTH * sizeof(bool));
    if (!processor->conditional_stack) {
        free(processor->macro_table);
        free(processor);
        return NULL;
    }
    processor->conditional_capacity = MAX_CONDITIONAL_DEPTH;
    processor->conditional_depth = 0;
    
    processor->include_stack = malloc(MAX_INCLUDE_DEPTH * sizeof(char*));
    if (!processor->include_stack) {
        free(processor->conditional_stack);
        free(processor->macro_table);
        free(processor);
        return NULL;
    }
    processor->include_capacity = MAX_INCLUDE_DEPTH;
    processor->include_depth = 0;
    
    return processor;
}

// Free a macro
static void macro_free(macro_t *macro) {
    if (!macro) return;
    
    free(macro->name);
    if (macro->parameters) {
        for (size_t i = 0; i < macro->parameter_count; i++) {
            free(macro->parameters[i]);
        }
        free(macro->parameters);
    }
    free(macro->body);
    free(macro);
}

// Destroy macro processor
void macro_processor_destroy(macro_processor_t *processor) {
    if (!processor) return;
    
    // Free all macros
    if (processor->macro_table) {
        for (size_t i = 0; i < processor->table_size; i++) {
            macro_t *macro = processor->macro_table[i];
            while (macro) {
                macro_t *next = macro->next;
                macro_free(macro);
                macro = next;
            }
        }
        free(processor->macro_table);
    }
    
    // Free include stack
    if (processor->include_stack) {
        for (size_t i = 0; i < processor->include_depth; i++) {
            free(processor->include_stack[i]);
        }
        free(processor->include_stack);
    }
    
    free(processor->conditional_stack);
    free(processor->error_message);
    free(processor);
}

// Set error message
static void set_error(macro_processor_t *processor, const char *message) {
    if (!processor) return;
    
    processor->error = true;
    free(processor->error_message);
    processor->error_message = strdup(message);
}

// Define a macro
bool macro_processor_define(macro_processor_t *processor, const char *name, 
                           const char **parameters, size_t parameter_count,
                           const char *body, size_t line, const char *filename) {
    if (!processor || !name || !body) {
        if (processor) set_error(processor, "Invalid parameters for macro definition");
        return false;
    }
    
    // Check if macro already exists
    size_t hash = hash_string(name);
    macro_t *existing = processor->macro_table[hash];
    while (existing) {
        if (strcmp(existing->name, name) == 0) {
            // Redefining macro - remove old definition
            break;
        }
        existing = existing->next;
    }
    
    // Create new macro
    macro_t *macro = calloc(1, sizeof(macro_t));
    if (!macro) {
        set_error(processor, "Memory allocation failed for macro definition");
        return false;
    }
    
    macro->name = strdup(name);
    macro->body = strdup(body);
    macro->line = line;
    macro->filename = filename;
    macro->parameter_count = parameter_count;
    
    if (parameter_count > 0 && parameters) {
        macro->parameters = malloc(parameter_count * sizeof(char*));
        if (!macro->parameters) {
            macro_free(macro);
            set_error(processor, "Memory allocation failed for macro parameters");
            return false;
        }
        
        for (size_t i = 0; i < parameter_count; i++) {
            macro->parameters[i] = strdup(parameters[i]);
            if (!macro->parameters[i]) {
                macro_free(macro);
                set_error(processor, "Memory allocation failed for macro parameter");
                return false;
            }
        }
    }
    
    // Add to hash table
    macro->next = processor->macro_table[hash];
    processor->macro_table[hash] = macro;
    
    return true;
}

// Undefine a macro
bool macro_processor_undefine(macro_processor_t *processor, const char *name) {
    if (!processor || !name) return false;
    
    size_t hash = hash_string(name);
    macro_t **current = &processor->macro_table[hash];
    
    while (*current) {
        if (strcmp((*current)->name, name) == 0) {
            macro_t *to_remove = *current;
            *current = to_remove->next;
            macro_free(to_remove);
            return true;
        }
        current = &(*current)->next;
    }
    
    return false; // Macro not found
}

// Lookup a macro
macro_t *macro_processor_lookup(macro_processor_t *processor, const char *name) {
    if (!processor || !name) return NULL;
    
    size_t hash = hash_string(name);
    macro_t *macro = processor->macro_table[hash];
    
    while (macro) {
        if (strcmp(macro->name, name) == 0) {
            return macro;
        }
        macro = macro->next;
    }
    
    return NULL;
}

// Check if macro is defined
bool macro_processor_is_defined(macro_processor_t *processor, const char *name) {
    return macro_processor_lookup(processor, name) != NULL;
}

// Substitute parameters in macro body
static char *substitute_parameters(const char *body, const char **parameters, 
                                 size_t parameter_count, const char **arguments, 
                                 size_t argument_count) {
    if (parameter_count != argument_count) {
        return NULL; // Parameter count mismatch
    }
    
    size_t body_len = strlen(body);
    size_t result_capacity = body_len * 2; // Initial capacity
    char *result = malloc(result_capacity);
    if (!result) return NULL;
    
    size_t result_len = 0;
    const char *pos = body;
    
    while (*pos) {
        bool found_param = false;
        
        // Check if current position starts a parameter
        for (size_t i = 0; i < parameter_count; i++) {
            size_t param_len = strlen(parameters[i]);
            if (strncmp(pos, parameters[i], param_len) == 0) {
                // Check that it's a complete word (not part of another identifier)
                if (pos == body || !isalnum(pos[-1])) {
                    if (!isalnum(pos[param_len]) && pos[param_len] != '_') {
                        // Substitute with argument
                        size_t arg_len = strlen(arguments[i]);
                        
                        // Ensure result buffer is large enough
                        while (result_len + arg_len >= result_capacity) {
                            result_capacity *= 2;
                            char *new_result = realloc(result, result_capacity);
                            if (!new_result) {
                                free(result);
                                return NULL;
                            }
                            result = new_result;
                        }
                        
                        strcpy(result + result_len, arguments[i]);
                        result_len += arg_len;
                        pos += param_len;
                        found_param = true;
                        break;
                    }
                }
            }
        }
        
        if (!found_param) {
            // Copy character as-is
            if (result_len >= result_capacity - 1) {
                result_capacity *= 2;
                char *new_result = realloc(result, result_capacity);
                if (!new_result) {
                    free(result);
                    return NULL;
                }
                result = new_result;
            }
            
            result[result_len++] = *pos++;
        }
    }
    
    result[result_len] = '\0';
    return result;
}

// Expand a macro
macro_expansion_t macro_processor_expand(macro_processor_t *processor, 
                                       const char *name, const char **arguments, 
                                       size_t argument_count) {
    macro_expansion_t result = {0};
    
    if (!processor || !name) {
        result.error_message = strdup("Invalid parameters for macro expansion");
        return result;
    }
    
    macro_t *macro = macro_processor_lookup(processor, name);
    if (!macro) {
        result.error_message = strdup("Macro not found");
        return result;
    }
    
    if (macro->parameter_count != argument_count) {
        char error_buf[256];
        snprintf(error_buf, sizeof(error_buf), 
                "Macro '%s' expects %zu arguments, got %zu", 
                name, macro->parameter_count, argument_count);
        result.error_message = strdup(error_buf);
        return result;
    }
    
    if (macro->parameter_count == 0) {
        // Simple macro without parameters
        result.expanded_text = strdup(macro->body);
        result.success = (result.expanded_text != NULL);
    } else {
        // Macro with parameters - substitute
        result.expanded_text = substitute_parameters(macro->body, 
                                                   (const char**)macro->parameters,
                                                   macro->parameter_count,
                                                   arguments, argument_count);
        result.success = (result.expanded_text != NULL);
    }
    
    if (!result.success && !result.error_message) {
        result.error_message = strdup("Memory allocation failed during macro expansion");
    }
    
    return result;
}

// Expand macros in a line of text
char *macro_processor_expand_line(macro_processor_t *processor, const char *line) {
    if (!processor || !line) return NULL;
    
    // For now, implement simple macro expansion
    // TODO: Add more sophisticated parsing for macro calls with parameters
    
    // Look for simple macro names (no parameters for now)
    size_t line_len = strlen(line);
    size_t result_capacity = line_len * 2;
    char *result = malloc(result_capacity);
    if (!result) return NULL;
    
    size_t result_len = 0;
    const char *pos = line;
    
    while (*pos) {
        if (isalpha(*pos) || *pos == '_') {
            // Found potential identifier
            const char *id_start = pos;
            while (isalnum(*pos) || *pos == '_') pos++;
            
            size_t id_len = pos - id_start;
            char *identifier = strndup(id_start, id_len);
            if (!identifier) {
                free(result);
                return NULL;
            }
            
            macro_t *macro = macro_processor_lookup(processor, identifier);
            if (macro && macro->parameter_count == 0) {
                // Simple macro expansion
                size_t body_len = strlen(macro->body);
                
                // Ensure result buffer is large enough
                while (result_len + body_len >= result_capacity) {
                    result_capacity *= 2;
                    char *new_result = realloc(result, result_capacity);
                    if (!new_result) {
                        free(identifier);
                        free(result);
                        return NULL;
                    }
                    result = new_result;
                }
                
                strcpy(result + result_len, macro->body);
                result_len += body_len;
            } else {
                // Copy identifier as-is
                while (result_len + id_len >= result_capacity) {
                    result_capacity *= 2;
                    char *new_result = realloc(result, result_capacity);
                    if (!new_result) {
                        free(identifier);
                        free(result);
                        return NULL;
                    }
                    result = new_result;
                }
                
                strncpy(result + result_len, id_start, id_len);
                result_len += id_len;
            }
            
            free(identifier);
        } else {
            // Copy character as-is
            if (result_len >= result_capacity - 1) {
                result_capacity *= 2;
                char *new_result = realloc(result, result_capacity);
                if (!new_result) {
                    free(result);
                    return NULL;
                }
                result = new_result;
            }
            
            result[result_len++] = *pos++;
        }
    }
    
    result[result_len] = '\0';
    return result;
}

// Conditional compilation functions
bool macro_processor_ifdef(macro_processor_t *processor, const char *name) {
    if (!processor || processor->conditional_depth >= processor->conditional_capacity) {
        if (processor) set_error(processor, "Maximum conditional depth exceeded");
        return false;
    }
    
    bool is_defined = macro_processor_is_defined(processor, name);
    processor->conditional_stack[processor->conditional_depth++] = is_defined;
    
    return true;
}

bool macro_processor_ifndef(macro_processor_t *processor, const char *name) {
    if (!processor || processor->conditional_depth >= processor->conditional_capacity) {
        if (processor) set_error(processor, "Maximum conditional depth exceeded");
        return false;
    }
    
    bool is_defined = macro_processor_is_defined(processor, name);
    processor->conditional_stack[processor->conditional_depth++] = !is_defined;
    
    return true;
}

bool macro_processor_else(macro_processor_t *processor) {
    if (!processor || processor->conditional_depth == 0) {
        if (processor) set_error(processor, "#else without matching #ifdef/#ifndef");
        return false;
    }
    
    // Flip the condition
    processor->conditional_stack[processor->conditional_depth - 1] = 
        !processor->conditional_stack[processor->conditional_depth - 1];
    
    return true;
}

bool macro_processor_endif(macro_processor_t *processor) {
    if (!processor || processor->conditional_depth == 0) {
        if (processor) set_error(processor, "#endif without matching #ifdef/#ifndef");
        return false;
    }
    
    processor->conditional_depth--;
    return true;
}

bool macro_processor_should_include_line(macro_processor_t *processor) {
    if (!processor) return true;
    
    // Check all conditional levels - all must be true to include line
    for (size_t i = 0; i < processor->conditional_depth; i++) {
        if (!processor->conditional_stack[i]) {
            return false;
        }
    }
    
    return true;
}

// Include file handling
bool macro_processor_include_file(macro_processor_t *processor, const char *filename) {
    if (!processor || !filename || processor->include_depth >= processor->include_capacity) {
        if (processor) set_error(processor, "Maximum include depth exceeded");
        return false;
    }
    
    processor->include_stack[processor->include_depth] = strdup(filename);
    if (!processor->include_stack[processor->include_depth]) {
        set_error(processor, "Memory allocation failed for include filename");
        return false;
    }
    
    processor->include_depth++;
    return true;
}

bool macro_processor_end_include(macro_processor_t *processor) {
    if (!processor || processor->include_depth == 0) {
        if (processor) set_error(processor, "No include file to end");
        return false;
    }
    
    processor->include_depth--;
    free(processor->include_stack[processor->include_depth]);
    processor->include_stack[processor->include_depth] = NULL;
    
    return true;
}

// Error handling
bool macro_processor_has_error(const macro_processor_t *processor) {
    return processor ? processor->error : true;
}

const char *macro_processor_get_error(const macro_processor_t *processor) {
    return processor ? processor->error_message : "Invalid processor";
}

// Free macro expansion result
void macro_expansion_free(macro_expansion_t *expansion) {
    if (!expansion) return;
    
    free(expansion->expanded_text);
    free(expansion->error_message);
    expansion->expanded_text = NULL;
    expansion->error_message = NULL;
    expansion->success = false;
}
