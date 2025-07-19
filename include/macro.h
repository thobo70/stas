#ifndef MACRO_H
#define MACRO_H

#include <stddef.h>
#include <stdbool.h>

// Macro definition structure
typedef struct macro {
    char *name;                    // Macro name
    char **parameters;             // Parameter names (NULL if no parameters)
    size_t parameter_count;        // Number of parameters
    char *body;                    // Macro body text
    size_t line;                   // Line number where defined
    const char *filename;          // File where defined
    struct macro *next;            // Next macro in hash table bucket
} macro_t;

// Macro processor state
typedef struct macro_processor {
    macro_t **macro_table;         // Hash table for macros
    size_t table_size;             // Size of hash table
    bool *conditional_stack;       // Stack for conditional compilation
    size_t conditional_depth;      // Current conditional depth
    size_t conditional_capacity;   // Capacity of conditional stack
    char **include_stack;          // Stack of included file names
    size_t include_depth;          // Current include depth
    size_t include_capacity;       // Capacity of include stack
    char *error_message;           // Error message
    bool error;                    // Error flag
} macro_processor_t;

// Macro expansion result
typedef struct {
    char *expanded_text;           // Expanded text (must be freed)
    bool success;                  // Whether expansion succeeded
    char *error_message;           // Error message if failed
} macro_expansion_t;

// Macro processor functions
macro_processor_t *macro_processor_create(void);
void macro_processor_destroy(macro_processor_t *processor);

// Macro definition and lookup
bool macro_processor_define(macro_processor_t *processor, const char *name, 
                           const char **parameters, size_t parameter_count,
                           const char *body, size_t line, const char *filename);
bool macro_processor_undefine(macro_processor_t *processor, const char *name);
macro_t *macro_processor_lookup(macro_processor_t *processor, const char *name);
bool macro_processor_is_defined(macro_processor_t *processor, const char *name);

// Macro expansion
macro_expansion_t macro_processor_expand(macro_processor_t *processor, 
                                       const char *name, const char **arguments, 
                                       size_t argument_count);
char *macro_processor_expand_line(macro_processor_t *processor, const char *line);

// Conditional compilation
bool macro_processor_ifdef(macro_processor_t *processor, const char *name);
bool macro_processor_ifndef(macro_processor_t *processor, const char *name);
bool macro_processor_else(macro_processor_t *processor);
bool macro_processor_endif(macro_processor_t *processor);
bool macro_processor_should_include_line(macro_processor_t *processor);

// Include file handling
bool macro_processor_include_file(macro_processor_t *processor, const char *filename);
bool macro_processor_end_include(macro_processor_t *processor);

// Error handling
bool macro_processor_has_error(const macro_processor_t *processor);
const char *macro_processor_get_error(const macro_processor_t *processor);

// Utility functions
void macro_expansion_free(macro_expansion_t *expansion);

#endif // MACRO_H
