/* Include processor for STAS assembler */
#ifndef INCLUDE_H
#define INCLUDE_H

#include <stddef.h>
#include <stdbool.h>

// Include processor functions
typedef struct include_processor include_processor_t;

// Create/destroy include processor
include_processor_t *include_processor_create(void);
void include_processor_destroy(include_processor_t *processor);

// Process include file
char *include_processor_read_file(include_processor_t *processor, 
                                 const char *filename,
                                 const char *current_dir);

// Error handling  
bool include_processor_has_error(const include_processor_t *processor);
const char *include_processor_get_error(const include_processor_t *processor);

#endif // INCLUDE_H
