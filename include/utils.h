/*
 * STAS Utility Functions Header
 * Common utility functions for the STIX Modular Assembler
 */

#ifndef UTILS_H
#define UTILS_H

#include <stddef.h>
#include <stdint.h>

//=============================================================================
// String Utilities
//=============================================================================

// Safe string duplication
char *safe_strdup(const char *s);

//=============================================================================
// Number Parsing Utilities
//=============================================================================

// Parse number with support for different bases (decimal, hex, octal, binary)
int64_t parse_number_with_base(const char *num_str);

//=============================================================================
// Memory Utilities
//=============================================================================

// Safe memory allocation with error checking
void *safe_malloc(size_t size);
void *safe_calloc(size_t nmemb, size_t size);
void *safe_realloc(void *ptr, size_t size);

// Legacy function declarations (to be deprecated)
int add_numbers(int a, int b);
int multiply_numbers(int a, int b);

#endif // UTILS_H
