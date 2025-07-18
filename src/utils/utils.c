#include "utils.h"
#include <stdlib.h>
#include <string.h>
#include <stdint.h>

// String utilities
char *safe_strdup(const char *str) {
    if (!str) return NULL;
    
    size_t len = strlen(str);
    char *copy = malloc(len + 1);
    if (!copy) return NULL;
    
    memcpy(copy, str, len + 1);
    return copy;
}

// Number parsing utilities  
int64_t parse_number_with_base(const char *str) {
    if (!str) return 0;
    
    // Parse different number formats: decimal, hex (0x), octal (0), binary (0b)
    if (strlen(str) > 2 && str[0] == '0' && (str[1] == 'x' || str[1] == 'X')) {
        return strtoll(str, NULL, 16);
    } else if (strlen(str) > 2 && str[0] == '0' && (str[1] == 'b' || str[1] == 'B')) {
        return strtoll(str + 2, NULL, 2);
    } else if (strlen(str) > 1 && str[0] == '0') {
        return strtoll(str, NULL, 8);
    } else {
        return strtoll(str, NULL, 10);
    }
}

// Memory utilities
void *safe_malloc(size_t size) {
    void *ptr = malloc(size);
    if (!ptr && size > 0) {
        // Handle memory allocation failure
        return NULL;
    }
    return ptr;
}

void *safe_calloc(size_t count, size_t size) {
    void *ptr = calloc(count, size);
    if (!ptr && count > 0 && size > 0) {
        // Handle memory allocation failure
        return NULL;
    }
    return ptr;
}

void *safe_realloc(void *ptr, size_t size) {
    void *new_ptr = realloc(ptr, size);
    if (!new_ptr && size > 0) {
        // Handle memory allocation failure
        return NULL;
    }
    return new_ptr;
}

// Legacy functions
int add_numbers(int a, int b) {
    return a + b;
}

int multiply_numbers(int a, int b) {
    return a * b;
}
