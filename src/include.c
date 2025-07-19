#define _GNU_SOURCE
#include "include.h"
#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <sys/stat.h>
#include <limits.h>
#include <libgen.h>

// Include processor structure
struct include_processor {
    char **include_paths;     // Search paths for include files
    size_t path_count;        // Number of include paths
    size_t path_capacity;     // Capacity of paths array
    char *error_message;      // Error message
    bool error;               // Error flag
};

// Create include processor
include_processor_t *include_processor_create(void) {
    include_processor_t *processor = calloc(1, sizeof(include_processor_t));
    if (!processor) return NULL;
    
    processor->path_capacity = 16;
    processor->include_paths = malloc(processor->path_capacity * sizeof(char*));
    if (!processor->include_paths) {
        free(processor);
        return NULL;
    }
    
    // Add default include paths
    processor->include_paths[0] = strdup(".");  // Current directory
    processor->path_count = 1;
    
    return processor;
}

// Destroy include processor
void include_processor_destroy(include_processor_t *processor) {
    if (!processor) return;
    
    if (processor->include_paths) {
        for (size_t i = 0; i < processor->path_count; i++) {
            free(processor->include_paths[i]);
        }
        free(processor->include_paths);
    }
    
    free(processor->error_message);
    free(processor);
}

// Set error message
static void set_include_error(include_processor_t *processor, const char *message) {
    if (!processor) return;
    
    processor->error = true;
    free(processor->error_message);
    processor->error_message = strdup(message);
}

// Check if file exists
static bool file_exists(const char *filepath) {
    struct stat st;
    return stat(filepath, &st) == 0 && S_ISREG(st.st_mode);
}

// Read entire file into string
static char *read_file_contents(const char *filepath) {
    FILE *file = fopen(filepath, "r");
    if (!file) return NULL;
    
    // Get file size
    if (fseek(file, 0, SEEK_END) != 0) {
        fclose(file);
        return NULL;
    }
    
    long size = ftell(file);
    if (size < 0) {
        fclose(file);
        return NULL;
    }
    
    if (fseek(file, 0, SEEK_SET) != 0) {
        fclose(file);
        return NULL;
    }
    
    // Allocate buffer
    char *content = malloc(size + 1);
    if (!content) {
        fclose(file);
        return NULL;
    }
    
    // Read file content
    size_t bytes_read = fread(content, 1, size, file);
    fclose(file);
    
    if (bytes_read != (size_t)size) {
        free(content);
        return NULL;
    }
    
    content[size] = '\0';
    return content;
}

// Find include file in search paths
static char *find_include_file(include_processor_t *processor, 
                              const char *filename, 
                              const char *current_dir) {
    char filepath[PATH_MAX];
    
    // First, try relative to current directory if specified
    if (current_dir) {
        snprintf(filepath, sizeof(filepath), "%s/%s", current_dir, filename);
        if (file_exists(filepath)) {
            return strdup(filepath);
        }
    }
    
    // Try each include path
    for (size_t i = 0; i < processor->path_count; i++) {
        snprintf(filepath, sizeof(filepath), "%s/%s", processor->include_paths[i], filename);
        if (file_exists(filepath)) {
            return strdup(filepath);
        }
    }
    
    return NULL; // File not found
}

// Process include file
char *include_processor_read_file(include_processor_t *processor, 
                                 const char *filename,
                                 const char *current_dir) {
    if (!processor || !filename) {
        if (processor) set_include_error(processor, "Invalid parameters for include processing");
        return NULL;
    }
    
    // Clear previous error
    processor->error = false;
    free(processor->error_message);
    processor->error_message = NULL;
    
    // Find the include file
    char *filepath = find_include_file(processor, filename, current_dir);
    if (!filepath) {
        char error_msg[512];
        snprintf(error_msg, sizeof(error_msg), "Include file not found: %s", filename);
        set_include_error(processor, error_msg);
        return NULL;
    }
    
    // Read file contents
    char *content = read_file_contents(filepath);
    if (!content) {
        char error_msg[512];
        snprintf(error_msg, sizeof(error_msg), "Failed to read include file: %s", filepath);
        set_include_error(processor, error_msg);
        free(filepath);
        return NULL;
    }
    
    free(filepath);
    return content;
}

// Error handling
bool include_processor_has_error(const include_processor_t *processor) {
    return processor ? processor->error : true;
}

const char *include_processor_get_error(const include_processor_t *processor) {
    return processor ? processor->error_message : "Invalid processor";
}
