#define _GNU_SOURCE
#include "unity_extensions.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <stdint.h>
#include <sys/stat.h>
#include <fcntl.h>

// Test resource cleanup (simplified version without symbol table)
void cleanup_test_resources(void* symbol_table, void* temp_file, void* other_resource)
{
    // For now, just handle temp file cleanup
    if (temp_file) {
        char* filename = (char*)temp_file;
        unlink(filename);
        free(filename);
    }
    
    // Handle other resources as needed
    (void)symbol_table; // Suppress unused parameter warning
    (void)other_resource; // Suppress unused parameter warning
}

// Helper for creating temporary test files
char* create_temp_test_file(const char* content, const char* suffix)
{
    char* filename = malloc(256);
    if (!filename) return NULL;
    
    // mkstemp requires template to end with XXXXXX
    snprintf(filename, 256, "/tmp/stas_test_XXXXXX");
    
    int fd = mkstemp(filename);
    if (fd == -1) {
        free(filename);
        return NULL;
    }
    
    if (content) {
        ssize_t result = write(fd, content, strlen(content));
        (void)result; // Suppress unused warning
    }
    
    close(fd);
    
    // If suffix is requested, we could rename the file, but for now just ignore it
    (void)suffix;
    
    return filename;
}

// Verify file exists and has expected content
bool verify_test_file_content(const char* filename, const char* expected_content)
{
    FILE* file = fopen(filename, "r");
    if (!file) return false;
    
    fseek(file, 0, SEEK_END);
    long size = ftell(file);
    fseek(file, 0, SEEK_SET);
    
    char* content = malloc(size + 1);
    if (!content) {
        fclose(file);
        return false;
    }
    
    size_t bytes_read = fread(content, 1, size, file);
    content[size] = '\0';
    fclose(file);
    
    if (bytes_read != (size_t)size) {
        free(content);
        return false;
    }
    
    bool result = strcmp(content, expected_content) == 0;
    free(content);
    return result;
}

// Compare binary data with hex dump utility
bool compare_binary_data(const uint8_t* data1, const uint8_t* data2, size_t size)
{
    if (!data1 || !data2) return false;
    
    for (size_t i = 0; i < size; i++) {
        if (data1[i] != data2[i]) {
            printf("Binary mismatch at offset %zu: expected 0x%02x, got 0x%02x\n", 
                   i, data2[i], data1[i]);
            return false;
        }
    }
    return true;
}

// Print hex dump for debugging
void print_hex_dump(const uint8_t* data, size_t size, const char* label)
{
    if (label) printf("%s:\n", label);
    
    for (size_t i = 0; i < size; i++) {
        if (i % 16 == 0) printf("%04zx: ", i);
        printf("%02x ", data[i]);
        if ((i + 1) % 16 == 0 || i == size - 1) printf("\n");
    }
}
