#include "../../unity/src/unity.h"
#include "unity_extensions.h"
#include "output_format.h"
#include "formats/com_format.h"
#include <string.h>
#include <stdlib.h>
#include <unistd.h>

// Global test fixtures
output_format_ops_t *com_ops;
output_context_t *ctx;

void setUp(void) {
    com_ops = NULL;
    ctx = NULL;
}

void tearDown(void) {
    if (ctx) {
        // Manual cleanup
        if (ctx->sections) {
            free(ctx->sections);
        }
        free(ctx);
        ctx = NULL;
    }
}

// Helper function to create test output context
static output_context_t *create_test_context(const char *filename) {
    output_context_t *test_ctx = calloc(1, sizeof(output_context_t));
    if (!test_ctx) return NULL;
    
    test_ctx->format = FORMAT_COM;
    test_ctx->filename = filename;
    test_ctx->sections = NULL;
    test_ctx->section_count = 0;
    test_ctx->entry_point = 0x100; // DOS .COM starts at 0x100
    test_ctx->base_address = 0x100;
    test_ctx->verbose = 0;
    
    return test_ctx;
}

// Helper function to add test data to context
static int add_test_section(output_context_t *test_ctx, const char *name, 
                           uint8_t *data, size_t size, uint32_t address) {
    output_section_t *new_sections = realloc(test_ctx->sections, 
                                            (test_ctx->section_count + 1) * sizeof(output_section_t));
    if (!new_sections) return -1;
    
    test_ctx->sections = new_sections;
    output_section_t *section = &test_ctx->sections[test_ctx->section_count];
    
    section->name = name;
    section->data = data; // Store pointer directly (no copy)
    section->size = size;
    section->virtual_address = address;
    section->file_offset = 0;
    section->flags = 0;
    
    test_ctx->section_count++;
    return 0;
}

// ========================================
// DOS .COM FORMAT OPERATIONS TESTS
// ========================================

void test_get_com_format_valid(void) {
    com_ops = get_com_format();
    
    TEST_ASSERT_NOT_NULL(com_ops);
    TEST_ASSERT_NOT_NULL(com_ops->name);
    TEST_ASSERT_NOT_NULL(com_ops->extension);
    TEST_ASSERT_NOT_NULL(com_ops->write_file);
    TEST_ASSERT_NOT_NULL(com_ops->add_section);
    TEST_ASSERT_NOT_NULL(com_ops->cleanup);
    
    TEST_ASSERT_EQUAL_STRING("dos-com", com_ops->name);
    TEST_ASSERT_EQUAL_STRING("com", com_ops->extension);
}

void test_com_ops_consistency(void) {
    output_format_ops_t *ops1 = get_com_format();
    output_format_ops_t *ops2 = get_com_format();
    
    TEST_ASSERT_EQUAL(ops1, ops2); // Should return same instance
}

// ========================================
// DOS .COM WRITE FILE TESTS
// ========================================

void test_com_write_file_null_context(void) {
    com_ops = get_com_format();
    
    int result = com_ops->write_file(NULL);
    TEST_ASSERT_EQUAL(-1, result);
}

void test_com_write_file_null_filename(void) {
    com_ops = get_com_format();
    ctx = create_test_context(NULL);
    
    int result = com_ops->write_file(ctx);
    TEST_ASSERT_EQUAL(-1, result);
}

void test_com_write_file_empty(void) {
    com_ops = get_com_format();
    const char *test_filename = "/tmp/test_empty.com";
    ctx = create_test_context(test_filename);
    
    int result = com_ops->write_file(ctx);
    TEST_ASSERT_EQUAL(0, result);
    
    // Verify empty file was created
    FILE *f = fopen(test_filename, "rb");
    TEST_ASSERT_NOT_NULL(f);
    fseek(f, 0, SEEK_END);
    long size = ftell(f);
    TEST_ASSERT_EQUAL(0, size);
    fclose(f);
    unlink(test_filename);
}

void test_com_write_file_simple_program(void) {
    com_ops = get_com_format();
    const char *test_filename = "/tmp/test_simple.com";
    ctx = create_test_context(test_filename);
    
    // Simple DOS program: MOV AH, 4C; INT 21h (exit)
    uint8_t test_data[] = {0xB4, 0x4C, 0xCD, 0x21};
    add_test_section(ctx, ".text", test_data, sizeof(test_data), 0x100);
    
    int result = com_ops->write_file(ctx);
    TEST_ASSERT_EQUAL(0, result);
    
    // Verify file content
    FILE *f = fopen(test_filename, "rb");
    TEST_ASSERT_NOT_NULL(f);
    
    uint8_t buffer[sizeof(test_data)];
    size_t read_size = fread(buffer, 1, sizeof(buffer), f);
    TEST_ASSERT_EQUAL(sizeof(test_data), read_size);
    TEST_ASSERT_EQUAL_MEMORY(test_data, buffer, sizeof(test_data));
    
    fclose(f);
    unlink(test_filename);
}

void test_com_write_file_hello_world(void) {
    com_ops = get_com_format();
    const char *test_filename = "/tmp/test_hello.com";
    ctx = create_test_context(test_filename);
    
    // Classic "Hello, World!" DOS .COM program
    uint8_t hello_program[] = {
        0xB4, 0x09,             // MOV AH, 09h (display string)
        0xBA, 0x10, 0x01,       // MOV DX, 0x110 (message offset)
        0xCD, 0x21,             // INT 21h (DOS interrupt)
        0xB4, 0x4C,             // MOV AH, 4Ch (exit)
        0xCD, 0x21,             // INT 21h
        'H', 'e', 'l', 'l', 'o', ',', ' ', 'W', 'o', 'r', 'l', 'd', '!', '$'
    };
    
    add_test_section(ctx, ".text", hello_program, sizeof(hello_program), 0x100);
    
    int result = com_ops->write_file(ctx);
    TEST_ASSERT_EQUAL(0, result);
    
    // Verify file size
    FILE *f = fopen(test_filename, "rb");
    TEST_ASSERT_NOT_NULL(f);
    fseek(f, 0, SEEK_END);
    long size = ftell(f);
    TEST_ASSERT_EQUAL(sizeof(hello_program), size);
    fclose(f);
    
    unlink(test_filename);
}

void test_com_write_file_multiple_sections(void) {
    com_ops = get_com_format();
    const char *test_filename = "/tmp/test_multiple.com";
    ctx = create_test_context(test_filename);
    
    uint8_t code[] = {0xB4, 0x4C, 0xCD, 0x21}; // Exit code
    uint8_t data[] = {'H', 'i', '!', '$'};      // Data
    
    add_test_section(ctx, ".text", code, sizeof(code), 0x100);
    add_test_section(ctx, ".data", data, sizeof(data), 0x110);
    
    int result = com_ops->write_file(ctx);
    TEST_ASSERT_EQUAL(0, result);
    
    // Verify total file size (0x110 + 4 - 0x100 = 20 bytes)
    FILE *f = fopen(test_filename, "rb");
    TEST_ASSERT_NOT_NULL(f);
    fseek(f, 0, SEEK_END);
    long size = ftell(f);
    TEST_ASSERT_EQUAL(20, size);
    fclose(f);
    
    unlink(test_filename);
}

void test_com_write_file_size_limit(void) {
    com_ops = get_com_format();
    const char *test_filename = "/tmp/test_size_limit.com";
    ctx = create_test_context(test_filename);
    
    // Create data that exceeds .COM size limit (65280 bytes)
    size_t large_size = 65300;
    uint8_t *large_data = malloc(large_size);
    memset(large_data, 0x90, large_size); // Fill with NOPs
    
    add_test_section(ctx, ".text", large_data, large_size, 0x100);
    
    int result = com_ops->write_file(ctx);
    TEST_ASSERT_EQUAL(-1, result); // Should fail due to size limit
    
    free(large_data);
    // No need to unlink as file creation should have failed
}

void test_com_write_file_gaps_filled(void) {
    com_ops = get_com_format();
    const char *test_filename = "/tmp/test_gaps.com";
    ctx = create_test_context(test_filename);
    
    uint8_t section1[] = {0xAA, 0xBB};
    uint8_t section2[] = {0xCC, 0xDD};
    
    // Create gap: section1 at 0x100, section2 at 0x110
    add_test_section(ctx, ".text1", section1, sizeof(section1), 0x100);
    add_test_section(ctx, ".text2", section2, sizeof(section2), 0x110);
    
    int result = com_ops->write_file(ctx);
    TEST_ASSERT_EQUAL(0, result);
    
    // Verify file content with gaps filled
    FILE *f = fopen(test_filename, "rb");
    TEST_ASSERT_NOT_NULL(f);
    
    uint8_t buffer[18]; // 0x110 + 2 - 0x100 = 18 bytes
    size_t read_size = fread(buffer, 1, sizeof(buffer), f);
    TEST_ASSERT_EQUAL(18, read_size);
    
    // Check first section
    TEST_ASSERT_EQUAL(0xAA, buffer[0]);
    TEST_ASSERT_EQUAL(0xBB, buffer[1]);
    
    // Check gap (should be zeros)
    for (int i = 2; i < 16; i++) {
        TEST_ASSERT_EQUAL(0x00, buffer[i]);
    }
    
    // Check second section
    TEST_ASSERT_EQUAL(0xCC, buffer[16]);
    TEST_ASSERT_EQUAL(0xDD, buffer[17]);
    
    fclose(f);
    unlink(test_filename);
}

void test_com_write_file_verbose_mode(void) {
    com_ops = get_com_format();
    const char *test_filename = "/tmp/test_verbose.com";
    ctx = create_test_context(test_filename);
    ctx->verbose = 1; // Enable verbose mode
    
    uint8_t test_data[] = {0x90};
    add_test_section(ctx, ".text", test_data, sizeof(test_data), 0x100);
    
    int result = com_ops->write_file(ctx);
    TEST_ASSERT_EQUAL(0, result);
    
    unlink(test_filename);
}

// ========================================
// DOS .COM ADD SECTION TESTS
// ========================================

void test_com_add_section_null_context(void) {
    com_ops = get_com_format();
    
    uint8_t data[] = {0x01, 0x02};
    int result = com_ops->add_section(NULL, ".text", data, sizeof(data), 0x100);
    TEST_ASSERT_EQUAL(-1, result);
}

void test_com_add_section_null_name(void) {
    com_ops = get_com_format();
    ctx = create_test_context("test.com");
    
    uint8_t data[] = {0x01, 0x02};
    int result = com_ops->add_section(ctx, NULL, data, sizeof(data), 0x100);
    TEST_ASSERT_EQUAL(-1, result);
}

void test_com_add_section_valid(void) {
    com_ops = get_com_format();
    ctx = create_test_context("test.com");
    
    uint8_t data[] = {0xB4, 0x4C, 0xCD, 0x21}; // DOS exit
    int result = com_ops->add_section(ctx, ".text", data, sizeof(data), 0x100);
    
    TEST_ASSERT_EQUAL(0, result);
    TEST_ASSERT_EQUAL(1, ctx->section_count);
    TEST_ASSERT_EQUAL_STRING(".text", ctx->sections[0].name);
    TEST_ASSERT_EQUAL(sizeof(data), ctx->sections[0].size);
    TEST_ASSERT_EQUAL(0x100, ctx->sections[0].virtual_address);
}

void test_com_add_section_empty_data(void) {
    com_ops = get_com_format();
    ctx = create_test_context("test.com");
    
    int result = com_ops->add_section(ctx, ".bss", NULL, 0, 0x200);
    
    TEST_ASSERT_EQUAL(0, result);
    TEST_ASSERT_EQUAL(1, ctx->section_count);
    TEST_ASSERT_EQUAL_STRING(".bss", ctx->sections[0].name);
    TEST_ASSERT_EQUAL(0, ctx->sections[0].size);
    TEST_ASSERT_EQUAL(0x200, ctx->sections[0].virtual_address);
}

void test_com_add_section_multiple(void) {
    com_ops = get_com_format();
    ctx = create_test_context("test.com");
    
    uint8_t data1[] = {0xB4, 0x4C};  // MOV AH, 4Ch
    uint8_t data2[] = {0xCD, 0x21};  // INT 21h
    
    int result1 = com_ops->add_section(ctx, ".text1", data1, sizeof(data1), 0x100);
    int result2 = com_ops->add_section(ctx, ".text2", data2, sizeof(data2), 0x102);
    
    TEST_ASSERT_EQUAL(0, result1);
    TEST_ASSERT_EQUAL(0, result2);
    TEST_ASSERT_EQUAL(2, ctx->section_count);
}

// ========================================
// DOS .COM CLEANUP TESTS
// ========================================

void test_com_cleanup_null_context(void) {
    com_ops = get_com_format();
    
    // Should not crash with NULL pointer
    com_ops->cleanup(NULL);
    TEST_ASSERT(1); // If we get here, the test passed
}

void test_com_cleanup_valid_context(void) {
    com_ops = get_com_format();
    ctx = create_test_context("test.com");
    
    uint8_t data[] = {0x90}; // nop
    com_ops->add_section(ctx, ".text", data, sizeof(data), 0x100);
    
    // Cleanup should not crash
    com_ops->cleanup(ctx);
    TEST_ASSERT(1); // If we get here, the test passed
}

void test_com_cleanup_empty_context(void) {
    com_ops = get_com_format();
    ctx = create_test_context("test.com");
    
    // Cleanup empty context should not crash
    com_ops->cleanup(ctx);
    TEST_ASSERT(1); // If we get here, the test passed
}

// ========================================
// DOS .COM EDGE CASE TESTS
// ========================================

void test_com_invalid_base_address(void) {
    com_ops = get_com_format();
    const char *test_filename = "/tmp/test_invalid_base.com";
    ctx = create_test_context(test_filename);
    
    uint8_t data[] = {0x90}; // nop
    // Add section below .COM base address (should fail)
    add_test_section(ctx, ".text", data, sizeof(data), 0x50);
    
    int result = com_ops->write_file(ctx);
    TEST_ASSERT_EQUAL(-1, result); // Should correctly reject invalid address
    
    unlink(test_filename);
}

void test_com_16bit_addressing_limits(void) {
    com_ops = get_com_format();
    const char *test_filename = "/tmp/test_16bit_limits.com";
    ctx = create_test_context(test_filename);
    
    uint8_t data[] = {0x90}; // nop
    // Add section at maximum 16-bit address
    add_test_section(ctx, ".text", data, sizeof(data), 0xFFFF);
    
    int result = com_ops->write_file(ctx);
    TEST_ASSERT_EQUAL(0, result);
    
    unlink(test_filename);
}

void test_com_invalid_filename(void) {
    com_ops = get_com_format();
    ctx = create_test_context("/invalid/path/that/does/not/exist/test.com");
    
    uint8_t data[] = {0x90}; // nop
    add_test_section(ctx, ".text", data, sizeof(data), 0x100);
    
    int result = com_ops->write_file(ctx);
    TEST_ASSERT_EQUAL(-1, result); // Should fail due to invalid path
}

void test_com_bootloader_style_program(void) {
    com_ops = get_com_format();
    const char *test_filename = "/tmp/test_bootloader.com";
    ctx = create_test_context(test_filename);
    
    // Simple bootloader-style code
    uint8_t bootloader[] = {
        0xFA,                   // CLI (disable interrupts)
        0xB8, 0x00, 0x13,       // MOV AX, 1300h (VGA mode)
        0xCD, 0x10,             // INT 10h (BIOS video)
        0xEB, 0xFE              // JMP $ (infinite loop)
    };
    
    add_test_section(ctx, ".text", bootloader, sizeof(bootloader), 0x100);
    
    int result = com_ops->write_file(ctx);
    TEST_ASSERT_EQUAL(0, result);
    
    // Verify exact size
    FILE *f = fopen(test_filename, "rb");
    TEST_ASSERT_NOT_NULL(f);
    fseek(f, 0, SEEK_END);
    long size = ftell(f);
    TEST_ASSERT_EQUAL(sizeof(bootloader), size);
    fclose(f);
    
    unlink(test_filename);
}

int main(void) {
    UNITY_BEGIN();
    
    // Format operations tests
    RUN_TEST(test_get_com_format_valid);
    RUN_TEST(test_com_ops_consistency);
    
    // Write file tests
    RUN_TEST(test_com_write_file_null_context);
    RUN_TEST(test_com_write_file_null_filename);
    RUN_TEST(test_com_write_file_empty);
    RUN_TEST(test_com_write_file_simple_program);
    RUN_TEST(test_com_write_file_hello_world);
    RUN_TEST(test_com_write_file_multiple_sections);
    RUN_TEST(test_com_write_file_size_limit);
    RUN_TEST(test_com_write_file_gaps_filled);
    RUN_TEST(test_com_write_file_verbose_mode);
    
    // Add section tests
    RUN_TEST(test_com_add_section_null_context);
    RUN_TEST(test_com_add_section_null_name);
    RUN_TEST(test_com_add_section_valid);
    RUN_TEST(test_com_add_section_empty_data);
    RUN_TEST(test_com_add_section_multiple);
    
    // Cleanup tests
    RUN_TEST(test_com_cleanup_null_context);
    RUN_TEST(test_com_cleanup_valid_context);
    RUN_TEST(test_com_cleanup_empty_context);
    
    // Edge case tests
    RUN_TEST(test_com_invalid_base_address);
    RUN_TEST(test_com_16bit_addressing_limits);
    RUN_TEST(test_com_invalid_filename);
    RUN_TEST(test_com_bootloader_style_program);
    
    return UNITY_END();
}
