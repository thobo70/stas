#include "unity.h"
#include "unity_extensions.h"
#include "output_format.h"
#include "formats/flat_binary.h"
#include <string.h>
#include <stdlib.h>
#include <unistd.h>

// Global test fixtures
output_format_ops_t *flat_binary_ops;
output_context_t *ctx;

void setUp(void) {
    flat_binary_ops = NULL;
    ctx = NULL;
}

void tearDown(void) {
    if (ctx) {
        // Manual cleanup without calling format cleanup
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
    
    test_ctx->format = FORMAT_FLAT_BIN;
    test_ctx->filename = filename;
    test_ctx->sections = NULL;
    test_ctx->section_count = 0;
    test_ctx->entry_point = 0;
    test_ctx->base_address = 0;
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
// FLAT BINARY FORMAT OPERATIONS TESTS
// ========================================

void test_get_flat_binary_format_valid(void) {
    flat_binary_ops = get_flat_binary_format();
    
    TEST_ASSERT_NOT_NULL(flat_binary_ops);
    TEST_ASSERT_NOT_NULL(flat_binary_ops->name);
    TEST_ASSERT_NOT_NULL(flat_binary_ops->extension);
    TEST_ASSERT_NOT_NULL(flat_binary_ops->write_file);
    TEST_ASSERT_NOT_NULL(flat_binary_ops->add_section);
    TEST_ASSERT_NOT_NULL(flat_binary_ops->cleanup);
    
    TEST_ASSERT_EQUAL_STRING("flat-binary", flat_binary_ops->name);
    TEST_ASSERT_EQUAL_STRING("bin", flat_binary_ops->extension);
}

void test_flat_binary_ops_consistency(void) {
    output_format_ops_t *ops1 = get_flat_binary_format();
    output_format_ops_t *ops2 = get_flat_binary_format();
    
    TEST_ASSERT_EQUAL(ops1, ops2); // Should return same instance
}

// ========================================
// FLAT BINARY WRITE FILE TESTS
// ========================================

void test_flat_binary_write_file_null_context(void) {
    flat_binary_ops = get_flat_binary_format();
    
    int result = flat_binary_ops->write_file(NULL);
    TEST_ASSERT_EQUAL(-1, result);
}

void test_flat_binary_write_file_null_filename(void) {
    flat_binary_ops = get_flat_binary_format();
    ctx = create_test_context(NULL);
    
    int result = flat_binary_ops->write_file(ctx);
    TEST_ASSERT_EQUAL(-1, result);
}

void test_flat_binary_write_file_empty(void) {
    flat_binary_ops = get_flat_binary_format();
    const char *test_filename = "/tmp/test_empty.bin";
    ctx = create_test_context(test_filename);
    
    int result = flat_binary_ops->write_file(ctx);
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

void test_flat_binary_write_file_single_section(void) {
    flat_binary_ops = get_flat_binary_format();
    const char *test_filename = "/tmp/test_single.bin";
    ctx = create_test_context(test_filename);
    
    uint8_t test_data[] = {0x48, 0x89, 0xC0, 0x48, 0x89, 0xDB}; // Sample x86-64 code
    add_test_section(ctx, ".text", test_data, sizeof(test_data), 0x1000);
    
    int result = flat_binary_ops->write_file(ctx);
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

void test_flat_binary_write_file_multiple_sections(void) {
    flat_binary_ops = get_flat_binary_format();
    const char *test_filename = "/tmp/test_multiple.bin";
    ctx = create_test_context(test_filename);
    
    uint8_t section1[] = {0x48, 0x89, 0xC0}; // movq %rax, %rax
    uint8_t section2[] = {0x48, 0x89, 0xDB}; // movq %rbx, %rbx
    uint8_t section3[] = {0x01, 0x02, 0x03, 0x04}; // data
    
    add_test_section(ctx, ".text1", section1, sizeof(section1), 0x1000);
    add_test_section(ctx, ".text2", section2, sizeof(section2), 0x1010);
    add_test_section(ctx, ".data", section3, sizeof(section3), 0x2000);
    
    int result = flat_binary_ops->write_file(ctx);
    TEST_ASSERT_EQUAL(0, result);
    
    // Calculate expected total size (0x2000 + 4 - 0x1000 = 0x1004)
    size_t expected_size = 0x1004;
    
    // Verify file size
    FILE *f = fopen(test_filename, "rb");
    TEST_ASSERT_NOT_NULL(f);
    fseek(f, 0, SEEK_END);
    long actual_size = ftell(f);
    TEST_ASSERT_EQUAL(expected_size, actual_size);
    
    fclose(f);
    unlink(test_filename);
}

void test_flat_binary_write_file_gaps_filled_with_zeros(void) {
    flat_binary_ops = get_flat_binary_format();
    const char *test_filename = "/tmp/test_gaps.bin";
    ctx = create_test_context(test_filename);
    
    uint8_t section1[] = {0xAA, 0xBB};
    uint8_t section2[] = {0xCC, 0xDD};
    
    // Create gap: section1 at 0x1000, section2 at 0x1010 (16 bytes apart)
    add_test_section(ctx, ".text1", section1, sizeof(section1), 0x1000);
    add_test_section(ctx, ".text2", section2, sizeof(section2), 0x1010);
    
    int result = flat_binary_ops->write_file(ctx);
    TEST_ASSERT_EQUAL(0, result);
    
    // Verify file content with gaps filled
    FILE *f = fopen(test_filename, "rb");
    TEST_ASSERT_NOT_NULL(f);
    
    uint8_t buffer[18]; // 0x1010 + 2 - 0x1000 = 18 bytes
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

void test_flat_binary_write_file_verbose_mode(void) {
    flat_binary_ops = get_flat_binary_format();
    const char *test_filename = "/tmp/test_verbose.bin";
    ctx = create_test_context(test_filename);
    ctx->verbose = 1; // Enable verbose mode
    
    uint8_t test_data[] = {0x48, 0x89, 0xC0};
    add_test_section(ctx, ".text", test_data, sizeof(test_data), 0x1000);
    
    // Capture stdout to verify verbose output (basic test)
    int result = flat_binary_ops->write_file(ctx);
    TEST_ASSERT_EQUAL(0, result);
    
    unlink(test_filename);
}

// ========================================
// FLAT BINARY ADD SECTION TESTS
// ========================================

void test_flat_binary_add_section_null_context(void) {
    flat_binary_ops = get_flat_binary_format();
    
    uint8_t data[] = {0x01, 0x02};
    int result = flat_binary_ops->add_section(NULL, ".text", data, sizeof(data), 0x1000);
    TEST_ASSERT_EQUAL(-1, result);
}

void test_flat_binary_add_section_null_name(void) {
    flat_binary_ops = get_flat_binary_format();
    ctx = create_test_context("test.bin");
    
    uint8_t data[] = {0x01, 0x02};
    int result = flat_binary_ops->add_section(ctx, NULL, data, sizeof(data), 0x1000);
    TEST_ASSERT_EQUAL(-1, result);
}

void test_flat_binary_add_section_valid(void) {
    flat_binary_ops = get_flat_binary_format();
    ctx = create_test_context("test.bin");
    
    uint8_t data[] = {0x48, 0x89, 0xC0};
    int result = flat_binary_ops->add_section(ctx, ".text", data, sizeof(data), 0x1000);
    
    TEST_ASSERT_EQUAL(0, result);
    TEST_ASSERT_EQUAL(1, ctx->section_count);
    TEST_ASSERT_EQUAL_STRING(".text", ctx->sections[0].name);
    TEST_ASSERT_EQUAL(sizeof(data), ctx->sections[0].size);
    TEST_ASSERT_EQUAL(0x1000, ctx->sections[0].virtual_address);
}

void test_flat_binary_add_section_empty_data(void) {
    flat_binary_ops = get_flat_binary_format();
    ctx = create_test_context("test.bin");
    
    int result = flat_binary_ops->add_section(ctx, ".bss", NULL, 0, 0x2000);
    
    TEST_ASSERT_EQUAL(0, result);
    TEST_ASSERT_EQUAL(1, ctx->section_count);
    TEST_ASSERT_EQUAL_STRING(".bss", ctx->sections[0].name);
    TEST_ASSERT_EQUAL(0, ctx->sections[0].size);
    TEST_ASSERT_EQUAL(0x2000, ctx->sections[0].virtual_address);
}

void test_flat_binary_add_section_multiple(void) {
    flat_binary_ops = get_flat_binary_format();
    ctx = create_test_context("test.bin");
    
    uint8_t data1[] = {0x48, 0x89, 0xC0};
    uint8_t data2[] = {0x48, 0x89, 0xDB};
    
    int result1 = flat_binary_ops->add_section(ctx, ".text", data1, sizeof(data1), 0x1000);
    int result2 = flat_binary_ops->add_section(ctx, ".data", data2, sizeof(data2), 0x2000);
    
    TEST_ASSERT_EQUAL(0, result1);
    TEST_ASSERT_EQUAL(0, result2);
    TEST_ASSERT_EQUAL(2, ctx->section_count);
}

// ========================================
// FLAT BINARY CLEANUP TESTS
// ========================================

void test_flat_binary_cleanup_null_context(void) {
    flat_binary_ops = get_flat_binary_format();
    
    // Should not crash with NULL pointer
    flat_binary_ops->cleanup(NULL);
    TEST_ASSERT(1); // If we get here, the test passed
}

void test_flat_binary_cleanup_valid_context(void) {
    flat_binary_ops = get_flat_binary_format();
    ctx = create_test_context("test.bin");
    
    uint8_t data[] = {0x48, 0x89, 0xC0};
    flat_binary_ops->add_section(ctx, ".text", data, sizeof(data), 0x1000);
    
    // Cleanup should not crash
    flat_binary_ops->cleanup(ctx);
    TEST_ASSERT(1); // If we get here, the test passed
}

void test_flat_binary_cleanup_empty_context(void) {
    flat_binary_ops = get_flat_binary_format();
    ctx = create_test_context("test.bin");
    
    // Cleanup empty context should not crash
    flat_binary_ops->cleanup(ctx);
    TEST_ASSERT(1); // If we get here, the test passed
}

// ========================================
// FLAT BINARY EDGE CASE TESTS
// ========================================

void test_flat_binary_large_address_range(void) {
    flat_binary_ops = get_flat_binary_format();
    const char *test_filename = "/tmp/test_large_range.bin";
    ctx = create_test_context(test_filename);
    
    uint8_t data1[] = {0xAA};
    uint8_t data2[] = {0xBB};
    
    // Large address range to test size calculation
    add_test_section(ctx, ".low", data1, sizeof(data1), 0x1000);
    add_test_section(ctx, ".high", data2, sizeof(data2), 0x10000);
    
    int result = flat_binary_ops->write_file(ctx);
    TEST_ASSERT_EQUAL(0, result);
    
    // Expected size: 0x10000 + 1 - 0x1000 = 0xF001
    FILE *f = fopen(test_filename, "rb");
    TEST_ASSERT_NOT_NULL(f);
    fseek(f, 0, SEEK_END);
    long size = ftell(f);
    TEST_ASSERT_EQUAL(0xF001, size);
    
    fclose(f);
    unlink(test_filename);
}

void test_flat_binary_zero_address(void) {
    flat_binary_ops = get_flat_binary_format();
    const char *test_filename = "/tmp/test_zero_addr.bin";
    ctx = create_test_context(test_filename);
    
    uint8_t data[] = {0xEB, 0xFE}; // jmp $ (infinite loop)
    add_test_section(ctx, ".text", data, sizeof(data), 0x0000);
    
    int result = flat_binary_ops->write_file(ctx);
    TEST_ASSERT_EQUAL(0, result);
    
    // Verify file size and content
    FILE *f = fopen(test_filename, "rb");
    TEST_ASSERT_NOT_NULL(f);
    
    uint8_t buffer[2];
    size_t read_size = fread(buffer, 1, sizeof(buffer), f);
    TEST_ASSERT_EQUAL(2, read_size);
    TEST_ASSERT_EQUAL_MEMORY(data, buffer, sizeof(data));
    
    fclose(f);
    unlink(test_filename);
}

void test_flat_binary_invalid_filename(void) {
    flat_binary_ops = get_flat_binary_format();
    ctx = create_test_context("/invalid/path/that/does/not/exist/test.bin");
    
    uint8_t data[] = {0x90}; // nop
    add_test_section(ctx, ".text", data, sizeof(data), 0x0000);
    
    int result = flat_binary_ops->write_file(ctx);
    TEST_ASSERT_EQUAL(-1, result); // Should fail due to invalid path
}

int main(void) {
    UNITY_BEGIN();
    
    // Format operations tests
    RUN_TEST(test_get_flat_binary_format_valid);
    RUN_TEST(test_flat_binary_ops_consistency);
    
    // Write file tests
    RUN_TEST(test_flat_binary_write_file_null_context);
    RUN_TEST(test_flat_binary_write_file_null_filename);
    RUN_TEST(test_flat_binary_write_file_empty);
    RUN_TEST(test_flat_binary_write_file_single_section);
    RUN_TEST(test_flat_binary_write_file_multiple_sections);
    RUN_TEST(test_flat_binary_write_file_gaps_filled_with_zeros);
    RUN_TEST(test_flat_binary_write_file_verbose_mode);
    
    // Add section tests
    RUN_TEST(test_flat_binary_add_section_null_context);
    RUN_TEST(test_flat_binary_add_section_null_name);
    RUN_TEST(test_flat_binary_add_section_valid);
    RUN_TEST(test_flat_binary_add_section_empty_data);
    RUN_TEST(test_flat_binary_add_section_multiple);
    
    // Cleanup tests
    RUN_TEST(test_flat_binary_cleanup_null_context);
    RUN_TEST(test_flat_binary_cleanup_valid_context);
    RUN_TEST(test_flat_binary_cleanup_empty_context);
    
    // Edge case tests
    RUN_TEST(test_flat_binary_large_address_range);
    RUN_TEST(test_flat_binary_zero_address);
    RUN_TEST(test_flat_binary_invalid_filename);
    
    return UNITY_END();
}
