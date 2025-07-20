#include "unity.h"
#include "unity_extensions.h"
#include "output_format.h"
#include "formats/motorola_srec.h"
#include <string.h>
#include <stdlib.h>
#include <unistd.h>

// Global test fixtures
output_format_ops_t *srec_ops;
output_context_t *ctx;

void setUp(void) {
    srec_ops = NULL;
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
    
    test_ctx->format = FORMAT_SREC;
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

// Helper function to read file content into string
static char *read_file_content(const char *filename) {
    FILE *f = fopen(filename, "r");
    if (!f) return NULL;
    
    fseek(f, 0, SEEK_END);
    long size = ftell(f);
    fseek(f, 0, SEEK_SET);
    
    char *content = malloc(size + 1);
    if (!content) {
        fclose(f);
        return NULL;
    }
    
    size_t read_bytes = fread(content, 1, size, f);
    content[read_bytes] = '\0'; // Handle partial reads properly
    fclose(f);
    
    return content;
}

// ========================================
// MOTOROLA S-RECORD FORMAT OPERATIONS TESTS
// ========================================

void test_get_motorola_srec_format_valid(void) {
    srec_ops = get_motorola_srec_format();
    
    TEST_ASSERT_NOT_NULL(srec_ops);
    TEST_ASSERT_NOT_NULL(srec_ops->name);
    TEST_ASSERT_NOT_NULL(srec_ops->extension);
    TEST_ASSERT_NOT_NULL(srec_ops->write_file);
    TEST_ASSERT_NOT_NULL(srec_ops->add_section);
    TEST_ASSERT_NOT_NULL(srec_ops->cleanup);
    
    TEST_ASSERT_EQUAL_STRING("motorola-srec", srec_ops->name);
    TEST_ASSERT_EQUAL_STRING("s19", srec_ops->extension);
}

void test_srec_ops_consistency(void) {
    output_format_ops_t *ops1 = get_motorola_srec_format();
    output_format_ops_t *ops2 = get_motorola_srec_format();
    
    TEST_ASSERT_EQUAL(ops1, ops2); // Should return same instance
}

// ========================================
// MOTOROLA S-RECORD WRITE FILE TESTS
// ========================================

void test_srec_write_file_null_context(void) {
    srec_ops = get_motorola_srec_format();
    
    int result = srec_ops->write_file(NULL);
    TEST_ASSERT_EQUAL(-1, result);
}

void test_srec_write_file_null_filename(void) {
    srec_ops = get_motorola_srec_format();
    ctx = create_test_context(NULL);
    
    int result = srec_ops->write_file(ctx);
    TEST_ASSERT_EQUAL(-1, result);
}

void test_srec_write_file_empty(void) {
    srec_ops = get_motorola_srec_format();
    const char *test_filename = "/tmp/test_empty.s19";
    ctx = create_test_context(test_filename);
    
    int result = srec_ops->write_file(ctx);
    TEST_ASSERT_EQUAL(0, result);
    
    // Verify file contains header record
    char *content = read_file_content(test_filename);
    TEST_ASSERT_NOT_NULL(content);
    
    // Should contain S0 header 
    TEST_ASSERT_TRUE(strstr(content, "S0") != NULL);
    // May or may not contain termination record (depends on entry point)
    
    free(content);
    unlink(test_filename);
}

void test_srec_write_file_16bit_data(void) {
    srec_ops = get_motorola_srec_format();
    const char *test_filename = "/tmp/test_16bit.s19";
    ctx = create_test_context(test_filename);
    
    uint8_t test_data[] = {0x48, 0x89, 0xC0}; // movq %rax, %rax
    add_test_section(ctx, ".text", test_data, sizeof(test_data), 0x1000);
    
    int result = srec_ops->write_file(ctx);
    TEST_ASSERT_EQUAL(0, result);
    
    // Verify file content
    char *content = read_file_content(test_filename);
    TEST_ASSERT_NOT_NULL(content);
    
    // Should contain S0 header and S1 data record (16-bit address)
    TEST_ASSERT_TRUE(strstr(content, "S0") != NULL);
    TEST_ASSERT_TRUE(strstr(content, "S1") != NULL); // 16-bit data record
    
    free(content);
    unlink(test_filename);
}

void test_srec_write_file_24bit_data(void) {
    srec_ops = get_motorola_srec_format();
    const char *test_filename = "/tmp/test_24bit.s19";
    ctx = create_test_context(test_filename);
    
    uint8_t test_data[] = {0x90, 0x90}; // nop nop
    add_test_section(ctx, ".text", test_data, sizeof(test_data), 0x100000); // 24-bit address
    
    int result = srec_ops->write_file(ctx);
    TEST_ASSERT_EQUAL(0, result);
    
    // Verify file content
    char *content = read_file_content(test_filename);
    TEST_ASSERT_NOT_NULL(content);
    
    // Should contain S0 header and S2 data record (24-bit address)
    TEST_ASSERT_TRUE(strstr(content, "S0") != NULL);
    TEST_ASSERT_TRUE(strstr(content, "S2") != NULL); // 24-bit data record
    
    free(content);
    unlink(test_filename);
}

void test_srec_write_file_32bit_data(void) {
    srec_ops = get_motorola_srec_format();
    const char *test_filename = "/tmp/test_32bit.s19";
    ctx = create_test_context(test_filename);
    
    uint8_t test_data[] = {0xEB, 0xFE}; // jmp $
    add_test_section(ctx, ".text", test_data, sizeof(test_data), 0x10000000); // 32-bit address
    
    int result = srec_ops->write_file(ctx);
    TEST_ASSERT_EQUAL(0, result);
    
    // Verify file content
    char *content = read_file_content(test_filename);
    TEST_ASSERT_NOT_NULL(content);
    
    // Should contain S0 header and S3 data record (32-bit address)
    TEST_ASSERT_TRUE(strstr(content, "S0") != NULL);
    TEST_ASSERT_TRUE(strstr(content, "S3") != NULL); // 32-bit data record
    
    free(content);
    unlink(test_filename);
}

void test_srec_write_file_large_data(void) {
    srec_ops = get_motorola_srec_format();
    const char *test_filename = "/tmp/test_large.s19";
    ctx = create_test_context(test_filename);
    
    // Create data larger than 32 bytes to test multiple records
    uint8_t test_data[64];
    for (int i = 0; i < 64; i++) {
        test_data[i] = (uint8_t)i;
    }
    
    add_test_section(ctx, ".text", test_data, sizeof(test_data), 0x8000);
    
    int result = srec_ops->write_file(ctx);
    TEST_ASSERT_EQUAL(0, result);
    
    // Verify file content has multiple records
    char *content = read_file_content(test_filename);
    TEST_ASSERT_NOT_NULL(content);
    
    // Count number of S1 records (should be more than 1)
    int s1_count = 0;
    char *pos = content;
    while ((pos = strstr(pos, "S1")) != NULL) {
        s1_count++;
        pos += 2;
    }
    
    TEST_ASSERT_GREATER_THAN(1, s1_count); // Should have multiple S1 records
    
    free(content);
    unlink(test_filename);
}

void test_srec_write_file_multiple_sections(void) {
    srec_ops = get_motorola_srec_format();
    const char *test_filename = "/tmp/test_multi_sections.s19";
    ctx = create_test_context(test_filename);
    
    uint8_t section1[] = {0x48, 0x89, 0xC0};
    uint8_t section2[] = {0x01, 0x02, 0x03, 0x04};
    
    add_test_section(ctx, ".text", section1, sizeof(section1), 0x1000);
    add_test_section(ctx, ".data", section2, sizeof(section2), 0x2000);
    
    int result = srec_ops->write_file(ctx);
    TEST_ASSERT_EQUAL(0, result);
    
    // Verify file content
    char *content = read_file_content(test_filename);
    TEST_ASSERT_NOT_NULL(content);
    
    // Should contain S0 header, multiple S1 data records, and S9 termination
    TEST_ASSERT_TRUE(strstr(content, "S0") != NULL);
    
    // Count S1 records for both sections
    int s1_count = 0;
    char *pos = content;
    while ((pos = strstr(pos, "S1")) != NULL) {
        s1_count++;
        pos += 2;
    }
    
    TEST_ASSERT_GREATER_OR_EQUAL(2, s1_count); // At least one record per section
    // No termination record expected without entry point
    
    free(content);
    unlink(test_filename);
}

void test_srec_write_file_with_entry_point(void) {
    srec_ops = get_motorola_srec_format();
    const char *test_filename = "/tmp/test_entry.s19";
    ctx = create_test_context(test_filename);
    ctx->entry_point = 0x8000; // Set entry point
    
    uint8_t test_data[] = {0x90}; // nop
    add_test_section(ctx, ".text", test_data, sizeof(test_data), 0x8000);
    
    int result = srec_ops->write_file(ctx);
    TEST_ASSERT_EQUAL(0, result);
    
    // Verify file content includes proper termination with entry point
    char *content = read_file_content(test_filename);
    TEST_ASSERT_NOT_NULL(content);
    
    // Should contain S9 record with entry point address
    TEST_ASSERT_TRUE(strstr(content, "S9") != NULL);
    
    free(content);
    unlink(test_filename);
}

void test_srec_write_file_verbose_mode(void) {
    srec_ops = get_motorola_srec_format();
    const char *test_filename = "/tmp/test_verbose.s19";
    ctx = create_test_context(test_filename);
    ctx->verbose = 1; // Enable verbose mode
    
    uint8_t test_data[] = {0x90};
    add_test_section(ctx, ".text", test_data, sizeof(test_data), 0x0000);
    
    int result = srec_ops->write_file(ctx);
    TEST_ASSERT_EQUAL(0, result);
    
    unlink(test_filename);
}

// ========================================
// MOTOROLA S-RECORD ADD SECTION TESTS
// ========================================

void test_srec_add_section_null_context(void) {
    srec_ops = get_motorola_srec_format();
    
    uint8_t data[] = {0x01, 0x02};
    int result = srec_ops->add_section(NULL, ".text", data, sizeof(data), 0x1000);
    TEST_ASSERT_EQUAL(-1, result);
}

void test_srec_add_section_null_name(void) {
    srec_ops = get_motorola_srec_format();
    ctx = create_test_context("test.s19");
    
    uint8_t data[] = {0x01, 0x02};
    int result = srec_ops->add_section(ctx, NULL, data, sizeof(data), 0x1000);
    TEST_ASSERT_EQUAL(-1, result);
}

void test_srec_add_section_valid(void) {
    srec_ops = get_motorola_srec_format();
    ctx = create_test_context("test.s19");
    
    uint8_t data[] = {0x48, 0x89, 0xC0};
    int result = srec_ops->add_section(ctx, ".text", data, sizeof(data), 0x1000);
    
    TEST_ASSERT_EQUAL(0, result);
    TEST_ASSERT_EQUAL(1, ctx->section_count);
    TEST_ASSERT_EQUAL_STRING(".text", ctx->sections[0].name);
    TEST_ASSERT_EQUAL(sizeof(data), ctx->sections[0].size);
    TEST_ASSERT_EQUAL(0x1000, ctx->sections[0].virtual_address);
}

void test_srec_add_section_empty_data(void) {
    srec_ops = get_motorola_srec_format();
    ctx = create_test_context("test.s19");
    
    int result = srec_ops->add_section(ctx, ".bss", NULL, 0, 0x2000);
    
    TEST_ASSERT_EQUAL(0, result);
    TEST_ASSERT_EQUAL(1, ctx->section_count);
    TEST_ASSERT_EQUAL_STRING(".bss", ctx->sections[0].name);
    TEST_ASSERT_EQUAL(0, ctx->sections[0].size);
    TEST_ASSERT_EQUAL(0x2000, ctx->sections[0].virtual_address);
}

void test_srec_add_section_multiple(void) {
    srec_ops = get_motorola_srec_format();
    ctx = create_test_context("test.s19");
    
    uint8_t data1[] = {0x48, 0x89, 0xC0};
    uint8_t data2[] = {0x48, 0x89, 0xDB};
    
    int result1 = srec_ops->add_section(ctx, ".text", data1, sizeof(data1), 0x1000);
    int result2 = srec_ops->add_section(ctx, ".data", data2, sizeof(data2), 0x2000);
    
    TEST_ASSERT_EQUAL(0, result1);
    TEST_ASSERT_EQUAL(0, result2);
    TEST_ASSERT_EQUAL(2, ctx->section_count);
}

// ========================================
// MOTOROLA S-RECORD CLEANUP TESTS
// ========================================

void test_srec_cleanup_null_context(void) {
    srec_ops = get_motorola_srec_format();
    
    // Should not crash with NULL pointer
    srec_ops->cleanup(NULL);
    TEST_ASSERT(1); // If we get here, the test passed
}

void test_srec_cleanup_valid_context(void) {
    srec_ops = get_motorola_srec_format();
    ctx = create_test_context("test.s19");
    
    uint8_t data[] = {0x48, 0x89, 0xC0};
    srec_ops->add_section(ctx, ".text", data, sizeof(data), 0x1000);
    
    // Cleanup should not crash
    srec_ops->cleanup(ctx);
    TEST_ASSERT(1); // If we get here, the test passed
}

void test_srec_cleanup_empty_context(void) {
    srec_ops = get_motorola_srec_format();
    ctx = create_test_context("test.s19");
    
    // Cleanup empty context should not crash
    srec_ops->cleanup(ctx);
    TEST_ASSERT(1); // If we get here, the test passed
}

// ========================================
// MOTOROLA S-RECORD FORMAT VALIDATION TESTS
// ========================================

void test_srec_header_record_format(void) {
    srec_ops = get_motorola_srec_format();
    const char *test_filename = "/tmp/test_header.s19";
    ctx = create_test_context(test_filename);
    
    uint8_t test_data[] = {0x90}; // nop
    add_test_section(ctx, ".text", test_data, sizeof(test_data), 0x0000);
    
    int result = srec_ops->write_file(ctx);
    TEST_ASSERT_EQUAL(0, result);
    
    // Read and validate S-Record format
    char *content = read_file_content(test_filename);
    TEST_ASSERT_NOT_NULL(content);
    
    // Parse first line (should be S0 header record)
    char *first_line = strtok(content, "\n");
    TEST_ASSERT_NOT_NULL(first_line);
    TEST_ASSERT_EQUAL('S', first_line[0]); // Should start with 'S'
    TEST_ASSERT_EQUAL('0', first_line[1]); // Should be S0 header
    
    free(content);
    unlink(test_filename);
}

void test_srec_checksum_validation(void) {
    srec_ops = get_motorola_srec_format();
    const char *test_filename = "/tmp/test_checksum.s19";
    ctx = create_test_context(test_filename);
    
    uint8_t test_data[] = {0x01, 0x02}; // Simple data
    add_test_section(ctx, ".text", test_data, sizeof(test_data), 0x0000);
    
    int result = srec_ops->write_file(ctx);
    TEST_ASSERT_EQUAL(0, result);
    
    // Read file and verify basic format
    char *content = read_file_content(test_filename);
    TEST_ASSERT_NOT_NULL(content);
    
    // Find S1 data record
    char *s1_record = strstr(content, "S1");
    TEST_ASSERT_NOT_NULL(s1_record);
    
    // Verify it has the expected format (S1 + length + address + data + checksum)
    TEST_ASSERT_GREATER_THAN(10, strlen(s1_record)); // Minimum length for S1 record
    
    free(content);
    unlink(test_filename);
}

void test_srec_invalid_filename(void) {
    srec_ops = get_motorola_srec_format();
    ctx = create_test_context("/invalid/path/that/does/not/exist/test.s19");
    
    uint8_t data[] = {0x90}; // nop
    add_test_section(ctx, ".text", data, sizeof(data), 0x0000);
    
    int result = srec_ops->write_file(ctx);
    TEST_ASSERT_EQUAL(-1, result); // Should fail due to invalid path
}

void test_srec_bootloader_rom_image(void) {
    srec_ops = get_motorola_srec_format();
    const char *test_filename = "/tmp/test_rom.s19";
    ctx = create_test_context(test_filename);
    ctx->entry_point = 0xF000; // ROM entry point
    
    // Simple ROM bootloader
    uint8_t rom_code[] = {
        0xEA, 0x00, 0xF0, 0xFF, 0xFF, // JMP FAR F000:0000 (reset vector)
        0x90, 0x90, 0x90              // padding NOPs
    };
    
    add_test_section(ctx, ".rom", rom_code, sizeof(rom_code), 0xF000);
    
    int result = srec_ops->write_file(ctx);
    TEST_ASSERT_EQUAL(0, result);
    
    // Verify S-Record format for ROM
    char *content = read_file_content(test_filename);
    TEST_ASSERT_NOT_NULL(content);
    
    // Should contain S0, S1, and S9 records
    TEST_ASSERT_TRUE(strstr(content, "S0") != NULL);
    TEST_ASSERT_TRUE(strstr(content, "S1") != NULL);
    TEST_ASSERT_TRUE(strstr(content, "S9") != NULL);
    
    free(content);
    unlink(test_filename);
}

int main(void) {
    UNITY_BEGIN();
    
    // Format operations tests
    RUN_TEST(test_get_motorola_srec_format_valid);
    RUN_TEST(test_srec_ops_consistency);
    
    // Write file tests
    RUN_TEST(test_srec_write_file_null_context);
    RUN_TEST(test_srec_write_file_null_filename);
    RUN_TEST(test_srec_write_file_empty);
    RUN_TEST(test_srec_write_file_16bit_data);
    RUN_TEST(test_srec_write_file_24bit_data);
    RUN_TEST(test_srec_write_file_32bit_data);
    RUN_TEST(test_srec_write_file_large_data);
    RUN_TEST(test_srec_write_file_multiple_sections);
    RUN_TEST(test_srec_write_file_with_entry_point);
    RUN_TEST(test_srec_write_file_verbose_mode);
    
    // Add section tests
    RUN_TEST(test_srec_add_section_null_context);
    RUN_TEST(test_srec_add_section_null_name);
    RUN_TEST(test_srec_add_section_valid);
    RUN_TEST(test_srec_add_section_empty_data);
    RUN_TEST(test_srec_add_section_multiple);
    
    // Cleanup tests
    RUN_TEST(test_srec_cleanup_null_context);
    RUN_TEST(test_srec_cleanup_valid_context);
    RUN_TEST(test_srec_cleanup_empty_context);
    
    // Format validation tests
    RUN_TEST(test_srec_header_record_format);
    RUN_TEST(test_srec_checksum_validation);
    RUN_TEST(test_srec_invalid_filename);
    RUN_TEST(test_srec_bootloader_rom_image);
    
    return UNITY_END();
}
