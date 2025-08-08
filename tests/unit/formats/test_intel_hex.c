#include "../../unity/src/unity.h"
#include "unity_extensions.h"
#include "output_format.h"
#include "formats/intel_hex.h"
#include <string.h>
#include <stdlib.h>
#include <unistd.h>

// Global test fixtures
output_format_ops_t *intel_hex_ops;
output_context_t *ctx;

void setUp(void) {
    intel_hex_ops = NULL;
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
    
    test_ctx->format = FORMAT_HEX;
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
// INTEL HEX FORMAT OPERATIONS TESTS
// ========================================

void test_get_intel_hex_format_valid(void) {
    intel_hex_ops = get_intel_hex_format();
    
    TEST_ASSERT_NOT_NULL(intel_hex_ops);
    TEST_ASSERT_NOT_NULL(intel_hex_ops->name);
    TEST_ASSERT_NOT_NULL(intel_hex_ops->extension);
    TEST_ASSERT_NOT_NULL(intel_hex_ops->write_file);
    TEST_ASSERT_NOT_NULL(intel_hex_ops->add_section);
    TEST_ASSERT_NOT_NULL(intel_hex_ops->cleanup);
    
    TEST_ASSERT_EQUAL_STRING("intel-hex", intel_hex_ops->name);
    TEST_ASSERT_EQUAL_STRING("hex", intel_hex_ops->extension);
}

void test_intel_hex_ops_consistency(void) {
    output_format_ops_t *ops1 = get_intel_hex_format();
    output_format_ops_t *ops2 = get_intel_hex_format();
    
    TEST_ASSERT_EQUAL(ops1, ops2); // Should return same instance
}

// ========================================
// INTEL HEX WRITE FILE TESTS
// ========================================

void test_intel_hex_write_file_null_context(void) {
    intel_hex_ops = get_intel_hex_format();
    
    int result = intel_hex_ops->write_file(NULL);
    TEST_ASSERT_EQUAL(-1, result);
}

void test_intel_hex_write_file_null_filename(void) {
    intel_hex_ops = get_intel_hex_format();
    ctx = create_test_context(NULL);
    
    int result = intel_hex_ops->write_file(ctx);
    TEST_ASSERT_EQUAL(-1, result);
}

void test_intel_hex_write_file_empty(void) {
    intel_hex_ops = get_intel_hex_format();
    const char *test_filename = "/tmp/test_empty.hex";
    ctx = create_test_context(test_filename);
    
    int result = intel_hex_ops->write_file(ctx);
    TEST_ASSERT_EQUAL(0, result);
    
    // Verify file contains only EOF record
    char *content = read_file_content(test_filename);
    TEST_ASSERT_NOT_NULL(content);
    
    // Should contain EOF record: ":00000001FF\n"
    TEST_ASSERT_TRUE(strstr(content, ":00000001FF") != NULL);
    
    free(content);
    unlink(test_filename);
}

void test_intel_hex_write_file_simple_data(void) {
    intel_hex_ops = get_intel_hex_format();
    const char *test_filename = "/tmp/test_simple.hex";
    ctx = create_test_context(test_filename);
    
    uint8_t test_data[] = {0x48, 0x89, 0xC0}; // movq %rax, %rax
    add_test_section(ctx, ".text", test_data, sizeof(test_data), 0x1000);
    
    int result = intel_hex_ops->write_file(ctx);
    TEST_ASSERT_EQUAL(0, result);
    
    // Verify file content
    char *content = read_file_content(test_filename);
    TEST_ASSERT_NOT_NULL(content);
    
    // Should start with data record and end with EOF
    TEST_ASSERT_TRUE(strstr(content, ":03100000") != NULL); // 3 bytes at 0x1000
    TEST_ASSERT_TRUE(strstr(content, ":00000001FF") != NULL); // EOF record
    
    free(content);
    unlink(test_filename);
}

void test_intel_hex_write_file_large_data(void) {
    intel_hex_ops = get_intel_hex_format();
    const char *test_filename = "/tmp/test_large.hex";
    ctx = create_test_context(test_filename);
    
    // Create data larger than 16 bytes to test multiple records
    uint8_t test_data[32];
    for (int i = 0; i < 32; i++) {
        test_data[i] = (uint8_t)i;
    }
    
    add_test_section(ctx, ".text", test_data, sizeof(test_data), 0x0000);
    
    int result = intel_hex_ops->write_file(ctx);
    TEST_ASSERT_EQUAL(0, result);
    
    // Verify file content has multiple records
    char *content = read_file_content(test_filename);
    TEST_ASSERT_NOT_NULL(content);
    
    // Count number of lines (should be more than 2: multiple data records + EOF)
    int line_count = 0;
    char *line = strtok(content, "\n");
    while (line != NULL) {
        if (line[0] == ':') line_count++;
        line = strtok(NULL, "\n");
    }
    
    TEST_ASSERT_GREATER_THAN(2, line_count); // Should have multiple data records + EOF
    
    free(content);
    unlink(test_filename);
}

void test_intel_hex_write_file_high_address(void) {
    intel_hex_ops = get_intel_hex_format();
    const char *test_filename = "/tmp/test_high_addr.hex";
    ctx = create_test_context(test_filename);
    
    uint8_t test_data[] = {0x90, 0x90}; // nop nop
    add_test_section(ctx, ".text", test_data, sizeof(test_data), 0x10000); // Address > 16-bit
    
    int result = intel_hex_ops->write_file(ctx);
    TEST_ASSERT_EQUAL(0, result);
    
    // Verify file content includes extended linear address record
    char *content = read_file_content(test_filename);
    TEST_ASSERT_NOT_NULL(content);
    
    // Should contain extended linear address record (type 04)
    TEST_ASSERT_TRUE(strstr(content, ":020000040001") != NULL); // Extended address for 0x10000
    
    free(content);
    unlink(test_filename);
}

void test_intel_hex_write_file_multiple_sections(void) {
    intel_hex_ops = get_intel_hex_format();
    const char *test_filename = "/tmp/test_multi_sections.hex";
    ctx = create_test_context(test_filename);
    
    uint8_t section1[] = {0x48, 0x89, 0xC0};
    uint8_t section2[] = {0x01, 0x02, 0x03, 0x04};
    
    add_test_section(ctx, ".text", section1, sizeof(section1), 0x1000);
    add_test_section(ctx, ".data", section2, sizeof(section2), 0x2000);
    
    int result = intel_hex_ops->write_file(ctx);
    TEST_ASSERT_EQUAL(0, result);
    
    // Verify file content
    char *content = read_file_content(test_filename);
    TEST_ASSERT_NOT_NULL(content);
    
    // Should contain data records for both sections
    TEST_ASSERT_TRUE(strstr(content, ":03100000") != NULL); // Section 1 at 0x1000
    TEST_ASSERT_TRUE(strstr(content, ":04200000") != NULL); // Section 2 at 0x2000
    TEST_ASSERT_TRUE(strstr(content, ":00000001FF") != NULL); // EOF record
    
    free(content);
    unlink(test_filename);
}

void test_intel_hex_write_file_verbose_mode(void) {
    intel_hex_ops = get_intel_hex_format();
    const char *test_filename = "/tmp/test_verbose.hex";
    ctx = create_test_context(test_filename);
    ctx->verbose = 1; // Enable verbose mode
    
    uint8_t test_data[] = {0x90};
    add_test_section(ctx, ".text", test_data, sizeof(test_data), 0x0000);
    
    int result = intel_hex_ops->write_file(ctx);
    TEST_ASSERT_EQUAL(0, result);
    
    unlink(test_filename);
}

// ========================================
// INTEL HEX ADD SECTION TESTS
// ========================================

void test_intel_hex_add_section_null_context(void) {
    intel_hex_ops = get_intel_hex_format();
    
    uint8_t data[] = {0x01, 0x02};
    int result = intel_hex_ops->add_section(NULL, ".text", data, sizeof(data), 0x1000);
    TEST_ASSERT_EQUAL(-1, result);
}

void test_intel_hex_add_section_null_name(void) {
    intel_hex_ops = get_intel_hex_format();
    ctx = create_test_context("test.hex");
    
    uint8_t data[] = {0x01, 0x02};
    int result = intel_hex_ops->add_section(ctx, NULL, data, sizeof(data), 0x1000);
    TEST_ASSERT_EQUAL(-1, result);
}

void test_intel_hex_add_section_valid(void) {
    intel_hex_ops = get_intel_hex_format();
    ctx = create_test_context("test.hex");
    
    uint8_t data[] = {0x48, 0x89, 0xC0};
    int result = intel_hex_ops->add_section(ctx, ".text", data, sizeof(data), 0x1000);
    
    TEST_ASSERT_EQUAL(0, result);
    TEST_ASSERT_EQUAL(1, ctx->section_count);
    TEST_ASSERT_EQUAL_STRING(".text", ctx->sections[0].name);
    TEST_ASSERT_EQUAL(sizeof(data), ctx->sections[0].size);
    TEST_ASSERT_EQUAL(0x1000, ctx->sections[0].virtual_address);
}

void test_intel_hex_add_section_empty_data(void) {
    intel_hex_ops = get_intel_hex_format();
    ctx = create_test_context("test.hex");
    
    int result = intel_hex_ops->add_section(ctx, ".bss", NULL, 0, 0x2000);
    
    TEST_ASSERT_EQUAL(0, result);
    TEST_ASSERT_EQUAL(1, ctx->section_count);
    TEST_ASSERT_EQUAL_STRING(".bss", ctx->sections[0].name);
    TEST_ASSERT_EQUAL(0, ctx->sections[0].size);
    TEST_ASSERT_EQUAL(0x2000, ctx->sections[0].virtual_address);
}

void test_intel_hex_add_section_multiple(void) {
    intel_hex_ops = get_intel_hex_format();
    ctx = create_test_context("test.hex");
    
    uint8_t data1[] = {0x48, 0x89, 0xC0};
    uint8_t data2[] = {0x48, 0x89, 0xDB};
    
    int result1 = intel_hex_ops->add_section(ctx, ".text", data1, sizeof(data1), 0x1000);
    int result2 = intel_hex_ops->add_section(ctx, ".data", data2, sizeof(data2), 0x2000);
    
    TEST_ASSERT_EQUAL(0, result1);
    TEST_ASSERT_EQUAL(0, result2);
    TEST_ASSERT_EQUAL(2, ctx->section_count);
}

// ========================================
// INTEL HEX CLEANUP TESTS
// ========================================

void test_intel_hex_cleanup_null_context(void) {
    intel_hex_ops = get_intel_hex_format();
    
    // Should not crash with NULL pointer
    intel_hex_ops->cleanup(NULL);
    TEST_ASSERT(1); // If we get here, the test passed
}

void test_intel_hex_cleanup_valid_context(void) {
    intel_hex_ops = get_intel_hex_format();
    ctx = create_test_context("test.hex");
    
    uint8_t data[] = {0x48, 0x89, 0xC0};
    intel_hex_ops->add_section(ctx, ".text", data, sizeof(data), 0x1000);
    
    // Cleanup should not crash
    intel_hex_ops->cleanup(ctx);
    TEST_ASSERT(1); // If we get here, the test passed
}

void test_intel_hex_cleanup_empty_context(void) {
    intel_hex_ops = get_intel_hex_format();
    ctx = create_test_context("test.hex");
    
    // Cleanup empty context should not crash
    intel_hex_ops->cleanup(ctx);
    TEST_ASSERT(1); // If we get here, the test passed
}

// ========================================
// INTEL HEX FORMAT VALIDATION TESTS
// ========================================

void test_intel_hex_record_format_validation(void) {
    intel_hex_ops = get_intel_hex_format();
    const char *test_filename = "/tmp/test_format.hex";
    ctx = create_test_context(test_filename);
    
    uint8_t test_data[] = {0xAA, 0xBB, 0xCC};
    add_test_section(ctx, ".text", test_data, sizeof(test_data), 0x0000);
    
    int result = intel_hex_ops->write_file(ctx);
    TEST_ASSERT_EQUAL(0, result);
    
    // Read and validate hex format
    char *content = read_file_content(test_filename);
    TEST_ASSERT_NOT_NULL(content);
    
    // Parse first line (should be data record)
    char *first_line = strtok(content, "\n");
    TEST_ASSERT_NOT_NULL(first_line);
    TEST_ASSERT_EQUAL(':', first_line[0]); // Should start with ':'
    TEST_ASSERT_EQUAL(17, strlen(first_line)); // :LLAAAATTDDDDDDCC format (3 bytes = 17 chars)
    
    free(content);
    unlink(test_filename);
}

void test_intel_hex_checksum_validation(void) {
    intel_hex_ops = get_intel_hex_format();
    const char *test_filename = "/tmp/test_checksum.hex";
    ctx = create_test_context(test_filename);
    
    uint8_t test_data[] = {0x01, 0x02}; // Simple data
    add_test_section(ctx, ".text", test_data, sizeof(test_data), 0x0000);
    
    int result = intel_hex_ops->write_file(ctx);
    TEST_ASSERT_EQUAL(0, result);
    
    // Read file and verify checksum
    char *content = read_file_content(test_filename);
    TEST_ASSERT_NOT_NULL(content);
    
    // Parse first data record: :020000000102FB
    // Bytes: 02(count) 00 00(addr) 00(type) 01 02(data) FB(checksum)
    // Sum: 02 + 00 + 00 + 00 + 01 + 02 = 05, Checksum = 0x100 - 0x05 = FB
    TEST_ASSERT_TRUE(strstr(content, ":020000000102FB") != NULL);
    
    free(content);
    unlink(test_filename);
}

void test_intel_hex_invalid_filename(void) {
    intel_hex_ops = get_intel_hex_format();
    ctx = create_test_context("/invalid/path/that/does/not/exist/test.hex");
    
    uint8_t data[] = {0x90}; // nop
    add_test_section(ctx, ".text", data, sizeof(data), 0x0000);
    
    int result = intel_hex_ops->write_file(ctx);
    TEST_ASSERT_EQUAL(-1, result); // Should fail due to invalid path
}

int main(void) {
    UNITY_BEGIN();
    
    // Format operations tests
    RUN_TEST(test_get_intel_hex_format_valid);
    RUN_TEST(test_intel_hex_ops_consistency);
    
    // Write file tests
    RUN_TEST(test_intel_hex_write_file_null_context);
    RUN_TEST(test_intel_hex_write_file_null_filename);
    RUN_TEST(test_intel_hex_write_file_empty);
    RUN_TEST(test_intel_hex_write_file_simple_data);
    RUN_TEST(test_intel_hex_write_file_large_data);
    RUN_TEST(test_intel_hex_write_file_high_address);
    RUN_TEST(test_intel_hex_write_file_multiple_sections);
    RUN_TEST(test_intel_hex_write_file_verbose_mode);
    
    // Add section tests
    RUN_TEST(test_intel_hex_add_section_null_context);
    RUN_TEST(test_intel_hex_add_section_null_name);
    RUN_TEST(test_intel_hex_add_section_valid);
    RUN_TEST(test_intel_hex_add_section_empty_data);
    RUN_TEST(test_intel_hex_add_section_multiple);
    
    // Cleanup tests
    RUN_TEST(test_intel_hex_cleanup_null_context);
    RUN_TEST(test_intel_hex_cleanup_valid_context);
    RUN_TEST(test_intel_hex_cleanup_empty_context);
    
    // Format validation tests
    RUN_TEST(test_intel_hex_record_format_validation);
    RUN_TEST(test_intel_hex_checksum_validation);
    RUN_TEST(test_intel_hex_invalid_filename);
    
    return UNITY_END();
}
