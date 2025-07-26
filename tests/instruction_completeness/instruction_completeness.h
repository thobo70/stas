#ifndef INSTRUCTION_SET_COMPLETENESS_H
#define INSTRUCTION_SET_COMPLETENESS_H

#include <stddef.h>
#include <stdbool.h>

// Architecture instruction set definitions
typedef struct {
    const char *mnemonic;
    const char *category;
    size_t operand_count;
    bool is_extension;  // For extended instruction sets (SSE, AVX, etc.)
} instruction_def_t;

typedef struct {
    const char *category_name;
    const instruction_def_t *instructions;
    size_t instruction_count;
} instruction_category_t;

typedef struct {
    const char *arch_name;
    const instruction_category_t *categories;
    size_t category_count;
} arch_instruction_set_t;

typedef struct {
    size_t recognized;
    size_t functional;
    size_t total;
    double recognition_percent;
    double functional_percent;
} instruction_test_result_t;

typedef struct {
    const char *category_name;
    instruction_test_result_t result;
} category_result_t;

typedef struct {
    const char *arch_name;
    category_result_t *category_results;
    size_t category_count;
    instruction_test_result_t overall;
} arch_test_result_t;

// Configuration options
typedef struct {
    int max_line_width;    // Maximum characters per line (default: 80)
    bool compact_mode;     // Use compact formatting
    bool show_progress_bars; // Show visual progress bars
    bool verbose_mode;     // Show detailed failure reports
    const char *target_arch; // Test only specific architecture (NULL for all)
} report_config_t;

// Function declarations
void run_instruction_completeness_tests(void);
void run_instruction_completeness_tests_with_config(const report_config_t *config);
void print_instruction_completeness_report(arch_test_result_t *results, size_t arch_count);
void print_instruction_completeness_report_with_config(arch_test_result_t *results, size_t arch_count, const report_config_t *config);
instruction_test_result_t test_instruction_category(const char *arch_name, 
                                                   const instruction_category_t *category);
instruction_test_result_t test_instruction_category_verbose(const char *arch_name, 
                                                           const instruction_category_t *category,
                                                           bool verbose_mode);

#endif // INSTRUCTION_SET_COMPLETENESS_H
