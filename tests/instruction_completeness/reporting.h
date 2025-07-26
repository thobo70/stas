#ifndef REPORTING_H
#define REPORTING_H

#include "instruction_completeness.h"

// Progress bar and visual formatting
void print_progress_bar(double percent, int width, bool compact);

// Report generation functions
void print_instruction_completeness_report(arch_test_result_t *results, size_t arch_count);
void print_instruction_completeness_report_compact(arch_test_result_t *results, size_t arch_count, const report_config_t *config);
void print_instruction_completeness_report_with_config(arch_test_result_t *results, size_t arch_count, const report_config_t *config);

// Main test runner functions
void run_instruction_completeness_tests(void);
void run_instruction_completeness_tests_with_config(const report_config_t *config);

#endif // REPORTING_H
