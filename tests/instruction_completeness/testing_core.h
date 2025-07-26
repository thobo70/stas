#ifndef TESTING_CORE_H
#define TESTING_CORE_H

#include "instruction_completeness.h"

// Core testing functions
instruction_test_result_t test_instruction_category(const char *arch_name, 
                                                   const instruction_category_t *category);
instruction_test_result_t test_instruction_category_verbose(const char *arch_name, 
                                                           const instruction_category_t *category,
                                                           bool verbose_mode);

#endif // TESTING_CORE_H
