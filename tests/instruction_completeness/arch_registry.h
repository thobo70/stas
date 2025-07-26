#ifndef ARCH_REGISTRY_H
#define ARCH_REGISTRY_H

#include "instruction_completeness.h"
#include <string.h>

// Functions to get all architectures and lookup by name
const arch_instruction_set_t** get_all_architectures(size_t* count);
const arch_instruction_set_t* get_architecture_by_name(const char* arch_name);

#endif // ARCH_REGISTRY_H
