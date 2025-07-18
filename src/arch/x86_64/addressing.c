/*
 * x86-64 Addressing Mode Implementation
 * Handles parsing and validation of x86-64 addressing modes
 */

#include "x86_64.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>

// Safe string duplication function
static char *safe_strdup(const char *s) {
    if (!s) return NULL;
    size_t len = strlen(s) + 1;
    char *dup = malloc(len);
    if (dup) {
        memcpy(dup, s, len);
    }
    return dup;
}

// Forward declarations - use external function from registers.c
extern bool is_64bit_register(x86_64_register_id_t id);

//=============================================================================
// Addressing Mode Parsing
//=============================================================================

static char *trim_whitespace(const char *str) {
    if (!str) return NULL;
    
    // Skip leading whitespace
    while (isspace(*str)) str++;
    
    // Find end of string
    const char *end = str + strlen(str) - 1;
    while (end > str && isspace(*end)) end--;
    
    // Allocate and copy trimmed string
    size_t len = end - str + 1;
    char *trimmed = malloc(len + 1);
    if (!trimmed) return NULL;
    
    strncpy(trimmed, str, len);
    trimmed[len] = '\0';
    
    return trimmed;
}

static int parse_displacement(const char *str, int64_t *displacement) {
    if (!str || !displacement) {
        return -1;
    }
    
    char *endptr;
    *displacement = strtoll(str, &endptr, 0); // Auto-detect base (hex with 0x)
    
    return (*endptr == '\0') ? 0 : -1;
}

static int parse_scale(const char *str, uint8_t *scale) {
    if (!str || !scale) {
        return -1;
    }
    
    int val = atoi(str);
    
    // Valid scales are 1, 2, 4, 8
    switch (val) {
        case 1: *scale = 0; break;  // 2^0 = 1
        case 2: *scale = 1; break;  // 2^1 = 2
        case 4: *scale = 2; break;  // 2^2 = 4
        case 8: *scale = 3; break;  // 2^3 = 8
        default: return -1;
    }
    
    return 0;
}

//=============================================================================
// AT&T Syntax Addressing Mode Parser
//=============================================================================

int x86_64_parse_addressing_att(const char *addr_str, addressing_mode_t *mode) {
    if (!addr_str || !mode) {
        return -1;
    }
    
    // Initialize addressing mode
    memset(mode, 0, sizeof(addressing_mode_t));
    mode->scale = 0; // Default scale = 1 (2^0)
    
    char *str_copy = trim_whitespace(addr_str);
    if (!str_copy) {
        return -1;
    }
    
    // Case 1: Simple symbol reference
    // Example: symbol
    if (str_copy[0] != '(' && strchr(str_copy, '(') == NULL) {
        mode->type = ADDR_DIRECT;
        mode->symbol = safe_strdup(str_copy);
        free(str_copy);
        return 0;
    }
    
    // Case 2: RIP-relative addressing
    // Example: symbol(%rip)
    char *rip_pos = strstr(str_copy, "(%rip)");
    if (rip_pos != NULL) {
        mode->type = ADDR_RIP_RELATIVE;
        *rip_pos = '\0'; // Terminate at (%rip)
        
        if (strlen(str_copy) > 0) {
            mode->symbol = safe_strdup(str_copy);
        }
        
        free(str_copy);
        return 0;
    }
    
    // Case 3: Register indirect or complex addressing
    // Examples: (%rax), 8(%rax), (%rax,%rbx,2), 8(%rax,%rbx,2)
    
    char *paren_start = strchr(str_copy, '(');
    char *paren_end = strrchr(str_copy, ')');
    
    if (!paren_start || !paren_end || paren_end <= paren_start) {
        free(str_copy);
        return -1; // Invalid syntax
    }
    
    // Parse displacement (before opening parenthesis)
    if (paren_start > str_copy) {
        *paren_start = '\0';
        if (parse_displacement(str_copy, &mode->offset) != 0) {
            free(str_copy);
            return -1;
        }
    }
    
    // Parse register part (between parentheses)
    *paren_end = '\0';
    char *reg_part = paren_start + 1;
    
    // Split by commas to get base, index, scale
    char *base_str = strtok(reg_part, ",");
    char *index_str = strtok(NULL, ",");
    char *scale_str = strtok(NULL, ",");
    
    // Parse base register
    if (base_str && strlen(trim_whitespace(base_str)) > 0) {
        char *clean_base = trim_whitespace(base_str);
        if (x86_64_parse_register(clean_base, &mode->base) != 0) {
            free(clean_base);
            free(str_copy);
            return -1;
        }
        free(clean_base);
    }
    
    // Parse index register
    if (index_str && strlen(trim_whitespace(index_str)) > 0) {
        char *clean_index = trim_whitespace(index_str);
        if (x86_64_parse_register(clean_index, &mode->index) != 0) {
            free(clean_index);
            free(str_copy);
            return -1;
        }
        free(clean_index);
        
        // Validate index register (RSP cannot be index)
        if (mode->index.id == RSP) {
            free(str_copy);
            return -1;
        }
    }
    
    // Parse scale
    if (scale_str && strlen(trim_whitespace(scale_str)) > 0) {
        char *clean_scale = trim_whitespace(scale_str);
        if (parse_scale(clean_scale, &mode->scale) != 0) {
            free(clean_scale);
            free(str_copy);
            return -1;
        }
        free(clean_scale);
    }
    
    // Determine addressing mode type
    if (mode->base.id != 0 && mode->index.id != 0) {
        mode->type = ADDR_INDEXED;
    } else if (mode->base.id != 0) {
        mode->type = ADDR_INDIRECT;
    } else {
        free(str_copy);
        return -1; // Invalid: no base register
    }
    
    free(str_copy);
    return 0;
}

//=============================================================================
// Addressing Mode Validation
//=============================================================================

bool x86_64_validate_addressing_mode(addressing_mode_t *mode, instruction_t *inst) {
    (void)inst; // Suppress unused parameter warning
    if (!mode) {
        return false;
    }
    
    switch (mode->type) {
        case ADDR_DIRECT:
            // Symbol reference: always valid
            return true;
            
        case ADDR_RIP_RELATIVE:
            // RIP-relative: only valid in 64-bit mode
            // Symbol must be present
            return mode->symbol != NULL;
            
        case ADDR_INDIRECT:
            // Register indirect: (%reg)
            // Base register must be valid 64-bit register
            return is_64bit_register(mode->base.id);
            
        case ADDR_INDEXED:
            // Complex addressing: offset(%base,%index,scale)
            
            // Base register validation
            if (!is_64bit_register(mode->base.id)) {
                return false;
            }
            
            // Index register validation
            if (mode->index.id != 0) {
                if (!is_64bit_register(mode->index.id)) {
                    return false;
                }
                
                // RSP cannot be used as index register
                if (mode->index.id == RSP) {
                    return false;
                }
            }
            
            // Scale validation (must be 1, 2, 4, or 8)
            if (mode->scale > 3) {
                return false;
            }
            
            // Displacement validation (must fit in 32 bits for x86-64)
            if (mode->offset < -2147483648LL || mode->offset > 2147483647LL) {
                return false;
            }
            
            return true;
            
        default:
            return false;
    }
}

//=============================================================================
// ModR/M and SIB Encoding
//=============================================================================

int encode_addressing_mode(addressing_mode_t *mode, uint8_t *modrm, uint8_t *sib, 
                          int8_t *disp8, int32_t *disp32, bool *needs_sib, 
                          bool *needs_disp8, bool *needs_disp32) {
    if (!mode || !modrm || !sib || !needs_sib || !needs_disp8 || !needs_disp32) {
        return -1;
    }
    
    *needs_sib = false;
    *needs_disp8 = false;
    *needs_disp32 = false;
    
    switch (mode->type) {
        case ADDR_INDIRECT: {
            // Register indirect: (%reg)
            uint8_t reg_encoding = mode->base.encoding & 0x07;
            
            if (mode->offset == 0) {
                // No displacement
                if (reg_encoding == 4) { // RSP/R12 requires SIB
                    *modrm = (0 << 6) | (0 << 3) | 4; // mod=00, r/m=100 (SIB)
                    *sib = (0 << 6) | (4 << 3) | reg_encoding; // scale=00, index=100 (none), base=reg
                    *needs_sib = true;
                } else if (reg_encoding == 5) { // RBP/R13 requires displacement
                    *modrm = (1 << 6) | (0 << 3) | reg_encoding; // mod=01, disp8
                    *disp8 = 0;
                    *needs_disp8 = true;
                } else {
                    *modrm = (0 << 6) | (0 << 3) | reg_encoding; // mod=00
                }
            } else if (mode->offset >= -128 && mode->offset <= 127) {
                // 8-bit displacement
                *modrm = (1 << 6) | (0 << 3) | reg_encoding; // mod=01
                *disp8 = (int8_t)mode->offset;
                *needs_disp8 = true;
                
                if (reg_encoding == 4) { // RSP/R12 requires SIB
                    *modrm = (1 << 6) | (0 << 3) | 4; // mod=01, r/m=100 (SIB)
                    *sib = (0 << 6) | (4 << 3) | reg_encoding; // scale=00, index=100 (none), base=reg
                    *needs_sib = true;
                }
            } else {
                // 32-bit displacement
                *modrm = (2 << 6) | (0 << 3) | reg_encoding; // mod=10
                *disp32 = (int32_t)mode->offset;
                *needs_disp32 = true;
                
                if (reg_encoding == 4) { // RSP/R12 requires SIB
                    *modrm = (2 << 6) | (0 << 3) | 4; // mod=10, r/m=100 (SIB)
                    *sib = (0 << 6) | (4 << 3) | reg_encoding; // scale=00, index=100 (none), base=reg
                    *needs_sib = true;
                }
            }
            break;
        }
        
        case ADDR_INDEXED: {
            // Complex addressing: offset(%base,%index,scale)
            uint8_t base_encoding = mode->base.encoding & 0x07;
            uint8_t index_encoding = mode->index.id ? (mode->index.encoding & 0x07) : 4; // 4 = no index
            
            *needs_sib = true;
            
            if (mode->offset == 0 && base_encoding != 5) { // Not RBP/R13
                *modrm = (0 << 6) | (0 << 3) | 4; // mod=00, r/m=100 (SIB)
            } else if (mode->offset >= -128 && mode->offset <= 127) {
                *modrm = (1 << 6) | (0 << 3) | 4; // mod=01, r/m=100 (SIB)
                *disp8 = (int8_t)mode->offset;
                *needs_disp8 = true;
            } else {
                *modrm = (2 << 6) | (0 << 3) | 4; // mod=10, r/m=100 (SIB)
                *disp32 = (int32_t)mode->offset;
                *needs_disp32 = true;
            }
            
            *sib = (mode->scale << 6) | (index_encoding << 3) | base_encoding;
            break;
        }
        
        case ADDR_RIP_RELATIVE: {
            // RIP-relative addressing
            *modrm = (0 << 6) | (0 << 3) | 5; // mod=00, r/m=101 (RIP+disp32)
            *disp32 = (int32_t)mode->offset;
            *needs_disp32 = true;
            break;
        }
        
        default:
            return -1;
    }
    
    return 0;
}

//=============================================================================
// Addressing Mode Size Calculation
//=============================================================================

size_t get_addressing_mode_size(addressing_mode_t *mode) {
    if (!mode) {
        return 0;
    }
    
    size_t size = 0;
    
    switch (mode->type) {
        case ADDR_DIRECT:
            // Direct addressing typically uses 32-bit displacement
            size = 4;
            break;
            
        case ADDR_RIP_RELATIVE:
            // RIP-relative uses 32-bit displacement
            size = 4;
            break;
            
        case ADDR_INDIRECT:
        case ADDR_INDEXED:
            // Calculate based on ModR/M/SIB encoding
            if (mode->offset == 0) {
                size = 0; // No displacement
            } else if (mode->offset >= -128 && mode->offset <= 127) {
                size = 1; // 8-bit displacement
            } else {
                size = 4; // 32-bit displacement
            }
            break;
    }
    
    return size;
}

//=============================================================================
// Addressing Mode String Representation
//=============================================================================

char *addressing_mode_to_string(addressing_mode_t *mode) {
    if (!mode) {
        return NULL;
    }
    
    char *result = malloc(256);
    if (!result) {
        return NULL;
    }
    
    switch (mode->type) {
        case ADDR_DIRECT:
            snprintf(result, 256, "%s", mode->symbol ? mode->symbol : "unknown");
            break;
            
        case ADDR_RIP_RELATIVE:
            if (mode->symbol) {
                snprintf(result, 256, "%s(%%rip)", mode->symbol);
            } else {
                snprintf(result, 256, "%ld(%%rip)", mode->offset);
            }
            break;
            
        case ADDR_INDIRECT:
            if (mode->offset == 0) {
                snprintf(result, 256, "(%%%s)", 
                         x86_64_get_register_name(mode->base));
            } else {
                snprintf(result, 256, "%ld(%%%s)", mode->offset,
                         x86_64_get_register_name(mode->base));
            }
            break;
            
        case ADDR_INDEXED: {
            char base_str[32] = "";
            char index_str[64] = "";
            
            if (mode->base.id != 0) {
                snprintf(base_str, sizeof(base_str), "%%%s", 
                         x86_64_get_register_name(mode->base));
            }
            
            if (mode->index.id != 0) {
                int scale_val = 1 << mode->scale;
                snprintf(index_str, sizeof(index_str), ",%%%s,%d",
                         x86_64_get_register_name(mode->index), scale_val);
            }
            
            if (mode->offset == 0) {
                snprintf(result, 256, "(%s%s)", base_str, index_str);
            } else {
                snprintf(result, 256, "%ld(%s%s)", mode->offset, base_str, index_str);
            }
            break;
        }
        
        default:
            snprintf(result, 256, "invalid");
            break;
    }
    
    return result;
}
