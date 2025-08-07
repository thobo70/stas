/*
 * x86-64 Comprehensive Addressing Mode Implementation
 * Complete AT&T syntax addressing mode parsing and encoding  
 * Following STAS Development Manifest requirements for CPU accuracy
 */

#include "x86_64_unified.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>

//=============================================================================
// Comprehensive AT&T Syntax Addressing Mode Parser
//=============================================================================

int x86_64_parse_addressing_mode(const char *addr_str, x86_64_address_t *addr) {
    if (!addr_str || !addr) return -1;
    
    // Initialize address structure  
    memset(addr, 0, sizeof(x86_64_address_t));
    addr->scale = 1;
    addr->base_reg = RAX;
    addr->index_reg = RAX;
    addr->segment_reg = DS;
    
    // Skip whitespace
    while (isspace(*addr_str)) addr_str++;
    
    // Handle immediate addressing: $value
    if (addr_str[0] == '$') {
        addr->type = X86_64_ADDR_IMMEDIATE;
        char *endptr;
        addr->displacement = strtol(addr_str + 1, &endptr, 0);
        if (endptr == addr_str + 1) return -1; // No valid number
        return 0;
    }
    
    // Handle register direct: %reg
    if (addr_str[0] == '%' && strchr(addr_str, '(') == NULL) {
        addr->type = X86_64_ADDR_REGISTER;
        const x86_64_register_info_t *reg = x86_64_find_register(addr_str);
        if (!reg) return -1;
        addr->base_reg = reg->id;
        return 0;
    }
    
    // Handle segment prefix (e.g., %fs:offset(%base))
    const char *segment_end = strchr(addr_str, ':');
    if (segment_end && addr_str[0] == '%') {
        // Parse segment register
        size_t seg_len = segment_end - addr_str;
        char seg_name[16];
        if (seg_len >= sizeof(seg_name)) return -1;
        strncpy(seg_name, addr_str, seg_len);
        seg_name[seg_len] = '\0';
        
        const x86_64_register_info_t *seg_reg = x86_64_find_register(seg_name);
        if (!seg_reg) return -1;
        addr->segment_reg = seg_reg->id;
        addr->has_segment_override = true;
        
        // Continue parsing after the segment prefix
        addr_str = segment_end + 1;
    }
    
    // Handle memory addressing modes
    const char *paren_start = strchr(addr_str, '(');
    if (paren_start) {
        addr->type = X86_64_ADDR_INDIRECT;
        
        // Parse displacement before parentheses
        if (paren_start > addr_str) {
            // There's a displacement
            size_t disp_len = paren_start - addr_str;
            char disp_str[32];
            if (disp_len >= sizeof(disp_str)) return -1;
            strncpy(disp_str, addr_str, disp_len);
            disp_str[disp_len] = '\0';
            
            // Handle negative displacement
            char *endptr;
            addr->displacement = strtol(disp_str, &endptr, 0);
            if (endptr != disp_str + disp_len) return -1; // Invalid displacement
            addr->has_displacement = true;
        }
        
        // Parse the content inside parentheses: (base,index,scale)
        const char *paren_end = strchr(paren_start, ')');
        if (!paren_end) return -1;
        
        size_t paren_content_len = paren_end - paren_start - 1;
        char paren_content[64];
        if (paren_content_len >= sizeof(paren_content)) return -1;
        strncpy(paren_content, paren_start + 1, paren_content_len);
        paren_content[paren_content_len] = '\0';
        
        // Parse components: base, index, scale
        char *token = strtok(paren_content, ",");
        int component = 0;
        
        while (token && component < 3) {
            // Trim whitespace
            while (isspace(*token)) token++;
            char *end = token + strlen(token) - 1;
            while (end > token && isspace(*end)) *end-- = '\0';
            
            if (strlen(token) > 0) {
                switch (component) {
                case 0: // Base register
                    if (token[0] == '%') {
                        const x86_64_register_info_t *base_reg = x86_64_find_register(token);
                        if (!base_reg) return -1;
                        addr->base_reg = base_reg->id;
                        addr->has_base = true;
                    } else if (strcmp(token, "") != 0) {
                        return -1; // Invalid base
                    }
                    break;
                    
                case 1: // Index register
                    if (token[0] == '%') {
                        const x86_64_register_info_t *index_reg = x86_64_find_register(token);
                        if (!index_reg) return -1;
                        addr->index_reg = index_reg->id;
                        addr->has_index = true;
                    } else if (strcmp(token, "") != 0) {
                        return -1; // Invalid index
                    }
                    break;
                    
                case 2: // Scale factor
                    {
                        char *endptr;
                        long scale = strtol(token, &endptr, 10);
                        if (endptr == token || *endptr != '\0') return -1;
                        if (scale != 1 && scale != 2 && scale != 4 && scale != 8) return -1;
                        addr->scale = (uint8_t)scale;
                    }
                    break;
                }
            }
            
            token = strtok(NULL, ",");
            component++;
        }
        
        // Special case: if no base but has index, it's still valid
        if (!addr->has_base && !addr->has_index) {
            return -1; // Must have at least one register
        }
        
    } else {
        // Direct addressing (just a displacement)
        addr->type = X86_64_ADDR_DIRECT;
        char *endptr;
        addr->displacement = strtol(addr_str, &endptr, 0);
        if (endptr == addr_str) return -1; // No valid number
        addr->has_displacement = true;
    }
    
    return 0;
}

//=============================================================================
// ModR/M and SIB Encoding for Addressing Modes
//=============================================================================

int x86_64_encode_addressing_mode(const x86_64_address_t *addr, uint8_t reg_field, 
                                  uint8_t *encoding, size_t *encoding_len) {
    if (!addr || !encoding || !encoding_len) return -1;
    
    *encoding_len = 0;
    
    switch (addr->type) {
    case X86_64_ADDR_REGISTER:
        // Direct register addressing: mod=11, rm=register
        encoding[(*encoding_len)++] = 0xC0 | (reg_field << 3) | (addr->base_reg & 0x7);
        break;
        
    case X86_64_ADDR_IMMEDIATE:
        // Immediate addressing doesn't use ModR/M in the same way
        return -1; // Handle separately in instruction encoding
        
    case X86_64_ADDR_DIRECT:
        // Direct memory addressing: mod=00, rm=101 (RIP-relative in 64-bit mode)
        encoding[(*encoding_len)++] = 0x05 | (reg_field << 3);
        // Add 32-bit displacement
        encoding[(*encoding_len)++] = addr->displacement & 0xFF;
        encoding[(*encoding_len)++] = (addr->displacement >> 8) & 0xFF;
        encoding[(*encoding_len)++] = (addr->displacement >> 16) & 0xFF;
        encoding[(*encoding_len)++] = (addr->displacement >> 24) & 0xFF;
        break;
        
    case X86_64_ADDR_INDIRECT:
        {
            uint8_t mod, rm;
            bool needs_sib = false;
            
            // Determine if we need SIB byte
            if (addr->has_index || (addr->has_base && (addr->base_reg & 0x7) == 4)) {
                needs_sib = true;
                rm = 4; // Indicates SIB follows
            } else if (addr->has_base) {
                rm = addr->base_reg & 0x7;
            } else {
                return -1; // Invalid addressing mode
            }
            
            // Determine mod field based on displacement
            if (!addr->has_displacement) {
                mod = 0; // No displacement
                // Special case: if base is RBP (%rbp), we need 8-bit displacement 0
                if (addr->has_base && (addr->base_reg & 0x7) == 5) {
                    mod = 1;
                }
            } else if (addr->displacement >= -128 && addr->displacement <= 127) {
                mod = 1; // 8-bit displacement
            } else {
                mod = 2; // 32-bit displacement
            }
            
            // Encode ModR/M byte
            encoding[(*encoding_len)++] = (mod << 6) | (reg_field << 3) | rm;
            
            // Encode SIB byte if needed
            if (needs_sib) {
                uint8_t scale_bits;
                switch (addr->scale) {
                case 1: scale_bits = 0; break;
                case 2: scale_bits = 1; break;
                case 4: scale_bits = 2; break;
                case 8: scale_bits = 3; break;
                default: return -1;
                }
                
                uint8_t index = addr->has_index ? (addr->index_reg & 0x7) : 4; // 4 = no index
                uint8_t base = addr->has_base ? (addr->base_reg & 0x7) : 5;    // 5 = no base (mod != 0)
                
                encoding[(*encoding_len)++] = (scale_bits << 6) | (index << 3) | base;
            }
            
            // Encode displacement
            if (mod == 1) {
                // 8-bit displacement
                encoding[(*encoding_len)++] = addr->displacement & 0xFF;
            } else if (mod == 2) {
                // 32-bit displacement
                encoding[(*encoding_len)++] = addr->displacement & 0xFF;
                encoding[(*encoding_len)++] = (addr->displacement >> 8) & 0xFF;
                encoding[(*encoding_len)++] = (addr->displacement >> 16) & 0xFF;
                encoding[(*encoding_len)++] = (addr->displacement >> 24) & 0xFF;
            } else if (mod == 0 && addr->has_base && (addr->base_reg & 0x7) == 5) {
                // Special case: RBP base with mod=0 needs 8-bit displacement 0
                encoding[(*encoding_len)++] = 0;
            }
        }
        break;
        
    default:
        return -1;
    }
    
    return 0;
}

//=============================================================================
// Addressing Mode Validation
//=============================================================================

bool x86_64_validate_addressing_mode(const x86_64_address_t *addr) {
    if (!addr) return false;
    
    switch (addr->type) {
    case X86_64_ADDR_IMMEDIATE:
        // Immediate values are always valid (range checked elsewhere)
        return true;
        
    case X86_64_ADDR_REGISTER:
        // Register must be valid
        return addr->base_reg >= AL && addr->base_reg <= GS;
        
    case X86_64_ADDR_DIRECT:
        // Direct addressing with displacement
        return addr->has_displacement;
        
    case X86_64_ADDR_INDIRECT:
        // Must have at least base or index
        if (!addr->has_base && !addr->has_index) return false;
        
        // Validate scale factor
        if (addr->scale != 1 && addr->scale != 2 && addr->scale != 4 && addr->scale != 8) {
            return false;
        }
        
        // Validate registers if present
        if (addr->has_base && (addr->base_reg < RAX || addr->base_reg > R15)) {
            return false;
        }
        if (addr->has_index && (addr->index_reg < RAX || addr->index_reg > R15)) {
            return false;
        }
        
        // RSP cannot be used as index register
        if (addr->has_index && (addr->index_reg & 0x7) == 4) {
            return false;
        }
        
        return true;
        
    default:
        return false;
    }
}

//=============================================================================
// Address Type Detection
//=============================================================================

x86_64_address_type_t x86_64_detect_address_type(const char *addr_str) {
    if (!addr_str) return X86_64_ADDR_INVALID;
    
    // Skip whitespace
    while (isspace(*addr_str)) addr_str++;
    
    if (addr_str[0] == '$') {
        return X86_64_ADDR_IMMEDIATE;
    } else if (addr_str[0] == '%' && strchr(addr_str, '(') == NULL) {
        return X86_64_ADDR_REGISTER;
    } else if (strchr(addr_str, '(')) {
        return X86_64_ADDR_INDIRECT;
    } else {
        return X86_64_ADDR_DIRECT;
    }
}
