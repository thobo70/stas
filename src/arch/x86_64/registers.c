/*
 * x86-64 Register Handling Implementation
 * Register validation, encoding, and name mapping
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

//=============================================================================
// Register Information Database
//=============================================================================

typedef struct {
    const char *name;
    x86_64_register_id_t id;
    uint8_t size;        // Size in bytes
    uint8_t encoding;    // Base encoding (0-7)
    bool requires_rex;   // Requires REX prefix
    uint8_t type;        // 0=GP, 1=Segment, 2=Control, 3=Debug, 4=XMM, etc.
} x86_64_register_info_t;

static const x86_64_register_info_t register_database[] = {
    // 8-bit general purpose registers
    {"al",   AL,   1, 0, false, 0}, {"cl",   CL,   1, 1, false, 0},
    {"dl",   DL,   1, 2, false, 0}, {"bl",   BL,   1, 3, false, 0},
    {"ah",   AH,   1, 4, false, 0}, {"ch",   CH,   1, 5, false, 0},
    {"dh",   DH,   1, 6, false, 0}, {"bh",   BH,   1, 7, false, 0},
    
    // 8-bit registers requiring REX prefix
    {"spl",  SPL,  1, 4, true,  0}, {"bpl",  BPL,  1, 5, true,  0},
    {"sil",  SIL,  1, 6, true,  0}, {"dil",  DIL,  1, 7, true,  0},
    {"r8b",  R8B,  1, 0, true,  0}, {"r9b",  R9B,  1, 1, true,  0},
    {"r10b", R10B, 1, 2, true,  0}, {"r11b", R11B, 1, 3, true,  0},
    {"r12b", R12B, 1, 4, true,  0}, {"r13b", R13B, 1, 5, true,  0},
    {"r14b", R14B, 1, 6, true,  0}, {"r15b", R15B, 1, 7, true,  0},
    
    // 16-bit general purpose registers
    {"ax",   AX,   2, 0, false, 0}, {"cx",   CX,   2, 1, false, 0},
    {"dx",   DX,   2, 2, false, 0}, {"bx",   BX,   2, 3, false, 0},
    {"sp",   SP,   2, 4, false, 0}, {"bp",   BP,   2, 5, false, 0},
    {"si",   SI,   2, 6, false, 0}, {"di",   DI,   2, 7, false, 0},
    {"r8w",  R8W,  2, 0, true,  0}, {"r9w",  R9W,  2, 1, true,  0},
    {"r10w", R10W, 2, 2, true,  0}, {"r11w", R11W, 2, 3, true,  0},
    {"r12w", R12W, 2, 4, true,  0}, {"r13w", R13W, 2, 5, true,  0},
    {"r14w", R14W, 2, 6, true,  0}, {"r15w", R15W, 2, 7, true,  0},
    
    // 32-bit general purpose registers
    {"eax",  EAX,  4, 0, false, 0}, {"ecx",  ECX,  4, 1, false, 0},
    {"edx",  EDX,  4, 2, false, 0}, {"ebx",  EBX,  4, 3, false, 0},
    {"esp",  ESP,  4, 4, false, 0}, {"ebp",  EBP,  4, 5, false, 0},
    {"esi",  ESI,  4, 6, false, 0}, {"edi",  EDI,  4, 7, false, 0},
    {"r8d",  R8D,  4, 0, true,  0}, {"r9d",  R9D,  4, 1, true,  0},
    {"r10d", R10D, 4, 2, true,  0}, {"r11d", R11D, 4, 3, true,  0},
    {"r12d", R12D, 4, 4, true,  0}, {"r13d", R13D, 4, 5, true,  0},
    {"r14d", R14D, 4, 6, true,  0}, {"r15d", R15D, 4, 7, true,  0},
    
    // 64-bit general purpose registers
    {"rax",  RAX,  8, 0, false, 0}, {"rcx",  RCX,  8, 1, false, 0},
    {"rdx",  RDX,  8, 2, false, 0}, {"rbx",  RBX,  8, 3, false, 0},
    {"rsp",  RSP,  8, 4, false, 0}, {"rbp",  RBP,  8, 5, false, 0},
    {"rsi",  RSI,  8, 6, false, 0}, {"rdi",  RDI,  8, 7, false, 0},
    {"r8",   R8,   8, 0, true,  0}, {"r9",   R9,   8, 1, true,  0},
    {"r10",  R10,  8, 2, true,  0}, {"r11",  R11,  8, 3, true,  0},
    {"r12",  R12,  8, 4, true,  0}, {"r13",  R13,  8, 5, true,  0},
    {"r14",  R14,  8, 6, true,  0}, {"r15",  R15,  8, 7, true,  0},
    
    // Special registers
    {"rip",    RIP,    8, 0, false, 2}, // Instruction pointer
    {"rflags", RFLAGS, 8, 0, false, 2}, // Flags register
    
    {NULL, 0, 0, 0, false, 0} // Sentinel
};

//=============================================================================
// Register Lookup Functions
//=============================================================================

static char *normalize_register_name(const char *name) {
    if (!name) return NULL;
    
    // Remove % prefix if present
    const char *clean_name = name;
    if (name[0] == '%') {
        clean_name++;
    }
    
    // Convert to lowercase
    size_t len = strlen(clean_name);
    char *normalized = malloc(len + 1);
    if (!normalized) return NULL;
    
    for (size_t i = 0; i < len; i++) {
        normalized[i] = tolower(clean_name[i]);
    }
    normalized[len] = '\0';
    
    return normalized;
}

const x86_64_register_info_t *find_register_info(const char *name) {
    char *normalized = normalize_register_name(name);
    if (!normalized) return NULL;
    
    for (int i = 0; register_database[i].name != NULL; i++) {
        if (strcmp(normalized, register_database[i].name) == 0) {
            free(normalized);
            return &register_database[i];
        }
    }
    
    free(normalized);
    return NULL;
}

const x86_64_register_info_t *find_register_by_id(x86_64_register_id_t id) {
    for (int i = 0; register_database[i].name != NULL; i++) {
        if (register_database[i].id == id) {
            return &register_database[i];
        }
    }
    return NULL;
}

//=============================================================================
// Register Validation Functions
//=============================================================================

bool is_8bit_register(x86_64_register_id_t id) {
    return (id >= AL && id <= BH) || (id >= SPL && id <= R15B);
}

bool is_16bit_register(x86_64_register_id_t id) {
    return (id >= AX && id <= DI) || (id >= R8W && id <= R15W);
}

bool is_32bit_register(x86_64_register_id_t id) {
    return (id >= EAX && id <= EDI) || (id >= R8D && id <= R15D);
}

bool is_64bit_register(x86_64_register_id_t id) {
    return (id >= RAX && id <= RDI) || (id >= R8 && id <= R15);
}

bool is_extended_register(x86_64_register_id_t id) {
    return (id >= R8B && id <= R15B) ||  // 8-bit extended
           (id >= R8W && id <= R15W) ||  // 16-bit extended
           (id >= R8D && id <= R15D) ||  // 32-bit extended
           (id >= R8 && id <= R15);      // 64-bit extended
}

bool can_be_index_register(x86_64_register_id_t id) {
    // RSP cannot be used as index register in SIB addressing
    return is_64bit_register(id) && id != RSP;
}

bool can_be_base_register(x86_64_register_id_t id) {
    // Any 64-bit register can be used as base
    return is_64bit_register(id);
}

//=============================================================================
// Register Encoding Functions
//=============================================================================

int get_register_encoding_info(asm_register_t reg, uint8_t *encoding, bool *needs_rex) {
    const x86_64_register_info_t *info = find_register_by_id(reg.id);
    if (!info) {
        return -1;
    }
    
    *encoding = info->encoding;
    *needs_rex = info->requires_rex;
    
    return 0;
}

int get_register_size_class(asm_register_t reg) {
    const x86_64_register_info_t *info = find_register_by_id(reg.id);
    if (!info) {
        return -1;
    }
    
    return info->size;
}

bool registers_compatible(asm_register_t reg1, asm_register_t reg2) {
    // Check if two registers can be used together in an instruction
    int size1 = get_register_size_class(reg1);
    int size2 = get_register_size_class(reg2);
    
    if (size1 < 0 || size2 < 0) {
        return false;
    }
    
    // Generally, registers should be the same size
    // Some exceptions exist for certain instructions
    return size1 == size2;
}

//=============================================================================
// Register Name Generation
//=============================================================================

const char *get_register_canonical_name(x86_64_register_id_t id) {
    const x86_64_register_info_t *info = find_register_by_id(id);
    return info ? info->name : NULL;
}

char *get_register_at_size(x86_64_register_id_t base_id, uint8_t size) {
    // Convert a register to a different size variant
    // e.g., RAX -> EAX (size 4), AX (size 2), AL (size 1)
    
    // Find the base register (assuming it's a 64-bit register)
    if (!is_64bit_register(base_id)) {
        return NULL;
    }
    
    // Map 64-bit register to other sizes
    int base_offset = base_id - RAX;
    if (base_offset < 0 || base_offset > 15) {
        return NULL;
    }
    
    x86_64_register_id_t target_id;
    
    switch (size) {
        case 1: // 8-bit
            if (base_offset < 8) {
                target_id = AL + base_offset;
            } else {
                target_id = R8B + (base_offset - 8);
            }
            break;
            
        case 2: // 16-bit
            if (base_offset < 8) {
                target_id = AX + base_offset;
            } else {
                target_id = R8W + (base_offset - 8);
            }
            break;
            
        case 4: // 32-bit
            if (base_offset < 8) {
                target_id = EAX + base_offset;
            } else {
                target_id = R8D + (base_offset - 8);
            }
            break;
            
        case 8: // 64-bit
            target_id = base_id;
            break;
            
        default:
            return NULL;
    }
    
    const char *name = get_register_canonical_name(target_id);
    return name ? safe_strdup(name) : NULL;
}

//=============================================================================
// Register Conflict Detection
//=============================================================================

bool registers_conflict(asm_register_t reg1, asm_register_t reg2) {
    // Check if two registers refer to overlapping parts of the same physical register
    
    // Get the base 64-bit register for each
    x86_64_register_id_t base1 = reg1.id;
    x86_64_register_id_t base2 = reg2.id;
    
    // Convert to base 64-bit register IDs
    if (is_8bit_register(reg1.id)) {
        if (reg1.id <= DI) {
            base1 = RAX + (reg1.id - AL);
        } else if (reg1.id >= R8B && reg1.id <= R15B) {
            base1 = R8 + (reg1.id - R8B);
        }
    } else if (is_16bit_register(reg1.id)) {
        if (reg1.id >= AX && reg1.id <= DI) {
            base1 = RAX + (reg1.id - AX);
        } else if (reg1.id >= R8W && reg1.id <= R15W) {
            base1 = R8 + (reg1.id - R8W);
        }
    } else if (is_32bit_register(reg1.id)) {
        if (reg1.id >= EAX && reg1.id <= EDI) {
            base1 = RAX + (reg1.id - EAX);
        } else if (reg1.id >= R8D && reg1.id <= R15D) {
            base1 = R8 + (reg1.id - R8D);
        }
    }
    
    // Similar conversion for reg2
    if (is_8bit_register(reg2.id)) {
        if (reg2.id <= DI) {
            base2 = RAX + (reg2.id - AL);
        } else if (reg2.id >= R8B && reg2.id <= R15B) {
            base2 = R8 + (reg2.id - R8B);
        }
    } else if (is_16bit_register(reg2.id)) {
        if (reg2.id >= AX && reg2.id <= DI) {
            base2 = RAX + (reg2.id - AX);
        } else if (reg2.id >= R8W && reg2.id <= R15W) {
            base2 = R8 + (reg2.id - R8W);
        }
    } else if (is_32bit_register(reg2.id)) {
        if (reg2.id >= EAX && reg2.id <= EDI) {
            base2 = RAX + (reg2.id - EAX);
        } else if (reg2.id >= R8D && reg2.id <= R15D) {
            base2 = R8 + (reg2.id - R8D);
        }
    }
    
    return base1 == base2;
}
