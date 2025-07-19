#ifndef ELF_H
#define ELF_H

#include <stdint.h>
#include <stddef.h>
#include "output_format.h"

// ELF Header constants
#define EI_NIDENT 16
#define EI_MAG0    0
#define EI_MAG1    1
#define EI_MAG2    2
#define EI_MAG3    3
#define EI_CLASS   4
#define EI_DATA    5
#define EI_VERSION 6
#define EI_OSABI   7
#define EI_ABIVERSION 8
#define EI_PAD     9

// ELF Magic numbers
#define ELFMAG0 0x7f
#define ELFMAG1 'E'
#define ELFMAG2 'L'
#define ELFMAG3 'F'

// ELF Classes
#define ELFCLASSNONE 0
#define ELFCLASS32   1
#define ELFCLASS64   2

// ELF Data encoding
#define ELFDATANONE 0
#define ELFDATA2LSB 1  // Little endian
#define ELFDATA2MSB 2  // Big endian

// ELF Version
#define EV_NONE    0
#define EV_CURRENT 1

// ELF OS/ABI
#define ELFOSABI_NONE    0  // System V
#define ELFOSABI_LINUX   3  // Linux
#define ELFOSABI_FREEBSD 9  // FreeBSD

// ELF File types
#define ET_NONE 0  // No file type
#define ET_REL  1  // Relocatable file
#define ET_EXEC 2  // Executable file
#define ET_DYN  3  // Shared object file
#define ET_CORE 4  // Core file

// ELF Machine types
#define EM_NONE  0   // No machine
#define EM_386   3   // Intel 80386
#define EM_X86_64 62 // AMD x86-64 architecture

// Section header types
#define SHT_NULL     0  // Section header table entry unused
#define SHT_PROGBITS 1  // Program data
#define SHT_SYMTAB   2  // Symbol table
#define SHT_STRTAB   3  // String table
#define SHT_RELA     4  // Relocation entries with addends
#define SHT_HASH     5  // Symbol hash table
#define SHT_DYNAMIC  6  // Dynamic linking information
#define SHT_NOTE     7  // Notes
#define SHT_NOBITS   8  // Program space with no data (bss)
#define SHT_REL      9  // Relocation entries, no addends
#define SHT_SHLIB    10 // Reserved
#define SHT_DYNSYM   11 // Dynamic linker symbol table

// Section header flags
#define SHF_WRITE     0x1  // Writable
#define SHF_ALLOC     0x2  // Occupies memory during execution
#define SHF_EXECINSTR 0x4  // Executable
#define SHF_MERGE     0x10 // Might be merged
#define SHF_STRINGS   0x20 // Contains nul-terminated strings
#define SHF_INFO_LINK 0x40 // 'sh_info' contains SHT index
#define SHF_LINK_ORDER 0x80 // Preserve order after combining

// Symbol binding
#define STB_LOCAL  0  // Local symbol
#define STB_GLOBAL 1  // Global symbol
#define STB_WEAK   2  // Weak symbol

// Symbol types
#define STT_NOTYPE  0  // Symbol type is not specified
#define STT_OBJECT  1  // Symbol is a data object
#define STT_FUNC    2  // Symbol is a function
#define STT_SECTION 3  // Symbol associated with a section
#define STT_FILE    4  // Symbol's name is file name

// Relocation types for x86-64
#define R_X86_64_NONE     0  // No relocation
#define R_X86_64_64       1  // Direct 64 bit
#define R_X86_64_PC32     2  // PC relative 32 bit signed
#define R_X86_64_GOT32    3  // 32 bit GOT entry
#define R_X86_64_PLT32    4  // 32 bit PLT address
#define R_X86_64_COPY     5  // Copy symbol at runtime
#define R_X86_64_GLOB_DAT 6  // Create GOT entry
#define R_X86_64_JUMP_SLOT 7 // Create PLT entry
#define R_X86_64_RELATIVE 8  // Adjust by program base
#define R_X86_64_GOTPCREL 9  // 32 bit signed PC relative offset to GOT
#define R_X86_64_32       10 // Direct 32 bit zero extended
#define R_X86_64_32S      11 // Direct 32 bit sign extended

// ELF64 Header
typedef struct {
    unsigned char e_ident[EI_NIDENT]; // Magic number and other info
    uint16_t e_type;                  // Object file type
    uint16_t e_machine;               // Architecture
    uint32_t e_version;               // Object file version
    uint64_t e_entry;                 // Entry point virtual address
    uint64_t e_phoff;                 // Program header table file offset
    uint64_t e_shoff;                 // Section header table file offset
    uint32_t e_flags;                 // Processor-specific flags
    uint16_t e_ehsize;                // ELF header size in bytes
    uint16_t e_phentsize;             // Program header table entry size
    uint16_t e_phnum;                 // Program header table entry count
    uint16_t e_shentsize;             // Section header table entry size
    uint16_t e_shnum;                 // Section header table entry count
    uint16_t e_shstrndx;              // Section header string table index
} elf64_ehdr_t;

// ELF32 Header
typedef struct {
    unsigned char e_ident[EI_NIDENT]; // Magic number and other info
    uint16_t e_type;                  // Object file type
    uint16_t e_machine;               // Architecture
    uint32_t e_version;               // Object file version
    uint32_t e_entry;                 // Entry point virtual address
    uint32_t e_phoff;                 // Program header table file offset
    uint32_t e_shoff;                 // Section header table file offset
    uint32_t e_flags;                 // Processor-specific flags
    uint16_t e_ehsize;                // ELF header size in bytes
    uint16_t e_phentsize;             // Program header table entry size
    uint16_t e_phnum;                 // Program header table entry count
    uint16_t e_shentsize;             // Section header table entry size
    uint16_t e_shnum;                 // Section header table entry count
    uint16_t e_shstrndx;              // Section header string table index
} elf32_ehdr_t;

// ELF64 Section Header
typedef struct {
    uint32_t sh_name;      // Section name (string tbl index)
    uint32_t sh_type;      // Section type
    uint64_t sh_flags;     // Section flags
    uint64_t sh_addr;      // Section virtual addr at execution
    uint64_t sh_offset;    // Section file offset
    uint64_t sh_size;      // Section size in bytes
    uint32_t sh_link;      // Link to another section
    uint32_t sh_info;      // Additional section information
    uint64_t sh_addralign; // Section alignment
    uint64_t sh_entsize;   // Entry size if section holds table
} elf64_shdr_t;

// ELF32 Section Header
typedef struct {
    uint32_t sh_name;      // Section name (string tbl index)
    uint32_t sh_type;      // Section type
    uint32_t sh_flags;     // Section flags
    uint32_t sh_addr;      // Section virtual addr at execution
    uint32_t sh_offset;    // Section file offset
    uint32_t sh_size;      // Section size in bytes
    uint32_t sh_link;      // Link to another section
    uint32_t sh_info;      // Additional section information
    uint32_t sh_addralign; // Section alignment
    uint32_t sh_entsize;   // Entry size if section holds table
} elf32_shdr_t;

// ELF64 Symbol Table Entry
typedef struct {
    uint32_t st_name;  // Symbol name (string table index)
    uint8_t st_info;   // Symbol type and binding
    uint8_t st_other;  // Symbol visibility
    uint16_t st_shndx; // Section index
    uint64_t st_value; // Symbol value
    uint64_t st_size;  // Symbol size
} elf64_sym_t;

// ELF32 Symbol Table Entry
typedef struct {
    uint32_t st_name;  // Symbol name (string table index)
    uint32_t st_value; // Symbol value
    uint32_t st_size;  // Symbol size
    uint8_t st_info;   // Symbol type and binding
    uint8_t st_other;  // Symbol visibility
    uint16_t st_shndx; // Section index
} elf32_sym_t;

// ELF64 Relocation Entry with Addend
typedef struct {
    uint64_t r_offset; // Location at which to apply the action
    uint64_t r_info;   // Relocation type and symbol index
    int64_t r_addend;  // Addend used to compute value to be stored
} elf64_rela_t;

// ELF32 Relocation Entry with Addend
typedef struct {
    uint32_t r_offset; // Location at which to apply the action
    uint32_t r_info;   // Relocation type and symbol index
    int32_t r_addend;  // Addend used to compute value to be stored
} elf32_rela_t;

// ELF64 Relocation Entry without Addend
typedef struct {
    uint64_t r_offset; // Location at which to apply the action
    uint64_t r_info;   // Relocation type and symbol index
} elf64_rel_t;

// ELF32 Relocation Entry without Addend
typedef struct {
    uint32_t r_offset; // Location at which to apply the action
    uint32_t r_info;   // Relocation type and symbol index
} elf32_rel_t;

// ELF manipulation macros
#define ELF64_R_SYM(info)  ((info) >> 32)
#define ELF64_R_TYPE(info) ((info) & 0xffffffff)
#define ELF64_R_INFO(sym, type) (((uint64_t)(sym) << 32) + (type))

#define ELF32_R_SYM(info)  ((info) >> 8)
#define ELF32_R_TYPE(info) ((unsigned char)(info))
#define ELF32_R_INFO(sym, type) (((sym) << 8) + (unsigned char)(type))

#define ELF64_ST_BIND(info) ((info) >> 4)
#define ELF64_ST_TYPE(info) ((info) & 0xf)
#define ELF64_ST_INFO(bind, type) (((bind) << 4) + ((type) & 0xf))

#define ELF32_ST_BIND(info) ((info) >> 4)
#define ELF32_ST_TYPE(info) ((info) & 0xf)
#define ELF32_ST_INFO(bind, type) (((bind) << 4) + ((type) & 0xf))

// ELF Context for building ELF files
typedef struct {
    int is_64bit;
    uint16_t machine_type;
    
    // Sections
    size_t section_count;
    size_t section_capacity;
    elf64_shdr_t *sections64;
    elf32_shdr_t *sections32;
    
    // Section data
    uint8_t **section_data;
    size_t *section_data_sizes;
    
    // String tables
    char *shstrtab;     // Section header string table
    size_t shstrtab_size;
    size_t shstrtab_capacity;
    
    char *strtab;       // Symbol string table
    size_t strtab_size;
    size_t strtab_capacity;
    
    // Symbol table
    void *symtab;       // Points to elf64_sym_t* or elf32_sym_t*
    size_t symbol_count;
    size_t symbol_capacity;
    
    // Relocations
    void *relocations;  // Points to elf64_rela_t* or elf32_rela_t*
    size_t relocation_count;
    size_t relocation_capacity;
    
} elf_context_t;

// Function declarations
output_format_ops_t *get_elf32_format(void);
output_format_ops_t *get_elf64_format(void);

// ELF building functions
elf_context_t *elf_context_create(int is_64bit, uint16_t machine_type);
void elf_context_free(elf_context_t *ctx);

int elf_add_section(elf_context_t *ctx, const char *name, uint32_t type, 
                   uint64_t flags, const uint8_t *data, size_t size);
int elf_add_symbol(elf_context_t *ctx, const char *name, uint64_t value, 
                  uint64_t size, uint8_t info, uint16_t shndx);
int elf_add_relocation(elf_context_t *ctx, uint64_t offset, uint64_t info, 
                      int64_t addend);

int elf_write_file(elf_context_t *ctx, const char *filename, int verbose);

// String table functions
uint32_t elf_add_string(char **strtab, size_t *size, size_t *capacity, 
                       const char *str);

#endif // ELF_H
