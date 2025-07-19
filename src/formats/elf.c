#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <unistd.h>
#include "formats/elf.h"
#include "output_format.h"

// Forward declarations for format operations
static int elf32_write_file(output_context_t *ctx);
static int elf32_add_section(output_context_t *ctx, const char *name, 
                            uint8_t *data, size_t size, uint32_t address);
static void elf32_cleanup(output_context_t *ctx);

static int elf64_write_file(output_context_t *ctx);
static int elf64_add_section(output_context_t *ctx, const char *name, 
                            uint8_t *data, size_t size, uint32_t address);
static void elf64_cleanup(output_context_t *ctx);

// Format operation structures
static output_format_ops_t elf32_ops = {
    .write_file = elf32_write_file,
    .add_section = elf32_add_section,
    .cleanup = elf32_cleanup
};

static output_format_ops_t elf64_ops = {
    .write_file = elf64_write_file,
    .add_section = elf64_add_section,
    .cleanup = elf64_cleanup
};

// Export format getters
output_format_ops_t *get_elf32_format(void) {
    return &elf32_ops;
}

output_format_ops_t *get_elf64_format(void) {
    return &elf64_ops;
}

// String table functions
uint32_t elf_add_string(char **strtab, size_t *size, size_t *capacity, 
                       const char *str) {
    if (!str || !*str) {
        return 0; // Empty string is at offset 0
    }
    
    size_t len = strlen(str);
    
    // Check if we need to resize the string table
    if (*size + len + 1 >= *capacity) {
        size_t new_capacity = *capacity * 2;
        if (new_capacity < *size + len + 1) {
            new_capacity = *size + len + 1 + 256;
        }
        
        char *new_strtab = realloc(*strtab, new_capacity);
        if (!new_strtab) {
            return 0;
        }
        
        *strtab = new_strtab;
        *capacity = new_capacity;
    }
    
    uint32_t offset = (uint32_t)*size;
    strcpy(*strtab + *size, str);
    *size += len + 1;
    
    return offset;
}

// ELF Context functions
elf_context_t *elf_context_create(int is_64bit, uint16_t machine_type) {
    elf_context_t *ctx = calloc(1, sizeof(elf_context_t));
    if (!ctx) {
        return NULL;
    }
    
    ctx->is_64bit = is_64bit;
    ctx->machine_type = machine_type;
    
    // Initialize section capacity
    ctx->section_capacity = 16;
    if (is_64bit) {
        ctx->sections64 = calloc(ctx->section_capacity, sizeof(elf64_shdr_t));
        if (!ctx->sections64) {
            free(ctx);
            return NULL;
        }
    } else {
        ctx->sections32 = calloc(ctx->section_capacity, sizeof(elf32_shdr_t));
        if (!ctx->sections32) {
            free(ctx);
            return NULL;
        }
    }
    
    ctx->section_data = calloc(ctx->section_capacity, sizeof(uint8_t*));
    ctx->section_data_sizes = calloc(ctx->section_capacity, sizeof(size_t));
    
    if (!ctx->section_data || !ctx->section_data_sizes) {
        elf_context_free(ctx);
        return NULL;
    }
    
    // Initialize string tables with null string
    ctx->shstrtab_capacity = 256;
    ctx->shstrtab = calloc(ctx->shstrtab_capacity, 1);
    ctx->shstrtab_size = 1; // Start with null string
    
    ctx->strtab_capacity = 256;
    ctx->strtab = calloc(ctx->strtab_capacity, 1);
    ctx->strtab_size = 1; // Start with null string
    
    if (!ctx->shstrtab || !ctx->strtab) {
        elf_context_free(ctx);
        return NULL;
    }
    
    // Initialize symbol table capacity
    ctx->symbol_capacity = 16;
    if (is_64bit) {
        ctx->symtab = calloc(ctx->symbol_capacity, sizeof(elf64_sym_t));
    } else {
        ctx->symtab = calloc(ctx->symbol_capacity, sizeof(elf32_sym_t));
    }
    
    if (!ctx->symtab) {
        elf_context_free(ctx);
        return NULL;
    }
    
    // Add the mandatory NULL section at index 0
    elf_add_section(ctx, "", SHT_NULL, 0, NULL, 0);
    
    return ctx;
}

void elf_context_free(elf_context_t *ctx) {
    if (!ctx) {
        return;
    }
    
    // Free section data
    if (ctx->section_data) {
        for (size_t i = 0; i < ctx->section_count; i++) {
            free(ctx->section_data[i]);
        }
        free(ctx->section_data);
    }
    
    free(ctx->section_data_sizes);
    free(ctx->sections64);
    free(ctx->sections32);
    free(ctx->shstrtab);
    free(ctx->strtab);
    free(ctx->symtab);
    free(ctx->relocations);
    free(ctx);
}

int elf_add_section(elf_context_t *ctx, const char *name, uint32_t type, 
                   uint64_t flags, const uint8_t *data, size_t size) {
    if (!ctx) {
        return -1;
    }
    
    // Resize section arrays if needed
    if (ctx->section_count >= ctx->section_capacity) {
        size_t new_capacity = ctx->section_capacity * 2;
        
        void *new_sections = NULL;
        if (ctx->is_64bit) {
            new_sections = realloc(ctx->sections64, 
                                 new_capacity * sizeof(elf64_shdr_t));
            if (!new_sections) {
                return -1;
            }
            ctx->sections64 = new_sections;
        } else {
            new_sections = realloc(ctx->sections32, 
                                 new_capacity * sizeof(elf32_shdr_t));
            if (!new_sections) {
                return -1;
            }
            ctx->sections32 = new_sections;
        }
        
        uint8_t **new_data = realloc(ctx->section_data, 
                                   new_capacity * sizeof(uint8_t*));
        size_t *new_sizes = realloc(ctx->section_data_sizes, 
                                  new_capacity * sizeof(size_t));
        
        if (!new_data || !new_sizes) {
            return -1;
        }
        
        ctx->section_data = new_data;
        ctx->section_data_sizes = new_sizes;
        ctx->section_capacity = new_capacity;
    }
    
    // Add section name to string table
    uint32_t name_offset = elf_add_string(&ctx->shstrtab, &ctx->shstrtab_size, 
                                        &ctx->shstrtab_capacity, name);
    
    // Copy section data
    uint8_t *section_data_copy = NULL;
    if (data && size > 0) {
        section_data_copy = malloc(size);
        if (!section_data_copy) {
            return -1;
        }
        memcpy(section_data_copy, data, size);
    }
    
    // Fill section header
    size_t idx = ctx->section_count;
    ctx->section_data[idx] = section_data_copy;
    ctx->section_data_sizes[idx] = size;
    
    if (ctx->is_64bit) {
        elf64_shdr_t *shdr = &ctx->sections64[idx];
        shdr->sh_name = name_offset;
        shdr->sh_type = type;
        shdr->sh_flags = flags;
        shdr->sh_addr = 0; // Will be set later
        shdr->sh_offset = 0; // Will be set when writing
        shdr->sh_size = size;
        shdr->sh_link = 0;
        shdr->sh_info = 0;
        shdr->sh_addralign = (type == SHT_PROGBITS) ? 1 : 0;
        shdr->sh_entsize = 0;
    } else {
        elf32_shdr_t *shdr = &ctx->sections32[idx];
        shdr->sh_name = name_offset;
        shdr->sh_type = type;
        shdr->sh_flags = (uint32_t)flags;
        shdr->sh_addr = 0; // Will be set later
        shdr->sh_offset = 0; // Will be set when writing
        shdr->sh_size = (uint32_t)size;
        shdr->sh_link = 0;
        shdr->sh_info = 0;
        shdr->sh_addralign = (type == SHT_PROGBITS) ? 1 : 0;
        shdr->sh_entsize = 0;
    }
    
    ctx->section_count++;
    return (int)idx;
}

int elf_add_symbol(elf_context_t *ctx, const char *name, uint64_t value, 
                  uint64_t size, uint8_t info, uint16_t shndx) {
    if (!ctx) {
        return -1;
    }
    
    // Resize symbol table if needed
    if (ctx->symbol_count >= ctx->symbol_capacity) {
        size_t new_capacity = ctx->symbol_capacity * 2;
        size_t entry_size = ctx->is_64bit ? sizeof(elf64_sym_t) : sizeof(elf32_sym_t);
        
        void *new_symtab = realloc(ctx->symtab, new_capacity * entry_size);
        if (!new_symtab) {
            return -1;
        }
        
        ctx->symtab = new_symtab;
        ctx->symbol_capacity = new_capacity;
    }
    
    // Add symbol name to string table
    uint32_t name_offset = elf_add_string(&ctx->strtab, &ctx->strtab_size, 
                                        &ctx->strtab_capacity, name);
    
    // Fill symbol entry
    size_t idx = ctx->symbol_count;
    
    if (ctx->is_64bit) {
        elf64_sym_t *sym = &((elf64_sym_t*)ctx->symtab)[idx];
        sym->st_name = name_offset;
        sym->st_info = info;
        sym->st_other = 0;
        sym->st_shndx = shndx;
        sym->st_value = value;
        sym->st_size = size;
    } else {
        elf32_sym_t *sym = &((elf32_sym_t*)ctx->symtab)[idx];
        sym->st_name = name_offset;
        sym->st_value = (uint32_t)value;
        sym->st_size = (uint32_t)size;
        sym->st_info = info;
        sym->st_other = 0;
        sym->st_shndx = shndx;
    }
    
    ctx->symbol_count++;
    return (int)idx;
}

int elf_write_file(elf_context_t *ctx, const char *filename, int verbose) {
    if (!ctx || !filename) {
        return -1;
    }
    
    FILE *f = fopen(filename, "wb");
    if (!f) {
        if (verbose) {
            fprintf(stderr, "Error: Cannot create ELF file '%s': %s\n", 
                    filename, strerror(errno));
        }
        return -1;
    }
    
    // Add string tables as sections if we have symbols
    int shstrtab_idx = -1, strtab_idx = -1, symtab_idx = -1;
    
    // Add section header string table
    shstrtab_idx = elf_add_section(ctx, ".shstrtab", SHT_STRTAB, 0, 
                                  (uint8_t*)ctx->shstrtab, ctx->shstrtab_size);
    
    // Add symbol string table and symbol table if we have symbols
    if (ctx->symbol_count > 0) {
        strtab_idx = elf_add_section(ctx, ".strtab", SHT_STRTAB, 0, 
                                   (uint8_t*)ctx->strtab, ctx->strtab_size);
        
        size_t symtab_size = ctx->symbol_count * 
            (ctx->is_64bit ? sizeof(elf64_sym_t) : sizeof(elf32_sym_t));
        symtab_idx = elf_add_section(ctx, ".symtab", SHT_SYMTAB, 0, 
                                   (uint8_t*)ctx->symtab, symtab_size);
        
        // Set up symbol table section linking
        if (ctx->is_64bit) {
            ctx->sections64[symtab_idx].sh_link = strtab_idx;
            ctx->sections64[symtab_idx].sh_info = 1; // First non-local symbol
            ctx->sections64[symtab_idx].sh_addralign = 8;
            ctx->sections64[symtab_idx].sh_entsize = sizeof(elf64_sym_t);
        } else {
            ctx->sections32[symtab_idx].sh_link = strtab_idx;
            ctx->sections32[symtab_idx].sh_info = 1; // First non-local symbol
            ctx->sections32[symtab_idx].sh_addralign = 4;
            ctx->sections32[symtab_idx].sh_entsize = sizeof(elf32_sym_t);
        }
    }
    
    // Calculate section offsets
    size_t current_offset;
    if (ctx->is_64bit) {
        current_offset = sizeof(elf64_ehdr_t);
    } else {
        current_offset = sizeof(elf32_ehdr_t);
    }
    
    // Set section offsets and addresses
    for (size_t i = 1; i < ctx->section_count; i++) { // Skip NULL section
        // Align to appropriate boundary
        size_t alignment = 1;
        if (ctx->is_64bit) {
            alignment = ctx->sections64[i].sh_addralign;
            if (alignment > 1) {
                current_offset = (current_offset + alignment - 1) & ~(alignment - 1);
            }
            ctx->sections64[i].sh_offset = current_offset;
            current_offset += ctx->sections64[i].sh_size;
        } else {
            alignment = ctx->sections32[i].sh_addralign;
            if (alignment > 1) {
                current_offset = (current_offset + alignment - 1) & ~(alignment - 1);
            }
            ctx->sections32[i].sh_offset = current_offset;
            current_offset += ctx->sections32[i].sh_size;
        }
    }
    
    // Calculate section header table offset
    size_t shdr_alignment = ctx->is_64bit ? 8 : 4;
    current_offset = (current_offset + shdr_alignment - 1) & ~(shdr_alignment - 1);
    size_t shdr_offset = current_offset;
    
    // Write ELF header
    if (ctx->is_64bit) {
        elf64_ehdr_t ehdr = {0};
        
        // ELF identification
        ehdr.e_ident[EI_MAG0] = ELFMAG0;
        ehdr.e_ident[EI_MAG1] = ELFMAG1;
        ehdr.e_ident[EI_MAG2] = ELFMAG2;
        ehdr.e_ident[EI_MAG3] = ELFMAG3;
        ehdr.e_ident[EI_CLASS] = ELFCLASS64;
        ehdr.e_ident[EI_DATA] = ELFDATA2LSB;
        ehdr.e_ident[EI_VERSION] = EV_CURRENT;
        ehdr.e_ident[EI_OSABI] = ELFOSABI_NONE;
        ehdr.e_ident[EI_ABIVERSION] = 0;
        
        ehdr.e_type = ET_REL; // Relocatable file
        ehdr.e_machine = ctx->machine_type;
        ehdr.e_version = EV_CURRENT;
        ehdr.e_entry = 0; // No entry point for object files
        ehdr.e_phoff = 0; // No program headers
        ehdr.e_shoff = shdr_offset;
        ehdr.e_flags = 0;
        ehdr.e_ehsize = sizeof(elf64_ehdr_t);
        ehdr.e_phentsize = 0;
        ehdr.e_phnum = 0;
        ehdr.e_shentsize = sizeof(elf64_shdr_t);
        ehdr.e_shnum = (uint16_t)ctx->section_count;
        ehdr.e_shstrndx = (uint16_t)shstrtab_idx;
        
        if (fwrite(&ehdr, sizeof(ehdr), 1, f) != 1) {
            fclose(f);
            return -1;
        }
    } else {
        elf32_ehdr_t ehdr = {0};
        
        // ELF identification
        ehdr.e_ident[EI_MAG0] = ELFMAG0;
        ehdr.e_ident[EI_MAG1] = ELFMAG1;
        ehdr.e_ident[EI_MAG2] = ELFMAG2;
        ehdr.e_ident[EI_MAG3] = ELFMAG3;
        ehdr.e_ident[EI_CLASS] = ELFCLASS32;
        ehdr.e_ident[EI_DATA] = ELFDATA2LSB;
        ehdr.e_ident[EI_VERSION] = EV_CURRENT;
        ehdr.e_ident[EI_OSABI] = ELFOSABI_NONE;
        ehdr.e_ident[EI_ABIVERSION] = 0;
        
        ehdr.e_type = ET_REL; // Relocatable file
        ehdr.e_machine = ctx->machine_type;
        ehdr.e_version = EV_CURRENT;
        ehdr.e_entry = 0; // No entry point for object files
        ehdr.e_phoff = 0; // No program headers
        ehdr.e_shoff = (uint32_t)shdr_offset;
        ehdr.e_flags = 0;
        ehdr.e_ehsize = sizeof(elf32_ehdr_t);
        ehdr.e_phentsize = 0;
        ehdr.e_phnum = 0;
        ehdr.e_shentsize = sizeof(elf32_shdr_t);
        ehdr.e_shnum = (uint16_t)ctx->section_count;
        ehdr.e_shstrndx = (uint16_t)shstrtab_idx;
        
        if (fwrite(&ehdr, sizeof(ehdr), 1, f) != 1) {
            fclose(f);
            return -1;
        }
    }
    
    // Write section data
    for (size_t i = 1; i < ctx->section_count; i++) { // Skip NULL section
        size_t target_offset;
        size_t section_size;
        
        if (ctx->is_64bit) {
            target_offset = ctx->sections64[i].sh_offset;
            section_size = ctx->sections64[i].sh_size;
        } else {
            target_offset = ctx->sections32[i].sh_offset;
            section_size = ctx->sections32[i].sh_size;
        }
        
        // Seek to section offset
        if (fseek(f, (long)target_offset, SEEK_SET) != 0) {
            fclose(f);
            return -1;
        }
        
        // Write section data
        if (section_size > 0 && ctx->section_data[i]) {
            if (fwrite(ctx->section_data[i], section_size, 1, f) != 1) {
                fclose(f);
                return -1;
            }
        }
    }
    
    // Write section header table
    if (fseek(f, (long)shdr_offset, SEEK_SET) != 0) {
        fclose(f);
        return -1;
    }
    
    if (ctx->is_64bit) {
        if (fwrite(ctx->sections64, sizeof(elf64_shdr_t), ctx->section_count, f) 
            != ctx->section_count) {
            fclose(f);
            return -1;
        }
    } else {
        if (fwrite(ctx->sections32, sizeof(elf32_shdr_t), ctx->section_count, f) 
            != ctx->section_count) {
            fclose(f);
            return -1;
        }
    }
    
    fclose(f);
    
    if (verbose) {
        printf("Successfully wrote ELF%d file '%s' with %zu sections\n",
               ctx->is_64bit ? 64 : 32, filename, ctx->section_count);
    }
    
    return 0;
}

// ELF32 format operations
static int elf32_write_file(output_context_t *ctx) {
    if (!ctx || !ctx->filename) {
        return -1;
    }
    
    // Create ELF context
    elf_context_t *elf_ctx = elf_context_create(0, EM_386);
    if (!elf_ctx) {
        return -1;
    }
    
    // Add sections from output context
    for (size_t i = 0; i < ctx->section_count; i++) {
        output_section_t *section = &ctx->sections[i];
        
        // Determine section type and flags
        uint32_t sh_type = SHT_PROGBITS;
        uint32_t sh_flags = SHF_ALLOC;
        
        if (strstr(section->name, "text") || strstr(section->name, "code")) {
            sh_flags |= SHF_EXECINSTR;
        }
        if (strstr(section->name, "data") || strstr(section->name, "bss")) {
            sh_flags |= SHF_WRITE;
        }
        if (strstr(section->name, "bss")) {
            sh_type = SHT_NOBITS;
        }
        
        int section_idx = elf_add_section(elf_ctx, section->name, sh_type, sh_flags, 
                                        section->data, section->size);
        
        if (ctx->verbose) {
            printf("Added ELF32 section '%s' (index %d): %zu bytes\n", 
                   section->name, section_idx, section->size);
        }
    }
    
    // Write ELF file
    int result = elf_write_file(elf_ctx, ctx->filename, ctx->verbose);
    
    elf_context_free(elf_ctx);
    return result;
}

static int elf32_add_section(output_context_t *ctx, const char *name, 
                            uint8_t *data, size_t size, uint32_t address) {
    // Use the same logic as flat binary for now
    if (!ctx || !name || !data) {
        return -1;
    }
    
    // Reallocate sections array
    output_section_t *new_sections = realloc(ctx->sections, 
                                            (ctx->section_count + 1) * sizeof(output_section_t));
    if (!new_sections) {
        return -1;
    }
    
    ctx->sections = new_sections;
    
    // Add new section
    output_section_t *section = &ctx->sections[ctx->section_count];
    section->name = malloc(strlen(name) + 1);
    section->data = malloc(size);
    if (!section->name || !section->data) {
        free((void*)section->name);
        free(section->data);
        return -1;
    }
    
    strcpy((char*)section->name, name);
    memcpy(section->data, data, size);
    section->size = size;
    section->virtual_address = address;
    section->file_offset = 0;
    section->flags = 0;
    
    ctx->section_count++;
    
    if (ctx->verbose) {
        printf("Added ELF32 section '%s': %zu bytes at 0x%08X\n", name, size, address);
    }
    
    return 0;
}

static void elf32_cleanup(output_context_t *ctx) {
    // Same cleanup as flat binary format
    if (!ctx || !ctx->sections) {
        return;
    }
    
    for (size_t i = 0; i < ctx->section_count; i++) {
        free((void*)ctx->sections[i].name);
        free(ctx->sections[i].data);
    }
    
    free(ctx->sections);
    ctx->sections = NULL;
    ctx->section_count = 0;
}

// ELF64 format operations
static int elf64_write_file(output_context_t *ctx) {
    if (!ctx || !ctx->filename) {
        return -1;
    }
    
    // Create ELF context
    elf_context_t *elf_ctx = elf_context_create(1, EM_X86_64);
    if (!elf_ctx) {
        return -1;
    }
    
    // Add sections from output context
    for (size_t i = 0; i < ctx->section_count; i++) {
        output_section_t *section = &ctx->sections[i];
        
        // Determine section type and flags
        uint32_t sh_type = SHT_PROGBITS;
        uint64_t sh_flags = SHF_ALLOC;
        
        if (strstr(section->name, "text") || strstr(section->name, "code")) {
            sh_flags |= SHF_EXECINSTR;
        }
        if (strstr(section->name, "data") || strstr(section->name, "bss")) {
            sh_flags |= SHF_WRITE;
        }
        if (strstr(section->name, "bss")) {
            sh_type = SHT_NOBITS;
        }
        
        int section_idx = elf_add_section(elf_ctx, section->name, sh_type, sh_flags, 
                                        section->data, section->size);
        
        if (ctx->verbose) {
            printf("Added ELF64 section '%s' (index %d): %zu bytes\n", 
                   section->name, section_idx, section->size);
        }
    }
    
    // Write ELF file
    int result = elf_write_file(elf_ctx, ctx->filename, ctx->verbose);
    
    elf_context_free(elf_ctx);
    return result;
}

static int elf64_add_section(output_context_t *ctx, const char *name, 
                            uint8_t *data, size_t size, uint32_t address) {
    // Same as ELF32 for now
    return elf32_add_section(ctx, name, data, size, address);
}

static void elf64_cleanup(output_context_t *ctx) {
    // Same as ELF32
    elf32_cleanup(ctx);
}
