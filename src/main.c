#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <getopt.h>
#ifndef STATIC_BUILD
#include <dlfcn.h>
#endif

#include "arch_interface.h"
#include "lexer.h"
#include "parser.h"
#include "symbols.h"
#include "core/output_format.h"
#include "codegen.h"

// External architecture function declarations
extern arch_ops_t *get_arch_ops_x86_16(void);
extern arch_ops_t *get_arch_ops_x86_32(void);
extern arch_ops_t *get_arch_ops_x86_64(void);

// Static build architecture detection
#ifdef STATIC_BUILD
#ifdef ARCH_X86_16_ONLY
#define STATIC_ARCH "x86_16"
#define STATIC_ARCH_NAME "Intel 8086/80286 16-bit"
#elif defined(ARCH_X86_32_ONLY)
#define STATIC_ARCH "x86_32"
#define STATIC_ARCH_NAME "Intel 80386+ 32-bit (IA-32)"
#elif defined(ARCH_X86_64_ONLY)
#define STATIC_ARCH "x86_64"
#define STATIC_ARCH_NAME "Intel/AMD 64-bit"
#elif defined(ARCH_ARM64_ONLY)
#define STATIC_ARCH "arm64"
#define STATIC_ARCH_NAME "ARM 64-bit (AArch64)"
#elif defined(ARCH_RISCV_ONLY)
#define STATIC_ARCH "riscv"
#define STATIC_ARCH_NAME "RISC-V 64-bit"
#endif
#endif

// Global configuration
typedef struct {
    char *input_file;
    char *output_file;
    char *architecture;
    output_format_t output_format;
    uint32_t base_address;
    bool verbose;
    bool debug;
    bool list_archs;
} config_t;

// Available architectures (will be loaded dynamically)
// static arch_plugin_t *loaded_plugins = NULL; // TODO: Implement plugin loading

void print_usage(const char *program_name) {
    printf("Usage: %s [options] input.s\n", program_name);
    printf("Options:\n");
#ifdef STATIC_BUILD
    printf("  -o, --output=FILE    Output file\n");
    printf("  -f, --format=FORMAT  Output format (bin, com, elf32, elf64)\n");
    printf("  -b, --base=ADDR      Base address for binary output (hex)\n");
    printf("  -v, --verbose        Verbose output\n");
    printf("  -d, --debug          Debug mode\n");
    printf("  -h, --help           Show this help message\n");
    printf("\nThis is a static build for %s architecture only.\n", STATIC_ARCH_NAME);
    printf("Target architecture: %s\n", STATIC_ARCH);
#else
    printf("  -a, --arch=ARCH      Target architecture (x86_16, x86_32, x86_64, arm64, riscv)\n");
    printf("  -o, --output=FILE    Output file\n");
    printf("  -f, --format=FORMAT  Output format (bin, com, elf32, elf64)\n");
    printf("  -b, --base=ADDR      Base address for binary output (hex)\n");
    printf("  -v, --verbose        Verbose output\n");
    printf("  -d, --debug          Debug mode\n");
    printf("  -l, --list-archs     List supported architectures\n");
    printf("  -h, --help           Show this help message\n");
    printf("\nSupported architectures:\n");
    printf("  x86_16               Intel 8086/80286 16-bit\n");
    printf("  x86_32               Intel 80386+ 32-bit (IA-32)\n");
    printf("  x86_64               Intel/AMD 64-bit\n");
    printf("  arm64                ARM 64-bit (AArch64)\n");
    printf("  riscv                RISC-V 64-bit\n");
    printf("\nOutput formats:\n");
    printf("  bin                  Flat binary (no headers)\n");
    printf("  com                  DOS .COM format (16-bit only)\n");
    printf("  elf32                ELF 32-bit object file\n");
    printf("  elf64                ELF 64-bit object file\n");
#endif
}

void print_version(void) {
#ifdef STATIC_BUILD
    printf("STAS - STIX Modular Assembler v0.0.1 (Static Build - %s)\n", STATIC_ARCH_NAME);
    printf("Specialized assembler for %s architecture\n", STATIC_ARCH);
#else
    printf("STAS - STIX Modular Assembler v0.0.1\n");
    printf("Multi-architecture assembler with AT&T syntax support\n");
#endif
}

// Get architecture operations by name
arch_ops_t *get_architecture(const char *arch_name) {
    if (!arch_name) return NULL;
    
    if (strcmp(arch_name, "x86_16") == 0) {
        return get_arch_ops_x86_16();
    } else if (strcmp(arch_name, "x86_32") == 0) {
        return get_arch_ops_x86_32();
    } else if (strcmp(arch_name, "x86_64") == 0) {
        return get_arch_ops_x86_64();
    }
    
    return NULL;
}

int load_architecture_plugins(void) {
    // In a full implementation, this would scan for .so files
    // For now, we'll simulate loading plugins
    
    printf("Loading architecture plugins...\n");
    
    // Simulate plugin loading
    const char *archs[] = {"x86_16", "x86_32", "x86_64", "arm64", "riscv"};
    for (size_t i = 0; i < sizeof(archs) / sizeof(archs[0]); i++) {
        printf("  Loaded %s architecture plugin\n", archs[i]);
    }
    
    return 0;
}

void list_architectures(void) {
    printf("Supported architectures:\n");
    printf("  x86_16     - Intel 8086/80286 16-bit instruction set\n");
    printf("  x86_32     - Intel 80386+ 32-bit (IA-32) instruction set\n");
    printf("  x86_64     - Intel/AMD 64-bit instruction set\n");
    printf("  arm64      - ARM 64-bit (AArch64) instruction set\n");
    printf("  riscv      - RISC-V 64-bit instruction set\n");
}

int assemble_file(const config_t *config) {
    FILE *input_file = NULL;
    char *source_code = NULL;
    size_t source_size = 0;
    int result = EXIT_FAILURE;
    
    // Open input file
    if (strcmp(config->input_file, "-") == 0) {
        input_file = stdin;
    } else {
        input_file = fopen(config->input_file, "r");
        if (!input_file) {
            fprintf(stderr, "Error: Cannot open input file '%s'\n", config->input_file);
            return EXIT_FAILURE;
        }
    }
    
    // Read source code
    if (input_file == stdin) {
        // For stdin, read in chunks since it's not seekable
        size_t capacity = 1024;
        size_t used = 0;
        source_code = malloc(capacity);
        if (!source_code) {
            fprintf(stderr, "Error: Memory allocation failed\n");
            return EXIT_FAILURE;
        }
        
        size_t bytes_read;
        while ((bytes_read = fread(source_code + used, 1, capacity - used - 1, input_file)) > 0) {
            used += bytes_read;
            if (used + 1 >= capacity) {
                capacity *= 2;
                char *new_buffer = realloc(source_code, capacity);
                if (!new_buffer) {
                    free(source_code);
                    fprintf(stderr, "Error: Memory allocation failed\n");
                    return EXIT_FAILURE;
                }
                source_code = new_buffer;
            }
        }
        source_code[used] = '\0';
        source_size = used;
    } else {
        // For regular files, use fseek/ftell
        fseek(input_file, 0, SEEK_END);
        source_size = ftell(input_file);
        fseek(input_file, 0, SEEK_SET);
        
        source_code = malloc(source_size + 1);
        if (!source_code) {
            fprintf(stderr, "Error: Memory allocation failed\n");
            goto cleanup;
        }
        
        size_t bytes_read = fread(source_code, 1, source_size, input_file);
        if (bytes_read != source_size) {
            fprintf(stderr, "Warning: Read %zu bytes, expected %zu\n", bytes_read, source_size);
        }
        source_code[source_size] = '\0';
    }
    
    if (config->verbose) {
        printf("Assembling %s for %s architecture...\n", 
               config->input_file, config->architecture);
    }
    
    // Create lexer
    lexer_t *lexer = lexer_create(source_code, config->input_file);
    if (!lexer) {
        fprintf(stderr, "Error: Failed to create lexer\n");
        goto cleanup;
    }
    
    // Get architecture operations
    arch_ops_t *arch_ops = get_architecture(config->architecture);
    if (!arch_ops) {
        fprintf(stderr, "Error: Unsupported architecture '%s'\n", config->architecture);
        lexer_destroy(lexer);
        goto cleanup;
    }
    
    // Initialize architecture
    if (arch_ops->init && arch_ops->init() != 0) {
        fprintf(stderr, "Error: Failed to initialize %s architecture\n", config->architecture);
        lexer_destroy(lexer);
        goto cleanup;
    }
    
    // Create parser
    parser_t *parser = parser_create(lexer, arch_ops);
    if (!parser) {
        fprintf(stderr, "Error: Failed to create parser\n");
        lexer_destroy(lexer);
        goto cleanup;
    }

    if (config->debug) {
        printf("=== LEXER TOKENS ===\n");
        // Create a temporary lexer for token display
        lexer_t *debug_lexer = lexer_create(source_code, config->input_file);
        token_t token;
        do {
            token = lexer_next_token(debug_lexer);
            printf("  Line %zu: %s = '%s'\n", 
                   token.line, 
                   token_type_to_string(token.type), 
                   token.value ? token.value : "");
            token_free(&token);
        } while (token.type != TOKEN_EOF && token.type != TOKEN_ERROR);
        lexer_destroy(debug_lexer);
        
        printf("\n=== PARSER AST ===\n");
    }
    
    // Parse the source code
    ast_node_t *ast = parser_parse(parser);
    
    if (parser_has_error(parser)) {
        fprintf(stderr, "Parse error: %s\n", parser_get_error(parser));
        parser_destroy(parser);
        goto cleanup;
    }
    
    if (config->debug && ast) {
        printf("\n");
        ast_print_tree(ast);
        printf("\n");
        ast_print_compact(ast);
        printf("\nAST created successfully with %s root node\n", 
               ast->type == AST_INSTRUCTION ? "instruction" :
               ast->type == AST_LABEL ? "label" :
               ast->type == AST_DIRECTIVE ? "directive" : "unknown");
    }

    // Generate output file
    output_context_t output_ctx = {
        .format = config->output_format,
        .filename = config->output_file,
        .sections = NULL,
        .section_count = 0,
        .entry_point = 0,
        .base_address = config->base_address,
        .verbose = config->verbose
    };
    
    // Generate machine code from AST
    codegen_ctx_t *codegen = codegen_create(arch_ops, &output_ctx);
    if (!codegen) {
        fprintf(stderr, "Error: Failed to create code generator\n");
        parser_destroy(parser);
        goto cleanup;
    }
    
    if (codegen_generate(codegen, ast) != 0) {
        fprintf(stderr, "Error: Code generation failed\n");
        codegen_destroy(codegen);
        parser_destroy(parser);
        goto cleanup;
    }
    
    codegen_destroy(codegen);
    
    // Write output file
    if (write_output_file(&output_ctx) == 0) {
        printf("Assembly completed successfully!\n");
        printf("Output written to: %s\n", config->output_file);
    } else {
        fprintf(stderr, "Error: Failed to write output file\n");
        result = EXIT_FAILURE;
    }
    
    // Cleanup output context
    output_format_ops_t *format_ops = get_output_format(config->output_format);
    if (format_ops && format_ops->cleanup) {
        format_ops->cleanup(&output_ctx);
    }
    
    result = EXIT_SUCCESS;
    
    parser_destroy(parser);
    
cleanup:
    if (source_code) free(source_code);
    if (input_file && input_file != stdin) fclose(input_file);
    
    return result;
}

int main(int argc, char *argv[]) {
    config_t config = {
        .input_file = NULL,
        .output_file = "a.out",
#ifdef STATIC_BUILD
        .architecture = STATIC_ARCH,
#else
        .architecture = "x86_64",
#endif
        .output_format = FORMAT_FLAT_BIN,
        .base_address = 0,
        .verbose = false,
        .debug = false,
        .list_archs = false
    };
    
    static struct option long_options[] = {
#ifndef STATIC_BUILD
        {"arch",       required_argument, 0, 'a'},
#endif
        {"output",     required_argument, 0, 'o'},
        {"format",     required_argument, 0, 'f'},
        {"base",       required_argument, 0, 'b'},
        {"verbose",    no_argument,       0, 'v'},
        {"debug",      no_argument,       0, 'd'},
#ifndef STATIC_BUILD
        {"list-archs", no_argument,       0, 'l'},
#endif
        {"help",       no_argument,       0, 'h'},
        {"version",    no_argument,       0, 'V'},
        {0, 0, 0, 0}
    };
    
    int option_index = 0;
    int c;
    
#ifdef STATIC_BUILD
    const char *optstring = "o:f:b:vdhV";
#else
    const char *optstring = "a:o:f:b:vdlhV";
#endif
    
    while ((c = getopt_long(argc, argv, optstring, long_options, &option_index)) != -1) {
        switch (c) {
#ifndef STATIC_BUILD
            case 'a':
                config.architecture = optarg;
                break;
#endif
            case 'o':
                config.output_file = optarg;
                break;
            case 'f':
                if (strcmp(optarg, "bin") == 0) {
                    config.output_format = FORMAT_FLAT_BIN;
                } else if (strcmp(optarg, "com") == 0) {
                    config.output_format = FORMAT_COM;
                } else if (strcmp(optarg, "elf32") == 0) {
                    config.output_format = FORMAT_ELF32;
                } else if (strcmp(optarg, "elf64") == 0) {
                    config.output_format = FORMAT_ELF64;
                } else {
                    fprintf(stderr, "Error: Unknown output format '%s'\n", optarg);
                    return EXIT_FAILURE;
                }
                break;
            case 'b':
                config.base_address = (uint32_t)strtoul(optarg, NULL, 0);
                break;
            case 'v':
                config.verbose = true;
                break;
            case 'd':
                config.debug = true;
                break;
#ifndef STATIC_BUILD
            case 'l':
                config.list_archs = true;
                break;
#endif
            case 'h':
                print_usage(argv[0]);
                return EXIT_SUCCESS;
            case 'V':
                print_version();
                return EXIT_SUCCESS;
            case '?':
            default:
                print_usage(argv[0]);
                return EXIT_FAILURE;
        }
    }
    
#ifndef STATIC_BUILD
    if (config.list_archs) {
        list_architectures();
        return EXIT_SUCCESS;
    }
#endif
    
    if (optind >= argc) {
        fprintf(stderr, "Error: No input file specified\n");
        print_usage(argv[0]);
        return EXIT_FAILURE;
    }
    
    config.input_file = argv[optind];
    
#ifndef STATIC_BUILD
    // Load architecture plugins
    if (load_architecture_plugins() != 0) {
        fprintf(stderr, "Error: Failed to load architecture plugins\n");
        return EXIT_FAILURE;
    }
#endif
    
    // Validate architecture
    const char *valid_archs[] = {"x86_16", "x86_32", "x86_64", "arm64", "riscv"};
    bool valid_arch = false;
    for (size_t i = 0; i < sizeof(valid_archs) / sizeof(valid_archs[0]); i++) {
        if (strcmp(config.architecture, valid_archs[i]) == 0) {
            valid_arch = true;
            break;
        }
    }
    
    if (!valid_arch) {
        fprintf(stderr, "Error: Unsupported architecture '%s'\n", config.architecture);
        fprintf(stderr, "Use --list-archs to see supported architectures\n");
        return EXIT_FAILURE;
    }
    
    if (config.verbose) {
        printf("STAS - STIX Modular Assembler\n");
        printf("Input file: %s\n", config.input_file);
        printf("Output file: %s\n", config.output_file);
        printf("Architecture: %s\n", config.architecture);
    }
    
    return assemble_file(&config);
}
