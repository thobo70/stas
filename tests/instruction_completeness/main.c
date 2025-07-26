#include "instruction_completeness.h"
#include <stdio.h>
#include <string.h>
#include <stdlib.h>

void print_usage(const char *program_name) {
    printf("Usage: %s [architecture] [options]\n", program_name);
    printf("Architectures:\n");
    printf("  x86_16, x86_32, x86_64, arm64, riscv  Test specific architecture only\n");
    printf("Options:\n");
    printf("  -v, --verbose     Show detailed failure reports for missing instructions\n");
    printf("  -w, --width N     Set max line width (default: 80)\n");
    printf("  -c, --compact     Use ultra-compact format\n");
    printf("  --no-bars         Disable progress bars\n");
    printf("  -h, --help        Show this help\n");
    printf("Examples:\n");
    printf("  %s                Test all architectures\n", program_name);
    printf("  %s x86_32         Test only x86_32 architecture\n", program_name);
    printf("  %s x86_32 -v      Test x86_32 with verbose failure reporting\n", program_name);
    printf("  %s -v             Test all architectures with verbose reporting\n", program_name);
}

int main(int argc, char *argv[]) {
    report_config_t config = {
        .max_line_width = 80,
        .compact_mode = false,
        .show_progress_bars = true,
        .verbose_mode = false,
        .target_arch = NULL
    };
    
    // Parse command line arguments
    for (int i = 1; i < argc; i++) {
        if (strcmp(argv[i], "-w") == 0 || strcmp(argv[i], "--width") == 0) {
            if (i + 1 < argc) {
                config.max_line_width = atoi(argv[++i]);
                if (config.max_line_width < 40) config.max_line_width = 40;
                if (config.max_line_width > 200) config.max_line_width = 200;
            }
        } else if (strcmp(argv[i], "-c") == 0 || strcmp(argv[i], "--compact") == 0) {
            config.compact_mode = true;
        } else if (strcmp(argv[i], "--no-bars") == 0) {
            config.show_progress_bars = false;
        } else if (strcmp(argv[i], "-v") == 0 || strcmp(argv[i], "--verbose") == 0) {
            config.verbose_mode = true;
        } else if (strcmp(argv[i], "-h") == 0 || strcmp(argv[i], "--help") == 0) {
            print_usage(argv[0]);
            return 0;
        } else if (argv[i][0] != '-') {
            // Check if it's a valid architecture name
            if (strcmp(argv[i], "x86_16") == 0 || strcmp(argv[i], "x86_32") == 0 ||
                strcmp(argv[i], "x86_64") == 0 || strcmp(argv[i], "arm64") == 0 ||
                strcmp(argv[i], "riscv") == 0) {
                config.target_arch = argv[i];
            } else {
                printf("Error: Unknown architecture '%s'\n", argv[i]);
                printf("Valid architectures: x86_16, x86_32, x86_64, arm64, riscv\n");
                return 1;
            }
        } else {
            printf("Error: Unknown option '%s'\n", argv[i]);
            print_usage(argv[0]);
            return 1;
        }
    }
    
    run_instruction_completeness_tests_with_config(&config);
    return 0;
}
