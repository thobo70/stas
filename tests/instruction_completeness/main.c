#include "instruction_completeness.h"
#include <stdio.h>
#include <string.h>
#include <stdlib.h>

void print_usage(const char *program_name) {
    printf("Usage: %s [options]\n", program_name);
    printf("Options:\n");
    printf("  -w, --width N     Set max line width (default: 80)\n");
    printf("  -c, --compact     Use ultra-compact format\n");
    printf("  --no-bars         Disable progress bars\n");
    printf("  -h, --help        Show this help\n");
}

int main(int argc, char *argv[]) {
    report_config_t config = {
        .max_line_width = 80,
        .compact_mode = false,
        .show_progress_bars = true
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
        } else if (strcmp(argv[i], "-h") == 0 || strcmp(argv[i], "--help") == 0) {
            print_usage(argv[0]);
            return 0;
        }
    }
    
    run_instruction_completeness_tests_with_config(&config);
    return 0;
}
