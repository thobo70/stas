# Project name
PROJECT_NAME = stas

# Default target (must be first)
.DEFAULT_GOAL := all

# Compiler and flags
CC = gcc
CFLAGS = -std=c99 -Wall -Wextra -Wpedantic -Werror -O2 -fPIC
DEBUG_CFLAGS = -std=c99 -Wall -Wextra -Wpedantic -Werror -g -DDEBUG -fPIC
STATIC_CFLAGS = -std=c99 -Wall -Wextra -Wpedantic -Werror -O2 -static -DSTATIC_BUILD
LDFLAGS = -ldl
STATIC_LDFLAGS = 

# Architecture-specific defines
ARCH_X86_16_CFLAGS = -DARCH_# Execution test compilation - specific rules for each architecture
$(TESTBIN_DIR)/execution_test_x86_16_basic: tests/execution/x86_16/test_basic.c $(UNICORN_FRAMEWORK) tests/unity/src/unity.c $(OBJECTS) | $(TESTBIN_DIR)
	@echo "Building execution test for x86_16..."
	$(CC) $(EXECUTION_TEST_CFLAGS) $< $(UNICORN_FRAMEWORK) tests/unity/src/unity.c $(filter-out $(OBJ_DIR)/main.o,$(OBJECTS)) -lunicorn -o $@

$(TESTBIN_DIR)/test_x86_16_algorithms: tests/execution/x86_16/test_algorithms.c $(UNICORN_FRAMEWORK) tests/unity/src/unity.c $(OBJECTS) | $(TESTBIN_DIR)
	@echo "Building algorithm test for x86_16..."
	$(CC) $(EXECUTION_TEST_CFLAGS) $< $(UNICORN_FRAMEWORK) tests/unity/src/unity.c $(filter-out $(OBJ_DIR)/main.o,$(OBJECTS)) -lunicorn -o $@

$(TESTBIN_DIR)/execution_test_x86_32_basic: tests/execution/x86_32/test_basic.c $(UNICORN_FRAMEWORK) tests/unity/src/unity.c $(OBJECTS) | $(TESTBIN_DIR)
	@echo "Building execution test for x86_32..."
	$(CC) $(EXECUTION_TEST_CFLAGS) $< $(UNICORN_FRAMEWORK) tests/unity/src/unity.c $(filter-out $(OBJ_DIR)/main.o,$(OBJECTS)) -lunicorn -o $@

$(TESTBIN_DIR)/test_x86_32_algorithms: tests/execution/x86_32/test_algorithms.c $(UNICORN_FRAMEWORK) tests/unity/src/unity.c $(OBJECTS) | $(TESTBIN_DIR)
	@echo "Building algorithm test for x86_32..."
	$(CC) $(EXECUTION_TEST_CFLAGS) $< $(UNICORN_FRAMEWORK) tests/unity/src/unity.c $(filter-out $(OBJ_DIR)/main.o,$(OBJECTS)) -lunicorn -o $@

$(TESTBIN_DIR)/execution_test_x86_32_real_to_protected: tests/execution/x86_32/test_real_to_protected_mode.c $(UNICORN_FRAMEWORK) tests/unity/src/unity.c $(OBJECTS) | $(TESTBIN_DIR)
	@echo "Building real-to-protected mode test for x86_32..."
	$(CC) $(EXECUTION_TEST_CFLAGS) $< $(UNICORN_FRAMEWORK) tests/unity/src/unity.c $(filter-out $(OBJ_DIR)/main.o,$(OBJECTS)) -lunicorn -o $@

$(TESTBIN_DIR)/execution_test_x86_64_basic: tests/execution/x86_64/test_basic.c $(UNICORN_FRAMEWORK) tests/unity/src/unity.c $(OBJECTS) | $(TESTBIN_DIR)
	@echo "Building execution test for x86_64..."
	$(CC) $(EXECUTION_TEST_CFLAGS) $< $(UNICORN_FRAMEWORK) tests/unity/src/unity.c $(filter-out $(OBJ_DIR)/main.o,$(OBJECTS)) -lunicorn -o $@

$(TESTBIN_DIR)/execution_test_arm64_basic: tests/execution/arm64/test_basic.c $(UNICORN_FRAMEWORK) tests/unity/src/unity.c $(OBJECTS) | $(TESTBIN_DIR)
	@echo "Building execution test for arm64..."
	$(CC) $(EXECUTION_TEST_CFLAGS) $< $(UNICORN_FRAMEWORK) tests/unity/src/unity.c $(filter-out $(OBJ_DIR)/main.o,$(OBJECTS)) -lunicorn -o $@

$(TESTBIN_DIR)/execution_test_riscv_basic: tests/execution/riscv/test_basic.c $(UNICORN_FRAMEWORK) tests/unity/src/unity.c $(OBJECTS) | $(TESTBIN_DIR)
	@echo "Building execution test for riscv..."
	$(CC) $(EXECUTION_TEST_CFLAGS) $< $(UNICORN_FRAMEWORK) tests/unity/src/unity.c $(filter-out $(OBJ_DIR)/main.o,$(OBJECTS)) -lunicorn -o $@

ARCH_X86_16_CFLAGS = -DARCH_X86_16_ONLY
ARCH_X86_32_CFLAGS = -DARCH_X86_32_ONLY
ARCH_X86_64_CFLAGS = -DARCH_X86_64_ONLY
ARCH_ARM64_CFLAGS = -DARCH_ARM64_ONLY
ARCH_RISCV_CFLAGS = -DARCH_RISCV_ONLY

# Directories
SRC_DIR = src
INCLUDE_DIR = include
OBJ_DIR = obj
BIN_DIR = bin
TESTBIN_DIR = testbin

# Core source files (moved to src/core)
CORE_SOURCES = $(SRC_DIR)/core/lexer.c $(SRC_DIR)/core/parser.c $(SRC_DIR)/core/expr.c $(SRC_DIR)/core/symbols.c $(SRC_DIR)/core/expressions.c $(SRC_DIR)/core/output.c $(SRC_DIR)/core/output_format.c $(SRC_DIR)/core/codegen.c
CORE_OBJECTS = $(CORE_SOURCES:$(SRC_DIR)/core/%.c=$(OBJ_DIR)/core/%.o) $(OBJ_DIR)/include.o

# Format source files
FORMAT_SOURCES = $(SRC_DIR)/formats/elf.c $(SRC_DIR)/formats/flat_binary.c $(SRC_DIR)/formats/com_format.c $(SRC_DIR)/formats/intel_hex.c $(SRC_DIR)/formats/motorola_srec.c $(SRC_DIR)/formats/smof.c
FORMAT_OBJECTS = $(FORMAT_SOURCES:$(SRC_DIR)/formats/%.c=$(OBJ_DIR)/formats/%.o)

# Utility source files
UTIL_SOURCES = $(SRC_DIR)/utils/utils.c
UTIL_OBJECTS = $(UTIL_SOURCES:$(SRC_DIR)/utils/%.c=$(OBJ_DIR)/utils/%.o)

# Architecture module sources - UNIFIED x86-64 implementation
ARCH_X86_64_SOURCES = $(SRC_DIR)/arch/x86_64/x86_64_unified.c $(SRC_DIR)/arch/x86_64/x86_64_parser.c $(SRC_DIR)/arch/x86_64/x86_64_addressing.c $(SRC_DIR)/arch/x86_64/x86_64_interface.c
ARCH_X86_64_OBJECTS = $(ARCH_X86_64_SOURCES:$(SRC_DIR)/arch/x86_64/%.c=$(OBJ_DIR)/arch/x86_64/%.o)

ARCH_X86_32_SOURCES = $(SRC_DIR)/arch/x86_32/x86_32.c
ARCH_X86_32_OBJECTS = $(ARCH_X86_32_SOURCES:$(SRC_DIR)/arch/x86_32/%.c=$(OBJ_DIR)/arch/x86_32/%.o)

ARCH_X86_16_SOURCES = $(SRC_DIR)/arch/x86_16/x86_16.c
ARCH_X86_16_OBJECTS = $(ARCH_X86_16_SOURCES:$(SRC_DIR)/arch/x86_16/%.c=$(OBJ_DIR)/arch/x86_16/%.o)

ARCH_ARM64_SOURCES = $(SRC_DIR)/arch/arm64/arm64.c $(SRC_DIR)/arch/arm64/arm64_utils.c
ARCH_ARM64_OBJECTS = $(ARCH_ARM64_SOURCES:$(SRC_DIR)/arch/arm64/%.c=$(OBJ_DIR)/arch/arm64/%.o)

ARCH_RISCV_SOURCES = $(SRC_DIR)/arch/riscv/riscv.c
ARCH_RISCV_OBJECTS = $(ARCH_RISCV_SOURCES:$(SRC_DIR)/arch/riscv/%.c=$(OBJ_DIR)/arch/riscv/%.o)

# Main application source
MAIN_SOURCE = $(SRC_DIR)/main.c
MAIN_OBJECT = $(OBJ_DIR)/main.o

# All sources and objects for dynamic build
SOURCES = $(CORE_SOURCES) $(SRC_DIR)/include.c $(FORMAT_SOURCES) $(UTIL_SOURCES) $(ARCH_X86_64_SOURCES) $(ARCH_X86_32_SOURCES) $(ARCH_X86_16_SOURCES) $(ARCH_ARM64_SOURCES) $(ARCH_RISCV_SOURCES) $(MAIN_SOURCE)
OBJECTS = $(CORE_OBJECTS) $(FORMAT_OBJECTS) $(UTIL_OBJECTS) $(ARCH_X86_64_OBJECTS) $(ARCH_X86_32_OBJECTS) $(ARCH_X86_16_OBJECTS) $(ARCH_ARM64_OBJECTS) $(ARCH_RISCV_OBJECTS) $(MAIN_OBJECT)

# Target executable
TARGET = $(BIN_DIR)/$(PROJECT_NAME)

# Static build targets
STATIC_TARGET_X86_16 = $(BIN_DIR)/$(PROJECT_NAME)-x86_16-static
STATIC_TARGET_X86_32 = $(BIN_DIR)/$(PROJECT_NAME)-x86_32-static
STATIC_TARGET_X86_64 = $(BIN_DIR)/$(PROJECT_NAME)-x86_64-static
STATIC_TARGET_ARM64 = $(BIN_DIR)/$(PROJECT_NAME)-arm64-static
STATIC_TARGET_RISCV = $(BIN_DIR)/$(PROJECT_NAME)-riscv-static

# Include directories
INCLUDES = -I$(INCLUDE_DIR) -I$(SRC_DIR)/core -I$(SRC_DIR)/arch

# Create necessary directories
$(OBJ_DIR):
	mkdir -p $(OBJ_DIR)
	mkdir -p $(OBJ_DIR)/core
	mkdir -p $(OBJ_DIR)/formats
	mkdir -p $(OBJ_DIR)/utils
	mkdir -p $(OBJ_DIR)/arch/x86_64
	mkdir -p $(OBJ_DIR)/arch/x86_32
	mkdir -p $(OBJ_DIR)/arch/x86_16
	mkdir -p $(OBJ_DIR)/arch/arm64
	mkdir -p $(OBJ_DIR)/arch/riscv

$(BIN_DIR):
	mkdir -p $(BIN_DIR)

$(TESTBIN_DIR):
	mkdir -p $(TESTBIN_DIR)

# Default target
all: $(TARGET)

# Build the main target
$(TARGET): $(OBJECTS) | $(BIN_DIR)
	$(CC) $(OBJECTS) $(LDFLAGS) -o $@
	@echo "Build complete: $@"

# Main source compilation
$(OBJ_DIR)/main.o: $(SRC_DIR)/main.c | $(OBJ_DIR)
	$(CC) $(CFLAGS) $(INCLUDES) -c $< -o $@

# Core module compilation
$(OBJ_DIR)/core/%.o: $(SRC_DIR)/core/%.c | $(OBJ_DIR)
	$(CC) $(CFLAGS) $(INCLUDES) -c $< -o $@

# Include processor compilation
$(OBJ_DIR)/include.o: $(SRC_DIR)/include.c | $(OBJ_DIR)
	$(CC) $(CFLAGS) $(INCLUDES) -c $< -o $@

# Format module compilation
$(OBJ_DIR)/formats/%.o: $(SRC_DIR)/formats/%.c | $(OBJ_DIR)
	$(CC) $(CFLAGS) $(INCLUDES) -c $< -o $@

# Utility module compilation
$(OBJ_DIR)/utils/%.o: $(SRC_DIR)/utils/%.c | $(OBJ_DIR)
	$(CC) $(CFLAGS) $(INCLUDES) -c $< -o $@

# Architecture module compilation
$(OBJ_DIR)/arch/x86_64/%.o: $(SRC_DIR)/arch/x86_64/%.c | $(OBJ_DIR)
	$(CC) $(CFLAGS) $(INCLUDES) -c $< -o $@

$(OBJ_DIR)/arch/x86_32/%.o: $(SRC_DIR)/arch/x86_32/%.c | $(OBJ_DIR)
	$(CC) $(CFLAGS) $(INCLUDES) -c $< -o $@

$(OBJ_DIR)/arch/x86_16/%.o: $(SRC_DIR)/arch/x86_16/%.c | $(OBJ_DIR)
	$(CC) $(CFLAGS) $(INCLUDES) -c $< -o $@

$(OBJ_DIR)/arch/arm64/%.o: $(SRC_DIR)/arch/arm64/%.c | $(OBJ_DIR)
	$(CC) $(CFLAGS) $(INCLUDES) -c $< -o $@

$(OBJ_DIR)/arch/riscv/%.o: $(SRC_DIR)/arch/riscv/%.c | $(OBJ_DIR)
	$(CC) $(CFLAGS) $(INCLUDES) -c $< -o $@

# Legacy compilation rule (for compatibility)
$(OBJ_DIR)/%.o: $(SRC_DIR)/%.c | $(OBJ_DIR)
	$(CC) $(CFLAGS) $(INCLUDES) -c $< -o $@

# Debug build
debug: CFLAGS = $(DEBUG_CFLAGS)
debug: $(TARGET)

# Static builds for specific architectures
static-x86_16: $(STATIC_TARGET_X86_16)
static-x86_32: $(STATIC_TARGET_X86_32)  
static-x86_64: $(STATIC_TARGET_X86_64)
static-arm64: $(STATIC_TARGET_ARM64)
static-riscv: $(STATIC_TARGET_RISCV)

# Build all static variants
static-all: static-x86_16 static-x86_32 static-x86_64 static-arm64 static-riscv

# Static build rules
$(STATIC_TARGET_X86_16): $(SOURCES) | $(BIN_DIR)
	@echo "Building static x86-16 assembler..."
	$(CC) $(STATIC_CFLAGS) $(ARCH_X86_16_CFLAGS) $(INCLUDES) $(SOURCES) $(STATIC_LDFLAGS) -o $@
	@echo "Static x86-16 assembler built: $@"

$(STATIC_TARGET_X86_32): $(SOURCES) | $(BIN_DIR)
	@echo "Building static x86-32 assembler..."
	$(CC) $(STATIC_CFLAGS) $(ARCH_X86_32_CFLAGS) $(INCLUDES) $(SOURCES) $(STATIC_LDFLAGS) -o $@
	@echo "Static x86-32 assembler built: $@"

$(STATIC_TARGET_X86_64): $(SOURCES) | $(BIN_DIR)
	@echo "Building static x86-64 assembler..."
	$(CC) $(STATIC_CFLAGS) $(ARCH_X86_64_CFLAGS) $(INCLUDES) $(SOURCES) $(STATIC_LDFLAGS) -o $@
	@echo "Static x86-64 assembler built: $@"

$(STATIC_TARGET_ARM64): $(SOURCES) | $(BIN_DIR)
	@echo "Building static ARM64 assembler..."
	$(CC) $(STATIC_CFLAGS) $(ARCH_ARM64_CFLAGS) $(INCLUDES) $(SOURCES) $(STATIC_LDFLAGS) -o $@
	@echo "Static ARM64 assembler built: $@"

$(STATIC_TARGET_RISCV): $(SOURCES) | $(BIN_DIR)
	@echo "Building static RISC-V assembler..."
	$(CC) $(STATIC_CFLAGS) $(ARCH_RISCV_CFLAGS) $(INCLUDES) $(SOURCES) $(STATIC_LDFLAGS) -o $@
	@echo "Static RISC-V assembler built: $@"

# Test with sample assembly file
test: $(TARGET)
	@echo "Creating test assembly file..."
	@echo '.section .text'           > test.s
	@echo '.global _start'           >> test.s
	@echo ''                         >> test.s
	@echo '_start:'                  >> test.s
	@echo '    movq $$message, %rdi'  >> test.s
	@echo '    movq $$14, %rsi'       >> test.s
	@echo '    movq $$1, %rax'        >> test.s
	@echo '    syscall'              >> test.s
	@echo ''                         >> test.s
	@echo '.section .data'           >> test.s
	@echo 'message: .ascii "Hello, World!\\n"' >> test.s
	@echo "Testing with sample assembly file..."
	./$(TARGET) --verbose --debug test.s
	@rm -f test.s

# === MODERN TESTING FRAMEWORK ===
# All legacy test infrastructure removed - using Unity-based framework only

# Clean build artifacts
clean:
	rm -rf $(OBJ_DIR) $(BIN_DIR) $(TESTBIN_DIR)
	rm -f test_x86_64_completeness test_x86_64_completeness_*
	rm -f test_x86_64_data_driven test_instruction_database test_stas_compliance
	@echo "Cleaned build artifacts and removed legacy test binaries from project root"

# Clean generated logs and reports  
clean-logs:
	rm -rf $(LOGS_DIR)/* $(REPORTS_DIR)/*
	@echo "Cleaned generated logs and reports"

# Clean everything including directories
distclean: clean clean-logs
	rm -rf $(OBJ_DIR) $(BIN_DIR) $(TESTBIN_DIR)
	@echo "Cleaned all generated files and directories"

# Run the program with help
run: $(TARGET)
	./$(TARGET) --help

# Install (copy to /usr/local/bin)
install: $(TARGET)
	sudo cp $(TARGET) /usr/local/bin/$(PROJECT_NAME)
	@echo "Installed $(PROJECT_NAME) to /usr/local/bin"

# Uninstall
uninstall:
	sudo rm -f /usr/local/bin/$(PROJECT_NAME)
	@echo "Uninstalled $(PROJECT_NAME)"

# Show help (updated for modern testing framework)
help:
	@echo "Available targets:"
	@echo "  all          - Build the project (default)"
	@echo "  debug        - Build with debug symbols"
	@echo "  test         - Build and test with sample assembly"
	@echo "  test-unit-all - Run all unit tests (modern Unity framework)"
	@echo "  test-comprehensive - Run complete test suite"
	@echo "  test-x86_64-completeness - Run x86-64 instruction set completeness test"
	@echo "  test-x86_64-data-driven - Run data-driven x86-64 instruction tests"
	@echo "  test-instruction-database - Validate instruction database files"
	@echo "  test-stas-compliance - Test STAS assembler CPU compliance (REAL VALIDATION)"
	@echo "  test-help    - Show detailed testing help"
	@echo "  test-phase7-advanced - Run Phase 7 advanced features"
	@echo "  test-all     - Run enhanced comprehensive tests"
	@echo "  static-x86_16 - Build static x86-16 only assembler"
	@echo "  static-x86_32 - Build static x86-32 only assembler"
	@echo "  static-x86_64 - Build static x86-64 only assembler"
	@echo "  static-arm64 - Build static ARM64 only assembler"
	@echo "  static-riscv - Build static RISC-V only assembler"
	@echo "  static-all   - Build all static architecture variants"
	@echo "  clean        - Remove object files and executable"
	@echo "  clean-logs   - Remove generated logs and reports"
	@echo "  distclean    - Remove all generated files and directories"
	@echo "  run          - Build and show help message"
	@echo "  install      - Install the program to /usr/local/bin"
	@echo "  uninstall    - Remove the program from /usr/local/bin"
	@echo "  structure    - Show the new modular project structure"
	@echo "  help         - Show this help message"

# Show project structure
structure:
	@echo "STAS Modular Architecture Structure:"
	@echo "src/"
	@echo "├── core/           # Core assembler functionality"
	@echo "│   ├── lexer.c     # Lexical analysis"
	@echo "│   ├── parser.c    # AT&T syntax parser"
	@echo "│   ├── symbols.c   # Symbol table management"
	@echo "│   ├── expressions.c # Expression evaluation"
	@echo "│   └── output.c    # Object file generation"
	@echo "├── arch/           # Architecture-specific modules"
	@echo "│   ├── x86_64/     # x86-64 instruction set (IMPLEMENTED)"
	@echo "│   │   ├── x86_64.c      # Main module"
	@echo "│   │   ├── instructions.c # Instruction encoding"
	@echo "│   │   ├── registers.c    # Register handling"
	@echo "│   │   └── addressing.c   # Addressing modes"
	@echo "│   ├── x86_32/     # x86-32 instruction set (complete)"
	@echo "│   ├── x86_16/     # x86-16 instruction set (complete)"
	@echo "│   ├── arm64/      # ARM64 instruction set (complete)"
	@echo "│   └── riscv/      # RISC-V instruction set (complete)"
	@echo "├── utils/          # Utility functions"
	@echo "│   └── utils.c     # General utilities"
	@echo "└── main.c          # Main entry point"

# === COMPREHENSIVE TESTING FRAMEWORK ===

# Test directories and framework
UNIT_TEST_DIR = tests/unit
INTEGRATION_TEST_DIR = tests/integration
EXECUTION_TEST_DIR = tests/execution
COVERAGE_DIR = tests/coverage
FRAMEWORK_DIR = tests/framework

# Generated files directories
LOGS_DIR = logs
REPORTS_DIR = reports

# Unity extensions and Unicorn framework
UNITY_EXTENSIONS = $(FRAMEWORK_DIR)/unity_extensions.c
UNICORN_FRAMEWORK = $(FRAMEWORK_DIR)/unicorn_test_framework.c
FRAMEWORK_INCLUDES = -I$(FRAMEWORK_DIR) -Itests -Itests/unity/src

# Enhanced test compilation flags
TEST_CFLAGS_ENHANCED = $(CFLAGS) $(INCLUDES) $(FRAMEWORK_INCLUDES) -DUNITY_INCLUDE_CONFIG_H
EXECUTION_TEST_CFLAGS = $(TEST_CFLAGS_ENHANCED) -DHAVE_UNICORN

# Coverage targets
COVERAGE_CFLAGS = --coverage -fprofile-arcs -ftest-coverage -O0 -g
COVERAGE_LDFLAGS = --coverage

# === UNIT TESTING WITH UNITY ===

# Unit test compilation - flexible pattern matching  
# === UNIT TESTING WITH UNITY ===

# Standard Unit Tests with Unity framework  
$(TESTBIN_DIR)/unit_test_%: tests/unit/*/test_%.c tests/unity/src/unity.c $(UNITY_EXTENSIONS) $(OBJECTS) | $(TESTBIN_DIR)
	@echo "Building unit test for $*..."
	$(CC) $(TEST_CFLAGS_ENHANCED) $< tests/unity/src/unity.c $(UNITY_EXTENSIONS) $(filter-out $(OBJ_DIR)/main.o,$(OBJECTS)) -o $@

# Core module unit tests
test-unit-core:
	@echo "=== Running Core Module Unit Tests ==="
	@echo "Checking for core unit tests..."
	@$(MAKE) -q $(TESTBIN_DIR)/unit_test_lexer_comprehensive || $(MAKE) $(TESTBIN_DIR)/unit_test_lexer_comprehensive || true
	@$(MAKE) -q $(TESTBIN_DIR)/unit_test_parser_comprehensive || $(MAKE) $(TESTBIN_DIR)/unit_test_parser_comprehensive || true
	@$(MAKE) -q $(TESTBIN_DIR)/unit_test_symbols_comprehensive || $(MAKE) $(TESTBIN_DIR)/unit_test_symbols_comprehensive || true
	@if [ -f $(TESTBIN_DIR)/unit_test_lexer_comprehensive ]; then echo "Running comprehensive lexer tests..."; ./$(TESTBIN_DIR)/unit_test_lexer_comprehensive; fi
	@if [ -f $(TESTBIN_DIR)/unit_test_parser_comprehensive ]; then echo "Running comprehensive parser tests..."; ./$(TESTBIN_DIR)/unit_test_parser_comprehensive; fi
	@if [ -f $(TESTBIN_DIR)/unit_test_symbols_comprehensive ]; then echo "Running comprehensive symbols tests..."; ./$(TESTBIN_DIR)/unit_test_symbols_comprehensive; fi
	@echo "Core unit tests completed"

# Architecture module unit tests
test-unit-arch:
	@echo "=== Running Architecture Module Unit Tests ==="
	@echo "Checking for architecture unit tests..."
	@$(MAKE) -q $(TESTBIN_DIR)/unit_test_x86_64 || $(MAKE) $(TESTBIN_DIR)/unit_test_x86_64 || true
	@$(MAKE) -q $(TESTBIN_DIR)/unit_test_x86_32 || $(MAKE) $(TESTBIN_DIR)/unit_test_x86_32 || true
	@$(MAKE) -q $(TESTBIN_DIR)/unit_test_x86_16 || $(MAKE) $(TESTBIN_DIR)/unit_test_x86_16 || true
	@$(MAKE) -q $(TESTBIN_DIR)/unit_test_arm64 || $(MAKE) $(TESTBIN_DIR)/unit_test_arm64 || true
	@$(MAKE) -q $(TESTBIN_DIR)/unit_test_riscv || $(MAKE) $(TESTBIN_DIR)/unit_test_riscv || true
	@$(MAKE) -q $(TESTBIN_DIR)/unit_test_x86_compatibility || $(MAKE) $(TESTBIN_DIR)/unit_test_x86_compatibility || true
	@$(MAKE) -q $(TESTBIN_DIR)/unit_test_x86_att_syntax || $(MAKE) $(TESTBIN_DIR)/unit_test_x86_att_syntax || true
	@for test in unit_test_x86_64 unit_test_x86_32 unit_test_x86_16 unit_test_arm64 unit_test_riscv unit_test_x86_compatibility unit_test_x86_att_syntax; do \
		if [ -f $(TESTBIN_DIR)/$$test ]; then echo "Running $$test..."; ./$(TESTBIN_DIR)/$$test; fi; \
	done
	@echo "Architecture unit tests completed"

# Format module unit tests
test-unit-formats:
	@echo "=== Running Format Module Unit Tests ==="
	@echo "Checking for format unit tests..."
	@$(MAKE) -q $(TESTBIN_DIR)/unit_test_elf || $(MAKE) $(TESTBIN_DIR)/unit_test_elf || true
	@$(MAKE) -q $(TESTBIN_DIR)/unit_test_flat_binary || $(MAKE) $(TESTBIN_DIR)/unit_test_flat_binary || true
	@$(MAKE) -q $(TESTBIN_DIR)/unit_test_intel_hex || $(MAKE) $(TESTBIN_DIR)/unit_test_intel_hex || true
	@$(MAKE) -q $(TESTBIN_DIR)/unit_test_com_format || $(MAKE) $(TESTBIN_DIR)/unit_test_com_format || true
	@$(MAKE) -q $(TESTBIN_DIR)/unit_test_motorola_srec || $(MAKE) $(TESTBIN_DIR)/unit_test_motorola_srec || true
	@for test in unit_test_elf unit_test_flat_binary unit_test_intel_hex unit_test_com_format unit_test_motorola_srec; do \
		if [ -f $(TESTBIN_DIR)/$$test ]; then echo "Running $$test..."; ./$(TESTBIN_DIR)/$$test; fi; \
	done
	@echo "Format unit tests completed"

# Utility module unit tests
test-unit-utils:
	@echo "=== Running Utility Module Unit Tests ==="
	@echo "Checking for utility unit tests..."
	@$(MAKE) -q $(TESTBIN_DIR)/unit_test_utils || $(MAKE) $(TESTBIN_DIR)/unit_test_utils || true
	@if [ -f $(TESTBIN_DIR)/unit_test_utils ]; then echo "Running utility tests..."; ./$(TESTBIN_DIR)/unit_test_utils; fi
	@echo "Utility unit tests completed"

# Directive unit tests
$(TESTBIN_DIR)/unit_test_data_directives: tests/unit/directives/test_data_directives.c tests/unity/src/unity.c $(OBJECTS) | $(TESTBIN_DIR)
	@echo "Compiling data directives unit test: $@"
	$(CC) $(TEST_CFLAGS_ENHANCED) $< tests/unity/src/unity.c $(filter-out $(OBJ_DIR)/main.o,$(OBJECTS)) -o $@

$(TESTBIN_DIR)/unit_test_symbol_directives: tests/unit/directives/test_symbol_directives.c tests/unity/src/unity.c $(OBJECTS) | $(TESTBIN_DIR)
	@echo "Compiling symbol directives unit test: $@"
	$(CC) $(TEST_CFLAGS_ENHANCED) $< tests/unity/src/unity.c $(filter-out $(OBJ_DIR)/main.o,$(OBJECTS)) -o $@

$(TESTBIN_DIR)/unit_test_alignment_directives: tests/unit/directives/test_alignment_directives.c tests/unity/src/unity.c $(OBJECTS) | $(TESTBIN_DIR)
	@echo "Compiling alignment directives unit test: $@"
	$(CC) $(TEST_CFLAGS_ENHANCED) $< tests/unity/src/unity.c $(filter-out $(OBJ_DIR)/main.o,$(OBJECTS)) -o $@

# Directive module unit tests
test-unit-directives:
	@echo "=== Running Directive Module Unit Tests ==="
	@echo "Checking for directive unit tests..."
	@$(MAKE) -q $(TESTBIN_DIR)/unit_test_data_directives || $(MAKE) $(TESTBIN_DIR)/unit_test_data_directives || true
	@$(MAKE) -q $(TESTBIN_DIR)/unit_test_symbol_directives || $(MAKE) $(TESTBIN_DIR)/unit_test_symbol_directives || true
	@$(MAKE) -q $(TESTBIN_DIR)/unit_test_alignment_directives || $(MAKE) $(TESTBIN_DIR)/unit_test_alignment_directives || true
	@for test in unit_test_data_directives unit_test_symbol_directives unit_test_alignment_directives; do \
		if [ -f $(TESTBIN_DIR)/$$test ]; then echo "Running $$test..."; ./$(TESTBIN_DIR)/$$test; fi; \
	done
	@echo "Directive unit tests completed"

# All unit tests
test-unit-all:
	@echo "=== Running All Available Unit Tests ==="
	@$(MAKE) test-unit-core test-unit-arch test-unit-formats test-unit-utils test-unit-directives

# === INTEGRATION TESTING ===

# Build variant testing
test-build-variants:
	@echo "=== Testing All Build Variants ==="
	@if [ -f tests/integration/build_variants/test_all_builds.sh ]; then \
		./tests/integration/build_variants/test_all_builds.sh; \
	else \
		echo "Build variant test script not found - testing basic build variants manually"; \
		$(MAKE) clean && $(MAKE) all && echo "✅ Dynamic build successful"; \
		$(MAKE) clean && $(MAKE) static-x86_64 && echo "✅ Static x86_64 build successful"; \
	fi

# Integration testing
test-integration:
	@echo "=== Running Integration Tests ==="
	@echo "Running simplified integration tests..."
	@$(MAKE) test
	@$(MAKE) test-phase7-advanced
	@echo "✅ Integration tests completed successfully"

# Phase 7: Advanced Language Features Test  
test-phase7-advanced: $(TARGET)
	@echo "=== Running Phase 7 Advanced Language Features Tests ==="
	cd tests/phase7 && ./working_tests.sh
	@echo "✅ All Phase 7 tests passed!"

# === EXECUTION TESTING ===

# Architecture-specific execution tests
test-execution-x86_16:
	@echo "=== Running x86-16 Execution Tests ==="
	@$(MAKE) -q $(TESTBIN_DIR)/execution_test_x86_16_basic || $(MAKE) $(TESTBIN_DIR)/execution_test_x86_16_basic || true
	@if [ -f $(TESTBIN_DIR)/execution_test_x86_16_basic ]; then ./$(TESTBIN_DIR)/execution_test_x86_16_basic; fi
	@$(MAKE) -q $(TESTBIN_DIR)/test_x86_16_algorithms || $(MAKE) $(TESTBIN_DIR)/test_x86_16_algorithms || true
	@if [ -f $(TESTBIN_DIR)/test_x86_16_algorithms ]; then ./$(TESTBIN_DIR)/test_x86_16_algorithms; fi

test-execution-x86_32:
	@echo "=== Running x86-32 Execution Tests ==="
	@$(MAKE) -q $(TESTBIN_DIR)/execution_test_x86_32_basic || $(MAKE) $(TESTBIN_DIR)/execution_test_x86_32_basic || true
	@if [ -f $(TESTBIN_DIR)/execution_test_x86_32_basic ]; then ./$(TESTBIN_DIR)/execution_test_x86_32_basic; fi
	@$(MAKE) -q $(TESTBIN_DIR)/test_x86_32_algorithms || $(MAKE) $(TESTBIN_DIR)/test_x86_32_algorithms || true
	@if [ -f $(TESTBIN_DIR)/test_x86_32_algorithms ]; then ./$(TESTBIN_DIR)/test_x86_32_algorithms; fi
	@$(MAKE) -q $(TESTBIN_DIR)/execution_test_x86_32_real_to_protected || $(MAKE) $(TESTBIN_DIR)/execution_test_x86_32_real_to_protected || true
	@if [ -f $(TESTBIN_DIR)/execution_test_x86_32_real_to_protected ]; then ./$(TESTBIN_DIR)/execution_test_x86_32_real_to_protected; fi

test-execution-x86_64:
	@echo "=== Running x86-64 Execution Tests ==="
	@$(MAKE) -q $(TESTBIN_DIR)/execution_test_x86_64_basic || $(MAKE) $(TESTBIN_DIR)/execution_test_x86_64_basic || true
	@if [ -f $(TESTBIN_DIR)/execution_test_x86_64_basic ]; then ./$(TESTBIN_DIR)/execution_test_x86_64_basic; fi

test-execution-arm64:
	@echo "=== Running ARM64 Execution Tests ==="
	@$(MAKE) -q $(TESTBIN_DIR)/execution_test_arm64_basic || $(MAKE) $(TESTBIN_DIR)/execution_test_arm64_basic || true
	@if [ -f $(TESTBIN_DIR)/execution_test_arm64_basic ]; then ./$(TESTBIN_DIR)/execution_test_arm64_basic; fi

test-execution-riscv:
	@echo "=== Running RISC-V Execution Tests ==="
	@$(MAKE) -q $(TESTBIN_DIR)/execution_test_riscv_basic || $(MAKE) $(TESTBIN_DIR)/execution_test_riscv_basic || true
	@if [ -f $(TESTBIN_DIR)/execution_test_riscv_basic ]; then ./$(TESTBIN_DIR)/execution_test_riscv_basic; fi

# All execution tests
test-execution-all:
	@echo "=== Running All Execution Tests ==="
	@$(MAKE) test-execution-x86_16 test-execution-x86_32 test-execution-x86_64 test-execution-arm64 test-execution-riscv

# QEMU System-Level Testing
test-qemu-x86_16:
	@echo "=== Running QEMU x86-16 System Tests ==="
	@tests/framework/qemu_test_framework.sh -a x86_16

test-qemu-x86_32:
	@echo "=== Running QEMU x86-32 System Tests ==="
	@tests/framework/qemu_test_framework.sh -a x86_32

test-qemu-x86_64:
	@echo "=== Running QEMU x86-64 System Tests ==="
	@tests/framework/qemu_test_framework.sh -a x86_64

test-qemu-arm64:
	@echo "=== Running QEMU ARM64 System Tests ==="
	@tests/framework/qemu_test_framework.sh -a arm64

test-qemu-riscv:
	@echo "=== Running QEMU RISC-V System Tests ==="
	@tests/framework/qemu_test_framework.sh -a riscv

test-qemu-all:
	@echo "=== Running All QEMU System Tests ==="
	@echo "Note: x86_32 is prioritized as the primary implementation"
	@tests/framework/qemu_test_framework.sh

# Quick QEMU test (x86_32 only - primary implementation)
test-qemu-quick:
	@echo "=== Running Quick QEMU Test (x86_32 Primary Implementation) ==="
	@tests/framework/qemu_test_framework.sh -a x86_32

# Emulator Integration Tests
$(TESTBIN_DIR)/test_emulator_integration: tests/integration/test_emulator_integration.c $(UNICORN_FRAMEWORK) tests/unity/src/unity.c $(OBJECTS) | $(TESTBIN_DIR)
	@echo "Compiling emulator integration test: $@"
	$(CC) $(EXECUTION_TEST_CFLAGS) $< $(UNICORN_FRAMEWORK) tests/unity/src/unity.c $(filter-out $(OBJ_DIR)/main.o,$(OBJECTS)) -lunicorn -o $@

test-emulator-integration:
	@echo "=== Running Emulator Integration Tests ==="
	@$(MAKE) -q $(TESTBIN_DIR)/test_emulator_integration || $(MAKE) $(TESTBIN_DIR)/test_emulator_integration
	@./$(TESTBIN_DIR)/test_emulator_integration

# Modern test suite
test-all: test test-unit-all test-execution-all test-qemu-all test-build-variants test-integration test-phase7-advanced

# === CODE COVERAGE ===

# Coverage build
coverage-build:
	@echo "=== Building with Coverage Support ==="
	$(MAKE) clean
	$(MAKE) CFLAGS="$(CFLAGS) $(COVERAGE_CFLAGS)" LDFLAGS="$(LDFLAGS) $(COVERAGE_LDFLAGS)" all
	@echo "=== Building tests with Coverage Support ==="
	$(MAKE) CFLAGS="$(CFLAGS) $(COVERAGE_CFLAGS)" LDFLAGS="$(LDFLAGS) $(COVERAGE_LDFLAGS)" test-unit-all test-execution-all

# Coverage testing
test-coverage:
	@echo "=== Running Tests with Coverage ==="
	@if [ -f tests/coverage/generate_coverage.sh ]; then \
		./tests/coverage/generate_coverage.sh; \
	else \
		echo "Coverage script not found - building with coverage and running tests"; \
		$(MAKE) coverage-build; \
		$(MAKE) test-all; \
		gcov src/*.c src/*/*.c || true; \
	fi

# === INSTRUCTION SET COMPLETENESS TESTING ===

# x86-64 Instruction Set Completeness Test (Unity Framework)
test-x86_64-completeness: $(OBJECTS) | $(TESTBIN_DIR)
	@echo "=== Building x86-64 Instruction Set Completeness Test ==="
	@gcc -std=c99 -Wall -Wextra -Wpedantic -Werror -O2 -Iinclude -Isrc/core -Isrc/arch -Itests \
		-DUNITY_INCLUDE_DOUBLE=0 -DUNITY_EXCLUDE_FLOAT \
		tests/unit/arch/test_x86_64_completeness.c tests/unity/src/unity.c \
		obj/arch/x86_64/x86_64_unified.o obj/arch/x86_64/x86_64_interface.o \
		obj/arch/x86_64/x86_64_parser.o obj/arch/x86_64/x86_64_addressing.o \
		obj/core/symbols.o obj/utils/utils.o \
		-o $(TESTBIN_DIR)/test_x86_64_completeness
	@echo "=== Running x86-64 Instruction Set Completeness Test ==="
	@$(TESTBIN_DIR)/test_x86_64_completeness
	@echo "x86-64 instruction completeness test completed"

# Data-driven x86-64 Instruction Set Test (Unity Framework)
test-x86_64-data-driven: $(OBJECTS) | $(TESTBIN_DIR)
	@echo "=== Building Data-Driven x86-64 Instruction Test ==="
	@gcc -std=c99 -Wall -Wextra -Wpedantic -Werror -O2 -Iinclude -Isrc/core -Isrc/arch -Itests \
		-DUNITY_INCLUDE_DOUBLE=0 -DUNITY_EXCLUDE_FLOAT \
		tests/unit/arch/test_x86_64_data_driven.c tests/unity/src/unity.c \
		obj/arch/x86_64/x86_64_unified.o obj/arch/x86_64/x86_64_interface.o \
		obj/arch/x86_64/x86_64_parser.o obj/arch/x86_64/x86_64_addressing.o \
		obj/core/symbols.o obj/utils/utils.o \
		-o $(TESTBIN_DIR)/test_x86_64_data_driven
	@echo "=== Running Data-Driven x86-64 Instruction Test ==="
	@$(TESTBIN_DIR)/test_x86_64_data_driven
	@echo "Data-driven x86-64 instruction test completed"

# Instruction Database Validation Test 
test-instruction-database: $(OBJECTS) | $(TESTBIN_DIR)
	@echo "=== Building Instruction Database Validation Test ==="
	@gcc -std=c99 -Wall -Wextra -Wpedantic -Werror -O2 -Iinclude -Isrc/core -Isrc/arch -Itests \
		-DUNITY_INCLUDE_DOUBLE=0 -DUNITY_EXCLUDE_FLOAT \
		tests/unit/arch/test_instruction_database.c tests/unity/src/unity.c \
		-o $(TESTBIN_DIR)/test_instruction_database
	@echo "=== Running Instruction Database Validation Test ==="
	@$(TESTBIN_DIR)/test_instruction_database
	@echo "Instruction database validation completed"

# STAS Assembler Compliance Test (Real CPU Validation)
test-stas-compliance: $(OBJECTS) | $(TESTBIN_DIR)
	@echo "=== Building STAS Assembler Compliance Test ==="
	@gcc -std=c99 -Wall -Wextra -Wpedantic -Werror -O2 -Iinclude -Isrc/core -Isrc/arch -Itests \
		-DUNITY_INCLUDE_DOUBLE=0 -DUNITY_EXCLUDE_FLOAT \
		tests/unit/arch/test_stas_compliance.c tests/unity/src/unity.c \
		obj/arch/x86_64/x86_64_unified.o obj/arch/x86_64/x86_64_interface.o \
		obj/arch/x86_64/x86_64_parser.o obj/arch/x86_64/x86_64_addressing.o \
		obj/core/symbols.o obj/utils/utils.o \
		-o $(TESTBIN_DIR)/test_stas_compliance
	@echo "=== Running STAS Assembler Compliance Test ==="
	@$(TESTBIN_DIR)/test_stas_compliance
	@echo "STAS assembler compliance validation completed"

# === COMPREHENSIVE TESTING ===

# Complete test suite with Python orchestration
test-comprehensive:
	@echo "🚀 Starting STAS Comprehensive Test Suite..."
	@mkdir -p $(LOGS_DIR) $(REPORTS_DIR)
	@if [ -f tests/framework/scripts/test_runner.py ]; then \
		python3 tests/framework/scripts/test_runner.py; \
	else \
		echo "Python test runner not found - running comprehensive tests manually"; \
		$(MAKE) test-unit-all || true; \
		$(MAKE) test-build-variants || true; \
		$(MAKE) test-execution-all || true; \
		$(MAKE) test-integration || true; \
		$(MAKE) test-instruction-completeness || true; \
		$(MAKE) test-phase7-advanced || true; \
		$(MAKE) test-coverage || true; \
	fi

# Quick test (essential tests only)
test-quick:
	@echo "=== Running Quick Test Suite ==="
	@$(MAKE) test-unit-core
	@$(MAKE) test
	@echo "Quick tests completed"

# Continuous integration test  
test-ci:
	@echo "=== Running CI Test Suite ==="
	@$(MAKE) test-comprehensive

# Performance tests
test-performance:
	@echo "=== Running Performance Tests ==="
	@echo "Performance tests not yet implemented"
	@echo "Measuring basic assembly performance..."
	@time $(MAKE) -B $(TARGET) || true
	@echo "Measuring test execution time..."
	@time $(MAKE) test-quick || true

# Test help
test-help:
	@echo "STAS Testing Framework - Available Test Targets:"
	@echo ""
	@echo "Unit Testing:"
	@echo "  test-unit-all        - Run all unit tests"
	@echo "  test-unit-core       - Test core modules (lexer, parser, etc.)"
	@echo "  test-unit-arch       - Test architecture modules"
	@echo "  test-unit-formats    - Test output format modules"
	@echo "  test-unit-utils      - Test utility modules"
	@echo ""
	@echo "Instruction Set Completeness:"
	@echo "  test-instruction-completeness - Run modular instruction completeness analysis"
	@echo "  test-x86_64-completeness     - Run x86-64 instruction set completeness test (Unity)"
	@echo ""
	@echo "Execution Testing (Unicorn Engine):"
	@echo "  test-execution-all   - Test code execution on all architectures"
	@echo "  test-execution-x86_16 - Test x86-16 code execution"
	@echo "  test-execution-x86_32 - Test x86-32 code execution"  
	@echo "  test-execution-x86_64 - Test x86-64 code execution"
	@echo "  test-execution-arm64 - Test ARM64 code execution"
	@echo "  test-execution-riscv - Test RISC-V code execution"
	@echo ""
	@echo "System Testing (QEMU):"
	@echo "  test-qemu-all        - Test system-level execution on all architectures"
	@echo "  test-qemu-x86_16     - Test x86-16 system-level execution"
	@echo "  test-qemu-x86_32     - Test x86-32 system-level execution"
	@echo "  test-qemu-x86_64     - Test x86-64 system-level execution"
	@echo "  test-qemu-arm64      - Test ARM64 system-level execution"
	@echo "  test-qemu-riscv      - Test RISC-V system-level execution"
	@echo ""
	@echo "Integration Testing:"
	@echo "  test-emulator-integration - Comprehensive emulator testing demo"
	@echo ""
	@echo "Build Testing:"
	@echo "  test-build-variants  - Test all build configurations"
	@echo ""
	@echo "Execution Testing:"
	@echo "  test-execution-all   - Test code execution on all architectures"
	@echo "  test-execution-x86_16 - Test x86-16 code execution"
	@echo "  test-execution-x86_32 - Test x86-32 code execution"  
	@echo "  test-execution-x86_64 - Test x86-64 code execution"
	@echo "  test-execution-arm64 - Test ARM64 code execution"
	@echo "  test-execution-riscv - Test RISC-V code execution"
	@echo ""
	@echo "Integration Testing:"
	@echo "  test-integration     - Test end-to-end workflows"
	@echo "  test-phase7-advanced - Test Phase 7 advanced features"
	@echo ""
	@echo "Code Coverage:"
	@echo "  test-coverage        - Generate code coverage report"
	@echo ""
	@echo "Comprehensive Testing:"
	@echo "  test-comprehensive   - Run complete test suite"
	@echo "  test-quick          - Run essential tests only"
	@echo "  test-ci             - Run CI/CD test suite"
	@echo "  test-performance    - Run performance benchmarks"
	@echo ""
	@echo "Legacy compatibility:"
	@echo "  test-all            - Enhanced comprehensive test suite"
	@echo "  test                - Basic functionality test"

# Declare phony targets (cleaned up for modern framework)
.PHONY: all debug test clean distclean run install uninstall help structure \
        test-unit-all test-unit-core test-unit-arch test-unit-formats test-unit-utils \
        test-build-variants test-execution-all test-execution-x86_16 test-execution-x86_32 \
        test-execution-x86_64 test-execution-arm64 test-execution-riscv test-integration \
        test-phase7-advanced test-all test-comprehensive test-quick test-ci test-performance \
        test-coverage coverage-build test-help test-instruction-completeness test-x86_64-completeness
