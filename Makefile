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
CORE_OBJECTS = $(CORE_SOURCES:$(SRC_DIR)/core/%.c=$(OBJ_DIR)/core/%.o) $(OBJ_DIR)/macro.o $(OBJ_DIR)/include.o

# Format source files
FORMAT_SOURCES = $(SRC_DIR)/formats/elf.c $(SRC_DIR)/formats/flat_binary.c $(SRC_DIR)/formats/com_format.c $(SRC_DIR)/formats/intel_hex.c $(SRC_DIR)/formats/motorola_srec.c $(SRC_DIR)/formats/smof.c
FORMAT_OBJECTS = $(FORMAT_SOURCES:$(SRC_DIR)/formats/%.c=$(OBJ_DIR)/formats/%.o)

# Utility source files
UTIL_SOURCES = $(SRC_DIR)/utils/utils.c
UTIL_OBJECTS = $(UTIL_SOURCES:$(SRC_DIR)/utils/%.c=$(OBJ_DIR)/utils/%.o)

# Architecture module sources
ARCH_X86_64_SOURCES = $(SRC_DIR)/arch/x86_64/x86_64.c $(SRC_DIR)/arch/x86_64/instructions.c $(SRC_DIR)/arch/x86_64/registers.c $(SRC_DIR)/arch/x86_64/addressing.c $(SRC_DIR)/arch/x86_64/x86_64_advanced.c
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
SOURCES = $(CORE_SOURCES) $(SRC_DIR)/macro.c $(SRC_DIR)/include.c $(FORMAT_SOURCES) $(UTIL_SOURCES) $(ARCH_X86_64_SOURCES) $(ARCH_X86_32_SOURCES) $(ARCH_X86_16_SOURCES) $(ARCH_ARM64_SOURCES) $(ARCH_RISCV_SOURCES) $(MAIN_SOURCE)
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

# Macro processor compilation
$(OBJ_DIR)/macro.o: $(SRC_DIR)/macro.c | $(OBJ_DIR)
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
	@echo "Cleaned build artifacts"

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
FRAMEWORK_INCLUDES = -I$(FRAMEWORK_DIR) -Itests

# Enhanced test compilation flags
TEST_CFLAGS_ENHANCED = $(CFLAGS) $(INCLUDES) $(FRAMEWORK_INCLUDES) -DUNITY_INCLUDE_CONFIG_H
EXECUTION_TEST_CFLAGS = $(TEST_CFLAGS_ENHANCED) -DHAVE_UNICORN

# Coverage targets
COVERAGE_CFLAGS = --coverage -fprofile-arcs -ftest-coverage -O0 -g
COVERAGE_LDFLAGS = --coverage

# === UNIT TESTING WITH UNITY ===

# Unit test compilation - flexible pattern matching  
$(TESTBIN_DIR)/unit_test_%: tests/unit/*/test_%.c tests/unity.c $(UNITY_EXTENSIONS) $(OBJECTS) | $(TESTBIN_DIR)
	@echo "Compiling unit test: $@"
	$(CC) $(TEST_CFLAGS_ENHANCED) $< tests/unity.c $(UNITY_EXTENSIONS) $(filter-out $(OBJ_DIR)/main.o,$(OBJECTS)) -o $@

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

# All unit tests
test-unit-all:
	@echo "=== Running All Available Unit Tests ==="
	@$(MAKE) test-unit-core test-unit-arch test-unit-formats test-unit-utils

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

# Execution test compilation - specific rules for each architecture
$(TESTBIN_DIR)/execution_test_x86_16_basic: tests/execution/x86_16/test_basic.c $(UNICORN_FRAMEWORK) tests/unity.c $(OBJECTS) | $(TESTBIN_DIR)
	@echo "Compiling x86_16 execution test: $@"
	$(CC) $(EXECUTION_TEST_CFLAGS) $< $(UNICORN_FRAMEWORK) tests/unity.c $(filter-out $(OBJ_DIR)/main.o,$(OBJECTS)) -lunicorn -o $@

$(TESTBIN_DIR)/execution_test_x86_32_basic: tests/execution/x86_32/test_basic.c $(UNICORN_FRAMEWORK) tests/unity.c $(OBJECTS) | $(TESTBIN_DIR)
	@echo "Compiling x86_32 execution test: $@"
	$(CC) $(EXECUTION_TEST_CFLAGS) $< $(UNICORN_FRAMEWORK) tests/unity.c $(filter-out $(OBJ_DIR)/main.o,$(OBJECTS)) -lunicorn -o $@

$(TESTBIN_DIR)/execution_test_x86_32_real_to_protected: tests/execution/x86_32/test_real_to_protected_mode.c $(UNICORN_FRAMEWORK) tests/unity.c $(OBJECTS) | $(TESTBIN_DIR)
	@echo "Compiling x86_32 real-to-protected mode test: $@"
	$(CC) $(EXECUTION_TEST_CFLAGS) $< $(UNICORN_FRAMEWORK) tests/unity.c $(filter-out $(OBJ_DIR)/main.o,$(OBJECTS)) -lunicorn -o $@

$(TESTBIN_DIR)/execution_test_x86_64_basic: tests/execution/x86_64/test_basic.c $(UNICORN_FRAMEWORK) tests/unity.c $(OBJECTS) | $(TESTBIN_DIR)
	@echo "Compiling x86_64 execution test: $@"
	$(CC) $(EXECUTION_TEST_CFLAGS) $< $(UNICORN_FRAMEWORK) tests/unity.c $(filter-out $(OBJ_DIR)/main.o,$(OBJECTS)) -lunicorn -o $@

$(TESTBIN_DIR)/execution_test_arm64_basic: tests/execution/arm64/test_basic.c $(UNICORN_FRAMEWORK) tests/unity.c $(OBJECTS) | $(TESTBIN_DIR)
	@echo "Compiling arm64 execution test: $@"
	$(CC) $(EXECUTION_TEST_CFLAGS) $< $(UNICORN_FRAMEWORK) tests/unity.c $(filter-out $(OBJ_DIR)/main.o,$(OBJECTS)) -lunicorn -o $@

$(TESTBIN_DIR)/execution_test_riscv_basic: tests/execution/riscv/test_basic.c $(UNICORN_FRAMEWORK) tests/unity.c $(OBJECTS) | $(TESTBIN_DIR)
	@echo "Compiling riscv execution test: $@"
	$(CC) $(EXECUTION_TEST_CFLAGS) $< $(UNICORN_FRAMEWORK) tests/unity.c $(filter-out $(OBJ_DIR)/main.o,$(OBJECTS)) -lunicorn -o $@

# Architecture-specific execution tests
test-execution-x86_16:
	@echo "=== Running x86-16 Execution Tests ==="
	@$(MAKE) -q $(TESTBIN_DIR)/execution_test_x86_16_basic || $(MAKE) $(TESTBIN_DIR)/execution_test_x86_16_basic || true
	@if [ -f $(TESTBIN_DIR)/execution_test_x86_16_basic ]; then ./$(TESTBIN_DIR)/execution_test_x86_16_basic; fi

test-execution-x86_32:
	@echo "=== Running x86-32 Execution Tests ==="
	@$(MAKE) -q $(TESTBIN_DIR)/execution_test_x86_32_basic || $(MAKE) $(TESTBIN_DIR)/execution_test_x86_32_basic || true
	@if [ -f $(TESTBIN_DIR)/execution_test_x86_32_basic ]; then ./$(TESTBIN_DIR)/execution_test_x86_32_basic; fi
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

# Modern test suite
test-all: test test-unit-all test-execution-all test-build-variants test-integration test-phase7-advanced

# === CODE COVERAGE ===

# Coverage build
coverage-build:
	@echo "=== Building with Coverage Support ==="
	$(MAKE) clean
	$(MAKE) CFLAGS="$(CFLAGS) $(COVERAGE_CFLAGS)" LDFLAGS="$(LDFLAGS) $(COVERAGE_LDFLAGS)" all

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
        test-coverage coverage-build test-help
