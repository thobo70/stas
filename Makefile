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

# Core source files (moved to src/core)
CORE_SOURCES = $(SRC_DIR)/core/lexer.c $(SRC_DIR)/core/parser.c $(SRC_DIR)/core/expr.c $(SRC_DIR)/core/symbols.c $(SRC_DIR)/core/expressions.c $(SRC_DIR)/core/output.c $(SRC_DIR)/core/output_format.c $(SRC_DIR)/core/codegen.c
CORE_OBJECTS = $(CORE_SOURCES:$(SRC_DIR)/core/%.c=$(OBJ_DIR)/core/%.o) $(OBJ_DIR)/macro.o $(OBJ_DIR)/include.o

# Format source files
FORMAT_SOURCES = $(SRC_DIR)/formats/elf.c $(SRC_DIR)/formats/flat_binary.c $(SRC_DIR)/formats/com_format.c $(SRC_DIR)/formats/intel_hex.c $(SRC_DIR)/formats/motorola_srec.c
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
SOURCES = $(CORE_SOURCES) $(FORMAT_SOURCES) $(UTIL_SOURCES) $(ARCH_X86_64_SOURCES) $(ARCH_X86_32_SOURCES) $(ARCH_X86_16_SOURCES) $(ARCH_ARM64_SOURCES) $(ARCH_RISCV_SOURCES) $(MAIN_SOURCE)
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

# Unity Testing Framework
UNITY_DIR = tests
UNITY_SRC = $(UNITY_DIR)/unity.c
UNITY_HEADERS = $(UNITY_DIR)/unity.h $(UNITY_DIR)/unity_internals.h

# Test source files
TEST_SOURCES = $(wildcard tests/test_*.c)
TEST_OBJECTS = $(TEST_SOURCES:.c=.o)
TEST_TARGETS = $(TEST_SOURCES:.c=)

# Unity test compilation flags
TEST_CFLAGS = $(CFLAGS) -I$(UNITY_DIR) -I$(INCLUDE_DIR)

# Unity unit tests
test-unity: $(TEST_TARGETS)
	@echo "==========================================="
	@echo "Running STAS Unit Tests"
	@echo "==========================================="
	@for test in $(TEST_TARGETS); do \
		echo "Running $$test..."; \
		if ./$$test; then \
			echo "✅ $$test PASSED"; \
		else \
			echo "❌ $$test FAILED"; \
			exit 1; \
		fi; \
		echo ""; \
	done
	@echo "🎉 All unit tests completed successfully!"

# Individual test compilation
tests/test_%: tests/test_%.c $(UNITY_SRC) $(UNITY_HEADERS) $(OBJECTS)
	@echo "Compiling unit test: $@"
	$(CC) $(TEST_CFLAGS) $< $(UNITY_SRC) $(filter-out $(OBJ_DIR)/main.o,$(OBJECTS)) -o $@

# Test object files
tests/%.o: tests/%.c $(UNITY_HEADERS)
	$(CC) $(TEST_CFLAGS) -c $< -o $@

# Clean test artifacts
test-clean:
	@echo "Cleaning test artifacts..."
	rm -f $(TEST_TARGETS) $(TEST_OBJECTS)

# Run Unicorn Engine tests
test-unicorn: $(TARGET)
	@echo "Running Unicorn Engine tests..."
	./tests/run_unicorn_tests.sh

# Build Unicorn test program
test-unicorn-build:
	@echo "Building Unicorn test program..."
	@if pkg-config --exists unicorn 2>/dev/null; then \
		gcc $(CFLAGS) `pkg-config --cflags unicorn` tests/test_unicorn_comprehensive.c `pkg-config --libs unicorn` -o tests/test_unicorn_comprehensive; \
	else \
		gcc $(CFLAGS) tests/test_unicorn_comprehensive.c -lunicorn -o tests/test_unicorn_comprehensive; \
	fi

# Run all tests
test-all: test test-unity test-unicorn

# Clean build artifacts
clean:
	rm -rf $(OBJ_DIR) $(BIN_DIR)
	@echo "Cleaned build artifacts"

# Clean everything including directories
distclean: clean
	rm -rf $(OBJ_DIR) $(BIN_DIR)
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

# Show help
help:
	@echo "Available targets:"
	@echo "  all          - Build the project (default)"
	@echo "  debug        - Build with debug symbols"
	@echo "  test         - Build and test with sample assembly"
	@echo "  test-unity   - Run unit tests (Unity framework)"
	@echo "  test-unicorn - Run Unicorn Engine emulation tests"
	@echo "  test-unicorn-build - Build Unicorn test program"
	@echo "  test-phase2-parsing - Run Phase 2 advanced parsing tests"
	@echo "  test-phase3-symbols - Run Phase 3 symbol enhancement tests"
	@echo "  test-phase3-basic   - Run Phase 3 basic symbol tests"
	@echo "  test-phase3-comprehensive - Run Phase 3 comprehensive symbol tests"
	@echo "  test-phase4-x86-64  - Run Phase 4 x86-64 architecture tests"
	@echo "  test-phase4-comprehensive - Run Phase 4 comprehensive encoding tests"
	@echo "  test-phase4-expanded - Run Phase 4 expanded instruction set tests"
	@echo "  test-all-phases     - Run all phase tests (Phase 2 + Phase 3)"
	@echo "  test-all     - Run all tests (sample + unity + unicorn)"
	@echo "  test-clean   - Clean test artifacts"
	@echo "  static-x86_16 - Build static x86-16 only assembler"
	@echo "  static-x86_32 - Build static x86-32 only assembler"
	@echo "  static-x86_64 - Build static x86-64 only assembler"
	@echo "  static-arm64 - Build static ARM64 only assembler"
	@echo "  static-riscv - Build static RISC-V only assembler"
	@echo "  static-all   - Build all static architecture variants"
	@echo "  clean        - Remove object files and executable"
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

# Comprehensive x86_16 test with Unicorn Engine
test-x86_16-comprehensive: bin/test_x86_16_comprehensive
	@echo "==========================================="
	@echo "Running Comprehensive x86_16 Test Suite"
	@echo "==========================================="
	./bin/test_x86_16_comprehensive

bin/test_x86_16_comprehensive: tests/test_x86_16_comprehensive.c $(ARCH_X86_16_OBJECTS) $(CORE_OBJECTS) | $(BIN_DIR)
	@echo "Building comprehensive x86_16 test..."
	$(CC) $(CFLAGS) $(INCLUDES) -I$(UNITY_DIR) \
		tests/test_x86_16_comprehensive.c \
		$(ARCH_X86_16_OBJECTS) \
		$(OBJ_DIR)/core/output_format.o \
		`pkg-config --cflags --libs unicorn` \
		-o $@
	@echo "Comprehensive x86_16 test built: $@"

# Phase 2: Advanced Parsing Test
test-phase2-parsing: bin/test_phase2_advanced_parsing
	@echo "==========================================="
	@echo "Running Phase 2 Advanced Parsing Tests"
	@echo "==========================================="
	./bin/test_phase2_advanced_parsing

bin/test_phase2_advanced_parsing: tests/test_phase2_advanced_parsing.c $(ARCH_X86_16_OBJECTS) $(CORE_OBJECTS) $(UTIL_OBJECTS) | $(BIN_DIR)
	@echo "Building Phase 2 advanced parsing test..."
	$(CC) $(CFLAGS) -g -O0 $(INCLUDES) \
		tests/test_phase2_advanced_parsing.c \
		$(ARCH_X86_16_OBJECTS) \
		$(CORE_OBJECTS) \
		$(UTIL_OBJECTS) \
		-o $@
	@echo "Phase 2 advanced parsing test built: $@"

# Phase 3: Symbol Table Enhancement Tests
test-phase3-symbols: bin/test_phase3_final
	@echo "==========================================="
	@echo "Running Phase 3 Symbol Enhancement Tests"
	@echo "==========================================="
	./bin/test_phase3_final

bin/test_phase3_final: tests/test_phase3_final.c $(ARCH_X86_16_OBJECTS) $(CORE_OBJECTS) $(UTIL_OBJECTS) | $(BIN_DIR)
	@echo "Building Phase 3 symbol enhancement test..."
	$(CC) $(CFLAGS) -g -O0 $(INCLUDES) \
		tests/test_phase3_final.c \
		$(ARCH_X86_16_OBJECTS) \
		$(CORE_OBJECTS) \
		$(UTIL_OBJECTS) \
		-o $@
	@echo "Phase 3 symbol enhancement test built: $@"

# Phase 3: Basic Symbol Test (simpler version)
test-phase3-basic: bin/test_phase3_basic
	@echo "==========================================="
	@echo "Running Phase 3 Basic Symbol Tests"
	@echo "==========================================="
	./bin/test_phase3_basic

bin/test_phase3_basic: tests/test_phase3_basic.c $(ARCH_X86_16_OBJECTS) $(CORE_OBJECTS) $(UTIL_OBJECTS) | $(BIN_DIR)
	@echo "Building Phase 3 basic symbol test..."
	$(CC) $(CFLAGS) -g -O0 $(INCLUDES) \
		tests/test_phase3_basic.c \
		$(ARCH_X86_16_OBJECTS) \
		$(CORE_OBJECTS) \
		$(UTIL_OBJECTS) \
		-o $@
	@echo "Phase 3 basic symbol test built: $@"

# Phase 3: Comprehensive Symbol Test
test-phase3-comprehensive: bin/test_phase3_comprehensive
	@echo "==========================================="
	@echo "Running Phase 3 Comprehensive Symbol Tests"
	@echo "==========================================="
	./bin/test_phase3_comprehensive

bin/test_phase3_comprehensive: tests/test_phase3_symbol_enhancement.c $(ARCH_X86_16_OBJECTS) $(CORE_OBJECTS) $(UTIL_OBJECTS) | $(BIN_DIR)
	@echo "Building Phase 3 comprehensive symbol test..."
	$(CC) $(CFLAGS) -g -O0 $(INCLUDES) \
		tests/test_phase3_symbol_enhancement.c \
		$(ARCH_X86_16_OBJECTS) \
		$(CORE_OBJECTS) \
		$(UTIL_OBJECTS) \
		-o $@
	@echo "Phase 3 comprehensive symbol test built: $@"

# Test all phases
test-all-phases: test-phase2-parsing test-phase3-symbols test-phase3-basic test-phase3-comprehensive test-phase4-x86-64 test-phase4-comprehensive test-phase4-expanded
	@echo "🎉 All phase tests completed successfully!"

# Phase 4: x86-64 Architecture Module Tests
test-phase4-x86-64: bin/test_phase4_x86_64
	@echo "=========================================="
	@echo "Running Phase 4 x86-64 Architecture Tests"
	@echo "=========================================="
	./bin/test_phase4_x86_64

bin/test_phase4_x86_64: tests/test_phase4_x86_64.c $(ARCH_X86_64_OBJECTS) $(CORE_OBJECTS) $(UTIL_OBJECTS) | $(BIN_DIR)
	@echo "Building Phase 4 x86-64 test..."
	$(CC) $(CFLAGS) -g -O0 $(INCLUDES) \
		tests/test_phase4_x86_64.c \
		tests/unity.c \
		$(ARCH_X86_64_OBJECTS) \
		$(CORE_OBJECTS) \
		$(UTIL_OBJECTS) \
		-o $@
	@echo "Phase 4 x86-64 test built: $@"

test-phase4-comprehensive: bin/test_phase4_comprehensive
	@echo "============================================="
	@echo "Running Phase 4 Comprehensive Encoding Tests"
	@echo "============================================="
	./bin/test_phase4_comprehensive

bin/test_phase4_comprehensive: tests/test_phase4_comprehensive.c $(ARCH_X86_64_OBJECTS) $(CORE_OBJECTS) $(UTIL_OBJECTS) | $(BIN_DIR)
	@echo "Building Phase 4 comprehensive test..."
	$(CC) $(CFLAGS) -g -O0 $(INCLUDES) \
		tests/test_phase4_comprehensive.c \
		tests/unity.c \
		$(ARCH_X86_64_OBJECTS) \
		$(CORE_OBJECTS) \
		$(UTIL_OBJECTS) \
		-o $@
	@echo "Phase 4 comprehensive test built: $@"

test-phase4-expanded: bin/test_phase4_expanded
	@echo "============================================"
	@echo "Running Phase 4 Expanded Instruction Tests"
	@echo "============================================"
	./bin/test_phase4_expanded

bin/test_phase4_expanded: tests/test_phase4_expanded.c $(ARCH_X86_64_OBJECTS) $(CORE_OBJECTS) $(UTIL_OBJECTS) | $(BIN_DIR)
	@echo "Building Phase 4 expanded instruction test..."
	$(CC) $(CFLAGS) -g -O0 $(INCLUDES) \
		tests/test_phase4_expanded.c \
		tests/unity.c \
		$(ARCH_X86_64_OBJECTS) \
		$(CORE_OBJECTS) \
		$(UTIL_OBJECTS) \
		-o $@
	@echo "Phase 4 expanded instruction test built: $@"

# Phase 5 Testing: Advanced Output Formats
test-phase5-elf: bin/test_phase5_elf bin/stas
	@echo "==========================================="
	@echo "Running Phase 5 ELF Format Tests"
	@echo "==========================================="
	./bin/test_phase5_elf

bin/test_phase5_elf: tests/test_phase5_elf.c $(FORMAT_OBJECTS) $(ARCH_X86_64_OBJECTS) $(ARCH_X86_32_OBJECTS) $(CORE_OBJECTS) $(UTIL_OBJECTS) | $(BIN_DIR)
	@echo "Building Phase 5 ELF format test..."
	$(CC) $(CFLAGS) -g -O0 $(INCLUDES) \
		tests/test_phase5_elf.c \
		$(FORMAT_OBJECTS) \
		$(ARCH_X86_64_OBJECTS) \
		$(ARCH_X86_32_OBJECTS) \
		$(CORE_OBJECTS) \
		$(UTIL_OBJECTS) \
		-o $@
	@echo "Phase 5 ELF format test built: $@"

# Test all variants
test-comprehensive: test-x86_16-comprehensive
	@echo "🎉 All comprehensive tests completed!"

# Declare phony targets
.PHONY: all debug test test-unity test-unicorn test-unicorn-build test-all test-clean test-x86_16-comprehensive test-comprehensive static-x86_16 static-x86_32 static-x86_64 static-arm64 static-riscv static-all clean distclean run install uninstall help
