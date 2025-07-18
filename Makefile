# Project name
PROJECT_NAME = stas

# Compiler and flags
CC = gcc
CFLAGS = -std=c99 -Wall -Wextra -Wpedantic -O2 -fPIC
DEBUG_CFLAGS = -std=c99 -Wall -Wextra -Wpedantic -g -DDEBUG -fPIC
LDFLAGS = -ldl

# Directories
SRC_DIR = src
INCLUDE_DIR = include
OBJ_DIR = obj
BIN_DIR = bin

# Find all .c files in src directory (excluding architecture modules for now)
SOURCES = $(SRC_DIR)/main.c $(SRC_DIR)/lexer.c
OBJECTS = $(SOURCES:$(SRC_DIR)/%.c=$(OBJ_DIR)/%.o)

# Target executable
TARGET = $(BIN_DIR)/$(PROJECT_NAME)

# Include directories
INCLUDES = -I$(INCLUDE_DIR)

# Default target
all: $(TARGET)

# Build the main target
$(TARGET): $(OBJECTS) | $(BIN_DIR)
	$(CC) $(OBJECTS) $(LDFLAGS) -o $@
	@echo "Build complete: $@"

# Compile source files to object files
$(OBJ_DIR)/%.o: $(SRC_DIR)/%.c | $(OBJ_DIR)
	$(CC) $(CFLAGS) $(INCLUDES) -c $< -o $@

# Debug build
debug: CFLAGS = $(DEBUG_CFLAGS)
debug: $(TARGET)

# Create directories if they don't exist
$(OBJ_DIR):
	mkdir -p $(OBJ_DIR)

$(BIN_DIR):
	mkdir -p $(BIN_DIR)

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

# Run Unicorn Engine tests
test-unicorn: $(TARGET)
	@echo "Running Unicorn Engine tests..."
	./tests/run_unicorn_tests.sh

# Build Unicorn test program
test-unicorn-build:
	@echo "Building Unicorn test program..."
	@if pkg-config --exists unicorn 2>/dev/null; then \
		gcc `pkg-config --cflags unicorn` tests/test_unicorn_comprehensive.c `pkg-config --libs unicorn` -o tests/test_unicorn_comprehensive; \
	else \
		gcc tests/test_unicorn_comprehensive.c -lunicorn -o tests/test_unicorn_comprehensive; \
	fi

# Run all tests
test-all: test test-unicorn

# Clean build artifacts
clean:
	rm -rf $(OBJ_DIR)/*.o $(TARGET)
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
	@echo "  test-unicorn - Run Unicorn Engine emulation tests"
	@echo "  test-unicorn-build - Build Unicorn test program"
	@echo "  test-all     - Run all tests"
	@echo "  clean        - Remove object files and executable"
	@echo "  distclean    - Remove all generated files and directories"
	@echo "  run          - Build and show help message"
	@echo "  install      - Install the program to /usr/local/bin"
	@echo "  uninstall    - Remove the program from /usr/local/bin"
	@echo "  help         - Show this help message"

# Declare phony targets
.PHONY: all debug test test-emulation test-all clean distclean run install uninstall help
