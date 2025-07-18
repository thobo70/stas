# Project name
PROJECT_NAME = stas

# Compiler and flags
CC = gcc
CFLAGS = -std=c99 -Wall -Wextra -Wpedantic -O2
DEBUG_CFLAGS = -std=c99 -Wall -Wextra -Wpedantic -g -DDEBUG

# Directories
SRC_DIR = src
INCLUDE_DIR = include
OBJ_DIR = obj
BIN_DIR = bin

# Find all .c files in src directory
SOURCES = $(wildcard $(SRC_DIR)/*.c)
OBJECTS = $(SOURCES:$(SRC_DIR)/%.c=$(OBJ_DIR)/%.o)

# Target executable
TARGET = $(BIN_DIR)/$(PROJECT_NAME)

# Include directories
INCLUDES = -I$(INCLUDE_DIR)

# Default target
all: $(TARGET)

# Build the main target
$(TARGET): $(OBJECTS) | $(BIN_DIR)
	$(CC) $(OBJECTS) -o $@
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

# Clean build artifacts
clean:
	rm -rf $(OBJ_DIR)/*.o $(TARGET)
	@echo "Cleaned build artifacts"

# Clean everything including directories
distclean: clean
	rm -rf $(OBJ_DIR) $(BIN_DIR)
	@echo "Cleaned all generated files and directories"

# Run the program
run: $(TARGET)
	./$(TARGET)

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
	@echo "  all       - Build the project (default)"
	@echo "  debug     - Build with debug symbols"
	@echo "  clean     - Remove object files and executable"
	@echo "  distclean - Remove all generated files and directories"
	@echo "  run       - Build and run the program"
	@echo "  install   - Install the program to /usr/local/bin"
	@echo "  uninstall - Remove the program from /usr/local/bin"
	@echo "  help      - Show this help message"

# Declare phony targets
.PHONY: all debug clean distclean run install uninstall help
