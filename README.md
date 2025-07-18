# Stas - C99 Project

A simple C99 project template with proper build system using Make.

## Project Structure

```
stas/
├── src/           # Source files (.c)
├── include/       # Header files (.h)
├── obj/           # Object files (generated)
├── bin/           # Executable files (generated)
├── Makefile       # Build configuration
└── README.md      # This file
```

## Requirements

- GCC compiler with C99 support
- Make utility

## Building

### Build the project:
```bash
make
```

### Build with debug symbols:
```bash
make debug
```

### Build and run:
```bash
make run
```

## Available Make Targets

- `make` or `make all` - Build the project
- `make debug` - Build with debug symbols and flags
- `make clean` - Remove object files and executable
- `make distclean` - Remove all generated files and directories
- `make run` - Build and run the program
- `make install` - Install the program to /usr/local/bin (requires sudo)
- `make uninstall` - Remove the program from /usr/local/bin (requires sudo)
- `make help` - Show available targets

## Compiler Flags

The project uses the following C99-compliant compiler flags:

- `-std=c99` - Use C99 standard
- `-Wall` - Enable all common warnings
- `-Wextra` - Enable extra warnings
- `-Wpedantic` - Enable pedantic warnings for strict standard compliance
- `-O2` - Optimization level 2 (release builds)
- `-g` - Include debug symbols (debug builds)
- `-DDEBUG` - Define DEBUG macro (debug builds)

## Adding New Files

1. Add source files (.c) to the `src/` directory
2. Add header files (.h) to the `include/` directory
3. The Makefile will automatically detect and compile new source files

## License

This project is provided as a template. Add your own license as needed.
