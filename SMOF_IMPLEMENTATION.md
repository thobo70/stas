# SMOF Format Implementation

## Overview

SMOF (STIX Minimal Object Format) has been successfully implemented as an output format for the STAS assembler. This is a minimal object file format designed for memory-constrained Unix systems with less than 100KB of RAM.

## Implementation Details

### Files Added:
- `include/formats/smof.h` - Header file with all SMOF format structures and constants
- `src/formats/smof.c` - Complete implementation of SMOF format writer

### Format Integration:
- Added `FORMAT_SMOF` to the output format enumeration
- Integrated with the output format manager
- Added command-line support with `-f smof` option
- Updated help text and documentation

### Key Features:
- 32-byte fixed header with magic number "SMOF"
- Supports sections, symbols, relocations, and imports
- String table for efficient name storage
- Validation functions for header and section integrity
- Memory-efficient design for embedded systems

## Usage

To generate a SMOF format file:

```bash
./bin/stas -a x86_64 -f smof -o output.smof input.s
```

## Format Specification

The implementation follows the SMOF specification from:
https://github.com/thobo70/stld/blob/568419bdb44e14760335c018abae457fd835e7d3/stix_minimal_object_format.md

### Header Structure (32 bytes):
- Magic: 4 bytes ("SMOF")
- Version: 2 bytes
- Flags: 2 bytes
- Entry point: 4 bytes
- Section count: 2 bytes
- Symbol count: 2 bytes
- Relocation count: 2 bytes
- Import count: 2 bytes
- Section table offset: 4 bytes
- String table offset: 4 bytes
- String table size: 4 bytes
- Relocation table offset: 4 bytes

### Section Structure (12 bytes each):
- Name offset: 4 bytes
- Virtual address: 4 bytes
- Size: 2 bytes
- File offset: 2 bytes

### Symbol Structure (16 bytes each):
- Name offset: 4 bytes
- Value: 4 bytes
- Size: 4 bytes
- Section index: 2 bytes
- Type: 1 byte
- Binding: 1 byte

## Testing

The implementation has been tested with:
- Build system integration
- Command-line interface
- File generation and validation
- Magic number verification

The SMOF format is now fully functional and available as an output option in STAS.
