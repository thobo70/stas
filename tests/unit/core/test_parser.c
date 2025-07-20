#include "unity.h"
#include "../framework/unity_extensions.h"
#include "../../include/parser.h"
#include "../../include/lexer.h"
#include "../../include/symbols.h"
#include "../../include/arch_interface.h"
#include <string.h>
#include <stdlib.h>

static parser_t* parser;
static symbol_table_t* symbols;
static arch_ops_t* arch;

void setUp(void) {
    symbols = symbol_table_create(32);  // Create with initial size
    arch = NULL;  // We'll set this per test as needed
    parser = NULL;
}

void tearDown(void) {
    if (parser) {
        parser_destroy(parser);
    }
    if (symbols) {
        symbol_table_destroy(symbols);
    }
}

// Test parser initialization
void test_parser_init_success(void) {
    Lexer* lexer = lexer_create("mov eax, ebx");
    parser = parser_create(lexer, symbols);
    
    TEST_ASSERT_NOT_NULL(parser);
    TEST_ASSERT_NOT_NULL(parser->lexer);
    TEST_ASSERT_NOT_NULL(parser->symbol_table);
    
    lexer_destroy(lexer);
}

void test_parser_init_null_lexer(void) {
    parser = parser_create(NULL, symbols);
    TEST_ASSERT_NULL(parser);
}

void test_parser_init_null_symbols(void) {
    Lexer* lexer = lexer_create("mov eax, ebx");
    parser = parser_create(lexer, NULL);
    TEST_ASSERT_NULL(parser);
    lexer_destroy(lexer);
}

// Test basic instruction parsing
void test_parser_simple_mov_instruction(void) {
    Lexer* lexer = lexer_create("mov eax, ebx");
    parser = parser_create(lexer, symbols);
    
    Instruction* inst = parser_parse_instruction(parser);
    
    TEST_ASSERT_NOT_NULL(inst);
    TEST_ASSERT_EQUAL_STRING("mov", inst->mnemonic);
    TEST_ASSERT_EQUAL(2, inst->operand_count);
    
    TEST_ASSERT_EQUAL(OPERAND_REGISTER, inst->operands[0].type);
    TEST_ASSERT_EQUAL_STRING("eax", inst->operands[0].value.reg.name);
    
    TEST_ASSERT_EQUAL(OPERAND_REGISTER, inst->operands[1].type);
    TEST_ASSERT_EQUAL_STRING("ebx", inst->operands[1].value.reg.name);
    
    instruction_destroy(inst);
    lexer_destroy(lexer);
}

void test_parser_mov_immediate(void) {
    Lexer* lexer = lexer_create("mov eax, 0x1234");
    parser = parser_create(lexer, symbols);
    
    Instruction* inst = parser_parse_instruction(parser);
    
    TEST_ASSERT_NOT_NULL(inst);
    TEST_ASSERT_EQUAL_STRING("mov", inst->mnemonic);
    TEST_ASSERT_EQUAL(2, inst->operand_count);
    
    TEST_ASSERT_EQUAL(OPERAND_REGISTER, inst->operands[0].type);
    TEST_ASSERT_EQUAL_STRING("eax", inst->operands[0].value.reg.name);
    
    TEST_ASSERT_EQUAL(OPERAND_IMMEDIATE, inst->operands[1].type);
    TEST_ASSERT_EQUAL(0x1234, inst->operands[1].value.immediate);
    
    instruction_destroy(inst);
    lexer_destroy(lexer);
}

void test_parser_memory_operand_simple(void) {
    Lexer* lexer = lexer_create("mov eax, [ebx]");
    parser = parser_create(lexer, symbols);
    
    Instruction* inst = parser_parse_instruction(parser);
    
    TEST_ASSERT_NOT_NULL(inst);
    TEST_ASSERT_EQUAL(2, inst->operand_count);
    
    TEST_ASSERT_EQUAL(OPERAND_REGISTER, inst->operands[0].type);
    TEST_ASSERT_EQUAL(OPERAND_MEMORY, inst->operands[1].type);
    TEST_ASSERT_EQUAL_STRING("ebx", inst->operands[1].value.memory.base);
    TEST_ASSERT_NULL(inst->operands[1].value.memory.index);
    TEST_ASSERT_EQUAL(0, inst->operands[1].value.memory.displacement);
    
    instruction_destroy(inst);
    lexer_destroy(lexer);
}

void test_parser_memory_operand_displacement(void) {
    Lexer* lexer = lexer_create("mov eax, [ebx+8]");
    parser = parser_create(lexer, symbols);
    
    Instruction* inst = parser_parse_instruction(parser);
    
    TEST_ASSERT_NOT_NULL(inst);
    TEST_ASSERT_EQUAL(OPERAND_MEMORY, inst->operands[1].type);
    TEST_ASSERT_EQUAL_STRING("ebx", inst->operands[1].value.memory.base);
    TEST_ASSERT_EQUAL(8, inst->operands[1].value.memory.displacement);
    
    instruction_destroy(inst);
    lexer_destroy(lexer);
}

void test_parser_memory_operand_complex(void) {
    Lexer* lexer = lexer_create("mov eax, [ebx+ecx*2+16]");
    parser = parser_create(lexer, symbols);
    
    Instruction* inst = parser_parse_instruction(parser);
    
    TEST_ASSERT_NOT_NULL(inst);
    TEST_ASSERT_EQUAL(OPERAND_MEMORY, inst->operands[1].type);
    TEST_ASSERT_EQUAL_STRING("ebx", inst->operands[1].value.memory.base);
    TEST_ASSERT_EQUAL_STRING("ecx", inst->operands[1].value.memory.index);
    TEST_ASSERT_EQUAL(2, inst->operands[1].value.memory.scale);
    TEST_ASSERT_EQUAL(16, inst->operands[1].value.memory.displacement);
    
    instruction_destroy(inst);
    lexer_destroy(lexer);
}

// Test label parsing
void test_parser_label_definition(void) {
    Lexer* lexer = lexer_create("start:");
    parser = parser_create(lexer, symbols);
    
    ParseResult result = parser_parse_line(parser);
    
    TEST_ASSERT_EQUAL(PARSE_RESULT_LABEL, result.type);
    TEST_ASSERT_EQUAL_STRING("start", result.data.label.name);
    
    // Check that symbol was added to symbol table
    TEST_ASSERT_SYMBOL_EXISTS(symbols, "start");
    
    lexer_destroy(lexer);
}

void test_parser_label_reference(void) {
    // First define the label
    symbol_table_define(symbols, "loop_start", 0x1000);
    
    Lexer* lexer = lexer_create("jmp loop_start");
    parser = parser_create(lexer, symbols);
    
    Instruction* inst = parser_parse_instruction(parser);
    
    TEST_ASSERT_NOT_NULL(inst);
    TEST_ASSERT_EQUAL_STRING("jmp", inst->mnemonic);
    TEST_ASSERT_EQUAL(1, inst->operand_count);
    TEST_ASSERT_EQUAL(OPERAND_LABEL, inst->operands[0].type);
    TEST_ASSERT_EQUAL_STRING("loop_start", inst->operands[0].value.label);
    
    instruction_destroy(inst);
    lexer_destroy(lexer);
}

// Test expression parsing
void test_parser_expression_simple(void) {
    Lexer* lexer = lexer_create("mov eax, 10+5");
    parser = parser_create(lexer, symbols);
    
    Instruction* inst = parser_parse_instruction(parser);
    
    TEST_ASSERT_NOT_NULL(inst);
    TEST_ASSERT_EQUAL(OPERAND_IMMEDIATE, inst->operands[1].type);
    TEST_ASSERT_EQUAL(15, inst->operands[1].value.immediate);
    
    instruction_destroy(inst);
    lexer_destroy(lexer);
}

void test_parser_expression_with_symbols(void) {
    symbol_table_define(symbols, "VALUE", 100);
    
    Lexer* lexer = lexer_create("mov eax, VALUE*2");
    parser = parser_create(lexer, symbols);
    
    Instruction* inst = parser_parse_instruction(parser);
    
    TEST_ASSERT_NOT_NULL(inst);
    TEST_ASSERT_EQUAL(OPERAND_IMMEDIATE, inst->operands[1].type);
    TEST_ASSERT_EQUAL(200, inst->operands[1].value.immediate);
    
    instruction_destroy(inst);
    lexer_destroy(lexer);
}

// Test directive parsing
void test_parser_db_directive(void) {
    Lexer* lexer = lexer_create("db 0x41, 0x42, 0x43");
    parser = parser_create(lexer, symbols);
    
    ParseResult result = parser_parse_line(parser);
    
    TEST_ASSERT_EQUAL(PARSE_RESULT_DIRECTIVE, result.type);
    TEST_ASSERT_EQUAL_STRING("db", result.data.directive.name);
    TEST_ASSERT_EQUAL(3, result.data.directive.arg_count);
    TEST_ASSERT_EQUAL(0x41, result.data.directive.args[0].immediate);
    TEST_ASSERT_EQUAL(0x42, result.data.directive.args[1].immediate);
    TEST_ASSERT_EQUAL(0x43, result.data.directive.args[2].immediate);
    
    lexer_destroy(lexer);
}

void test_parser_dw_directive(void) {
    Lexer* lexer = lexer_create("dw 0x1234, 0x5678");
    parser = parser_create(lexer, symbols);
    
    ParseResult result = parser_parse_line(parser);
    
    TEST_ASSERT_EQUAL(PARSE_RESULT_DIRECTIVE, result.type);
    TEST_ASSERT_EQUAL_STRING("dw", result.data.directive.name);
    TEST_ASSERT_EQUAL(2, result.data.directive.arg_count);
    TEST_ASSERT_EQUAL(0x1234, result.data.directive.args[0].immediate);
    TEST_ASSERT_EQUAL(0x5678, result.data.directive.args[1].immediate);
    
    lexer_destroy(lexer);
}

// Test section directives
void test_parser_section_directive(void) {
    Lexer* lexer = lexer_create(".text");
    parser = parser_create(lexer, symbols);
    
    ParseResult result = parser_parse_line(parser);
    
    TEST_ASSERT_EQUAL(PARSE_RESULT_DIRECTIVE, result.type);
    TEST_ASSERT_EQUAL_STRING(".text", result.data.directive.name);
    
    lexer_destroy(lexer);
}

// Test error handling
void test_parser_invalid_instruction(void) {
    Lexer* lexer = lexer_create("invalid_instruction eax, ebx");
    parser = parser_create(lexer, symbols);
    
    Instruction* inst = parser_parse_instruction(parser);
    
    TEST_ASSERT_NULL(inst);
    TEST_ASSERT_TRUE(parser_has_error(parser));
    TEST_ASSERT_ERROR_CONTAINS(parser_get_error(parser), "invalid_instruction");
    
    lexer_destroy(lexer);
}

void test_parser_invalid_operand(void) {
    Lexer* lexer = lexer_create("mov eax, @invalid");
    parser = parser_create(lexer, symbols);
    
    Instruction* inst = parser_parse_instruction(parser);
    
    TEST_ASSERT_NULL(inst);
    TEST_ASSERT_TRUE(parser_has_error(parser));
    
    lexer_destroy(lexer);
}

void test_parser_missing_operand(void) {
    Lexer* lexer = lexer_create("mov eax,");
    parser = parser_create(lexer, symbols);
    
    Instruction* inst = parser_parse_instruction(parser);
    
    TEST_ASSERT_NULL(inst);
    TEST_ASSERT_TRUE(parser_has_error(parser));
    
    lexer_destroy(lexer);
}

void test_parser_undefined_symbol(void) {
    Lexer* lexer = lexer_create("mov eax, undefined_symbol");
    parser = parser_create(lexer, symbols);
    
    Instruction* inst = parser_parse_instruction(parser);
    
    // Should create a forward reference
    TEST_ASSERT_NOT_NULL(inst);
    TEST_ASSERT_EQUAL(OPERAND_LABEL, inst->operands[1].type);
    TEST_ASSERT_EQUAL_STRING("undefined_symbol", inst->operands[1].value.label);
    
    instruction_destroy(inst);
    lexer_destroy(lexer);
}

// Test multi-line parsing
void test_parser_multiple_instructions(void) {
    Lexer* lexer = lexer_create("mov eax, ebx\nadd eax, 5\nret");
    parser = parser_create(lexer, symbols);
    
    // Parse first instruction
    Instruction* inst1 = parser_parse_instruction(parser);
    TEST_ASSERT_NOT_NULL(inst1);
    TEST_ASSERT_EQUAL_STRING("mov", inst1->mnemonic);
    
    // Parse second instruction
    Instruction* inst2 = parser_parse_instruction(parser);
    TEST_ASSERT_NOT_NULL(inst2);
    TEST_ASSERT_EQUAL_STRING("add", inst2->mnemonic);
    
    // Parse third instruction
    Instruction* inst3 = parser_parse_instruction(parser);
    TEST_ASSERT_NOT_NULL(inst3);
    TEST_ASSERT_EQUAL_STRING("ret", inst3->mnemonic);
    TEST_ASSERT_EQUAL(0, inst3->operand_count);
    
    instruction_destroy(inst1);
    instruction_destroy(inst2);
    instruction_destroy(inst3);
    lexer_destroy(lexer);
}

// Test different instruction formats
void test_parser_different_operand_counts(void) {
    const char* instructions[] = {
        "nop",           // 0 operands
        "inc eax",       // 1 operand
        "mov eax, ebx",  // 2 operands
        "imul eax, ebx, 5" // 3 operands
    };
    
    int expected_counts[] = {0, 1, 2, 3};
    int num_tests = sizeof(instructions) / sizeof(instructions[0]);
    
    for (int i = 0; i < num_tests; i++) {
        Lexer* lexer = lexer_create(instructions[i]);
        Parser* test_parser = parser_create(lexer, symbols);
        
        Instruction* inst = parser_parse_instruction(test_parser);
        TEST_ASSERT_NOT_NULL(inst);
        TEST_ASSERT_EQUAL(expected_counts[i], inst->operand_count);
        
        instruction_destroy(inst);
        parser_destroy(test_parser);
        lexer_destroy(lexer);
    }
}

int main(void) {
    UNITY_BEGIN();
    
    // Initialization tests
    RUN_TEST(test_parser_init_success);
    RUN_TEST(test_parser_init_null_lexer);
    RUN_TEST(test_parser_init_null_symbols);
    
    // Basic instruction parsing
    RUN_TEST(test_parser_simple_mov_instruction);
    RUN_TEST(test_parser_mov_immediate);
    
    // Memory operand parsing
    RUN_TEST(test_parser_memory_operand_simple);
    RUN_TEST(test_parser_memory_operand_displacement);
    RUN_TEST(test_parser_memory_operand_complex);
    
    // Label and symbol handling
    RUN_TEST(test_parser_label_definition);
    RUN_TEST(test_parser_label_reference);
    
    // Expression parsing
    RUN_TEST(test_parser_expression_simple);
    RUN_TEST(test_parser_expression_with_symbols);
    
    // Directive parsing
    RUN_TEST(test_parser_db_directive);
    RUN_TEST(test_parser_dw_directive);
    RUN_TEST(test_parser_section_directive);
    
    // Error handling
    RUN_TEST(test_parser_invalid_instruction);
    RUN_TEST(test_parser_invalid_operand);
    RUN_TEST(test_parser_missing_operand);
    RUN_TEST(test_parser_undefined_symbol);
    
    // Complex parsing
    RUN_TEST(test_parser_multiple_instructions);
    RUN_TEST(test_parser_different_operand_counts);
    
    return UNITY_END();
}
