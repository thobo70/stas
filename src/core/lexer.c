#define _GNU_SOURCE  // For strdup
#include "lexer.h"
#include "macro.h"
#include <stdlib.h>
#include <string.h>
#include <ctype.h>
#include <stdio.h>

// Create a new lexer
lexer_t *lexer_create(const char *input, const char *filename) {
    if (!input) return NULL;
    
    lexer_t *lexer = malloc(sizeof(lexer_t));
    if (!lexer) return NULL;
    
    lexer->input = input;
    lexer->length = strlen(input);
    lexer->position = 0;
    lexer->line = 1;
    lexer->column = 1;
    lexer->filename = filename ? strdup(filename) : strdup("<stdin>");
    lexer->macros = NULL;
    lexer->error = false;
    lexer->error_message = NULL;
    
    return lexer;
}

// Destroy lexer and free memory
void lexer_destroy(lexer_t *lexer) {
    if (!lexer) return;
    
    if (lexer->filename) free((char*)lexer->filename);
    if (lexer->error_message) free(lexer->error_message);
    free(lexer);
}

// Set macro processor for lexer
void lexer_set_macro_processor(lexer_t *lexer, void *processor) {
    if (lexer) {
        lexer->macros = processor;
    }
}

// Peek at current character without advancing
static char lexer_peek(lexer_t *lexer) {
    if (lexer->position >= lexer->length) return '\0';
    return lexer->input[lexer->position];
}

// Advance to next character
static void lexer_advance(lexer_t *lexer) {
    if (lexer->position < lexer->length) {
        if (lexer->input[lexer->position] == '\n') {
            lexer->line++;
            lexer->column = 1;
        } else {
            lexer->column++;
        }
        lexer->position++;
    }
}

// Skip whitespace (except newlines)
static void lexer_skip_whitespace(lexer_t *lexer) {
    while (lexer->position < lexer->length) {
        char c = lexer_peek(lexer);
        if (c == ' ' || c == '\t' || c == '\r') {
            lexer_advance(lexer);
        } else {
            break;
        }
    }
}

// Read identifier or keyword
static char *lexer_read_identifier(lexer_t *lexer) {
    size_t start = lexer->position;
    
    while (lexer->position < lexer->length) {
        char c = lexer_peek(lexer);
        if (isalnum(c) || c == '_' || c == '.') {
            lexer_advance(lexer);
        } else {
            break;
        }
    }
    
    size_t length = lexer->position - start;
    char *identifier = malloc(length + 1);
    if (identifier) {
        strncpy(identifier, &lexer->input[start], length);
        identifier[length] = '\0';
    }
    
    return identifier;
}

// Read string literal
static char *lexer_read_string(lexer_t *lexer) {
    lexer_advance(lexer); // Skip opening quote
    size_t start = lexer->position;
    
    while (lexer->position < lexer->length) {
        char c = lexer_peek(lexer);
        if (c == '"') {
            break;
        } else if (c == '\\') {
            lexer_advance(lexer); // Skip escape character
            if (lexer->position < lexer->length) {
                lexer_advance(lexer); // Skip escaped character
            }
        } else {
            lexer_advance(lexer);
        }
    }
    
    size_t length = lexer->position - start;
    char *string = malloc(length + 1);
    if (string) {
        if (length > 0) {
            memcpy(string, &lexer->input[start], length);
        }
        string[length] = '\0';
    }
    
    if (lexer_peek(lexer) == '"') {
        lexer_advance(lexer); // Skip closing quote
    }
    
    return string;
}

// Read number (decimal, hexadecimal, or binary)
static char *lexer_read_number(lexer_t *lexer) {
    size_t start = lexer->position;
    
    // Handle hexadecimal numbers
    if (lexer_peek(lexer) == '0' && lexer->position + 1 < lexer->length &&
        (lexer->input[lexer->position + 1] == 'x' || lexer->input[lexer->position + 1] == 'X')) {
        lexer_advance(lexer); // Skip '0'
        lexer_advance(lexer); // Skip 'x'
        
        while (lexer->position < lexer->length && isxdigit(lexer_peek(lexer))) {
            lexer_advance(lexer);
        }
    } else if (lexer_peek(lexer) == '0' && lexer->position + 1 < lexer->length &&
               (lexer->input[lexer->position + 1] == 'b' || lexer->input[lexer->position + 1] == 'B')) {
        // Handle binary numbers
        lexer_advance(lexer); // Skip '0'
        lexer_advance(lexer); // Skip 'b'
        
        while (lexer->position < lexer->length && 
               (lexer_peek(lexer) == '0' || lexer_peek(lexer) == '1')) {
            lexer_advance(lexer);
        }
    } else {
        // Handle decimal numbers
        while (lexer->position < lexer->length && isdigit(lexer_peek(lexer))) {
            lexer_advance(lexer);
        }
    }
    
    size_t length = lexer->position - start;
    char *number = malloc(length + 1);
    if (number) {
        strncpy(number, &lexer->input[start], length);
        number[length] = '\0';
    }
    
    return number;
}

// Skip comment until end of line
static void lexer_skip_comment(lexer_t *lexer) {
    while (lexer->position < lexer->length && lexer_peek(lexer) != '\n') {
        lexer_advance(lexer);
    }
}

// Handle '#' - could be comment or macro directive
static token_t lexer_handle_hash(lexer_t *lexer) {
    token_t token = {0};
    token.line = lexer->line;
    token.column = lexer->column;
    
    lexer_advance(lexer); // Skip '#'
    
    // Check if this is a macro directive
    if (isalpha(lexer_peek(lexer))) {
        char *directive = lexer_read_identifier(lexer);
        if (!directive) {
            token.type = TOKEN_ERROR;
            return token;
        }
        
        // Check for macro directives
        if (strcmp(directive, "define") == 0) {
            token.type = TOKEN_MACRO_DEFINE;
            token.value = directive;
        } else if (strcmp(directive, "ifdef") == 0) {
            token.type = TOKEN_MACRO_IFDEF;
            token.value = directive;
        } else if (strcmp(directive, "ifndef") == 0) {
            token.type = TOKEN_MACRO_IFNDEF;
            token.value = directive;
        } else if (strcmp(directive, "else") == 0) {
            token.type = TOKEN_MACRO_ELSE;
            token.value = directive;
        } else if (strcmp(directive, "endif") == 0) {
            token.type = TOKEN_MACRO_ENDIF;
            token.value = directive;
        } else if (strcmp(directive, "include") == 0) {
            token.type = TOKEN_MACRO_INCLUDE;
            token.value = directive;
        } else if (strcmp(directive, "undef") == 0) {
            token.type = TOKEN_MACRO_UNDEF;
            token.value = directive;
        } else {
            // Not a recognized macro directive, treat as comment
            free(directive);
            lexer_skip_comment(lexer);
            token.type = TOKEN_COMMENT;
        }
    } else {
        // Regular comment
        lexer_skip_comment(lexer);
        token.type = TOKEN_COMMENT;
    }
    
    return token;
}

// Get next token
token_t lexer_next_token(lexer_t *lexer) {
    token_t token = {0};
    
    if (lexer->error) {
        token.type = TOKEN_ERROR;
        return token;
    }
    
    lexer_skip_whitespace(lexer);
    
    if (lexer->position >= lexer->length) {
        token.type = TOKEN_EOF;
        token.line = lexer->line;
        token.column = lexer->column;
        return token;
    }
    
    char c = lexer_peek(lexer);
    token.line = lexer->line;
    token.column = lexer->column;
    
    switch (c) {
        case '\n':
            token.type = TOKEN_NEWLINE;
            token.value = strdup("\n");
            lexer_advance(lexer);
            break;
            
        case '#':
            return lexer_handle_hash(lexer);
            
        case ';':
            // Semicolon comment (common in assembly language)
            lexer_skip_comment(lexer);
            token.type = TOKEN_COMMENT;
            break;
            
        case '%':
            lexer_advance(lexer);
            token.value = lexer_read_identifier(lexer);
            token.type = TOKEN_REGISTER;
            break;
            
        case '$':
            lexer_advance(lexer);
            if (isdigit(lexer_peek(lexer))) {
                token.value = lexer_read_number(lexer);
            } else {
                token.value = lexer_read_identifier(lexer);
                
                // Check for macro expansion in immediate values
                if (token.value && lexer->macros) {
                    macro_processor_t *processor = (macro_processor_t*)lexer->macros;
                    macro_t *macro = macro_processor_lookup(processor, token.value);
                    if (macro && macro->parameter_count == 0) {
                        // Simple macro without parameters - expand inline
                        free(token.value);
                        token.value = strdup(macro->body);
                        if (!token.value) {
                            token.type = TOKEN_ERROR;
                            lexer->error = true;
                            lexer->error_message = strdup("Memory allocation failed for macro expansion");
                            break;
                        }
                    }
                }
            }
            token.type = TOKEN_IMMEDIATE;
            break;
            
        case '"':
            token.value = lexer_read_string(lexer);
            token.type = TOKEN_STRING;
            break;
            
        case ',':
            token.type = TOKEN_COMMA;
            token.value = strdup(",");
            lexer_advance(lexer);
            break;
            
        case '(':
            token.type = TOKEN_LPAREN;
            token.value = strdup("(");
            lexer_advance(lexer);
            break;
            
        case ')':
            token.type = TOKEN_RPAREN;
            token.value = strdup(")");
            lexer_advance(lexer);
            break;
            
        case '+':
        case '-':
        case '*':
        case '/':
        case '&':
        case '|':
        case '^':
        case '~':
        case '!':
        case '<':
        case '>':
        case '=':
            token.type = TOKEN_OPERATOR;
            token.value = malloc(2);
            token.value[0] = c;
            token.value[1] = '\0';
            lexer_advance(lexer);
            break;
            
        default:
            if (isdigit(c)) {
                token.value = lexer_read_number(lexer);
                token.type = TOKEN_NUMBER;
            } else if (isalpha(c) || c == '_' || c == '.') {
                token.value = lexer_read_identifier(lexer);
                
                // Check if it's a directive
                if (token.value && token.value[0] == '.') {
                    token.type = TOKEN_DIRECTIVE;
                } else if (is_instruction_token(token.value)) {
                    token.type = TOKEN_INSTRUCTION;
                } else {
                    token.type = TOKEN_SYMBOL;
                    
                    // Check if it's followed by a colon (label)
                    if (lexer_peek(lexer) == ':') {
                        token.type = TOKEN_LABEL;
                        lexer_advance(lexer); // Skip the colon
                    } else if (lexer->macros) {
                        // Check for macro expansion
                        macro_processor_t *processor = (macro_processor_t*)lexer->macros;
                        macro_t *macro = macro_processor_lookup(processor, token.value);
                        if (macro && macro->parameter_count == 0) {
                            // Simple macro without parameters - expand inline
                            free(token.value);
                            token.value = strdup(macro->body);
                            if (!token.value) {
                                token.type = TOKEN_ERROR;
                                lexer->error = true;
                                lexer->error_message = strdup("Memory allocation failed for macro expansion");
                            }
                        }
                    }
                }
            } else {
                // Unknown character
                token.type = TOKEN_ERROR;
                lexer->error = true;
                lexer->error_message = malloc(64);
                snprintf(lexer->error_message, 64, "Unexpected character '%c'", c);
                lexer_advance(lexer);
            }
            break;
    }
    
    if (token.value) {
        token.length = strlen(token.value);
    }
    
    return token;
}

// Free token memory
void token_free(token_t *token) {
    if (token && token->value) {
        free(token->value);
        token->value = NULL;
    }
}

// Check if lexer has error
bool lexer_has_error(const lexer_t *lexer) {
    return lexer ? lexer->error : true;
}

// Get error message
const char *lexer_get_error(const lexer_t *lexer) {
    return lexer ? lexer->error_message : "Invalid lexer";
}

// Convert token type to string
const char *token_type_to_string(token_type_t type) {
    switch (type) {
        case TOKEN_INSTRUCTION: return "INSTRUCTION";
        case TOKEN_REGISTER:    return "REGISTER";
        case TOKEN_IMMEDIATE:   return "IMMEDIATE";
        case TOKEN_SYMBOL:      return "SYMBOL";
        case TOKEN_LABEL:       return "LABEL";
        case TOKEN_DIRECTIVE:   return "DIRECTIVE";
        case TOKEN_STRING:      return "STRING";
        case TOKEN_NUMBER:      return "NUMBER";
        case TOKEN_OPERATOR:    return "OPERATOR";
        case TOKEN_COMMA:       return "COMMA";
        case TOKEN_LPAREN:      return "LPAREN";
        case TOKEN_RPAREN:      return "RPAREN";
        case TOKEN_NEWLINE:     return "NEWLINE";
        case TOKEN_COMMENT:     return "COMMENT";
        case TOKEN_MACRO_DEFINE:  return "MACRO_DEFINE";
        case TOKEN_MACRO_IFDEF:   return "MACRO_IFDEF";
        case TOKEN_MACRO_IFNDEF:  return "MACRO_IFNDEF";
        case TOKEN_MACRO_ELSE:    return "MACRO_ELSE";
        case TOKEN_MACRO_ENDIF:   return "MACRO_ENDIF";
        case TOKEN_MACRO_INCLUDE: return "MACRO_INCLUDE";
        case TOKEN_MACRO_UNDEF:   return "MACRO_UNDEF";
        case TOKEN_EOF:         return "EOF";
        case TOKEN_ERROR:       return "ERROR";
        default:                return "UNKNOWN";
    }
}

// Check if string is an instruction
bool is_instruction_token(const char *str) {
    if (!str) return false;
    
    // Common x86 instructions (16/32/64-bit)
    const char *instructions[] = {
        // Data movement
        "mov", "movb", "movw", "movl", "movq",
        "push", "pushw", "pushl", "pushq",
        "pop", "popw", "popl", "popq",
        "lea", "leaw", "leal", "leaq",
        "xchg", "xchgb", "xchgw", "xchgl",
        "movzx", "movsx", "movzbl", "movzwl", "movzbw",
        "movsbl", "movswl", "movsbw",
        "bswap", "bswapl", "xadd", "xaddl", "xaddw", "xaddb",
        "cmpxchg", "cmpxchgl", "cmpxchgw", "cmpxchgb",
        "pushad", "popad", "pushfd", "popfd",
        
        // Arithmetic
        "add", "addb", "addw", "addl", "addq",
        "sub", "subb", "subw", "subl", "subq",
        "mul", "mulb", "mulw", "mull", "mulq",
        "div", "divb", "divw", "divl", "divq",
        "inc", "incb", "incw", "incl", "incq",
        "dec", "decb", "decw", "decl", "decq",
        "imul", "imull", "imulw", "imulb", "idiv", "idivl", "idivw", "idivb", "adc", "sbb", "neg", "negb", "negw", "negl",
        "daa", "das", "aaa", "aas", "aam", "aad",
        "bsf", "bsr", "bt", "btc", "btr", "bts",
        "bsfl", "bsfw", "bsrl", "bsrw", "btl", "btw", "btcl", "btcw", 
        "btrl", "btrw", "btsl", "btsw",
        
        // Logical
        "and", "andb", "andw", "andl", "andq",
        "or", "orb", "orw", "orl", "orq",
        "xor", "xorb", "xorw", "xorl", "xorq",
        "not", "notb", "notw", "notl", "notq",
        
        // Comparison
        "cmp", "cmpb", "cmpw", "cmpl", "cmpq",
        "test", "testb", "testw", "testl", "testq",
        
        // Control flow
        "jmp", "je", "jne", "jz", "jnz", "jl", "jle", "jg", "jge",
        "ja", "jae", "jb", "jbe", "jc", "jnc", "jo", "jno",
        "js", "jns", "jp", "jnp", "call", "ret", "retf",
        "jna", "jnae", "jnb", "jnbe", "jng", "jnge", "jnl", "jnle",
        "loop", "loope", "loopne", "jecxz", "retn", "iret", "iretd",
        
        // String operations
        "movs", "movsb", "movsw", "movsl", "movsq", "movsd",
        "stos", "stosb", "stosw", "stosl", "stosq",
        "lods", "lodsb", "lodsw", "lodsl", "lodsq",
        "cmps", "cmpsb", "cmpsw", "cmpsl", "cmpsd",
        "scas", "scasb", "scasw", "scasl", "scasd",
        "rep", "repe", "repne",
        
        // Stack operations (32-bit specific)
        "pushad", "popad", "pushfd", "popfd",
        
        // System
        "int", "iret", "hlt", "nop", "syscall", "sysenter", "sysexit",
        "cli", "sti", "cld", "std", "clc", "stc", "cmc",
        "wait", "cpuid", "rdtsc", "rdmsr", "wrmsr",
        "lahf", "sahf", "pushf", "popf", "into", "bound",
        "enter", "leave", "pusha", "popa",
        
        // Additional x86_32 i386 instructions
        "arpl", "verr", "verw", "clts", "lmsw", "smsw",
        "lgdt", "sgdt", "lidt", "sidt", "lldt", "sldt",
        "ltr", "str", "lar", "lsl", "lock", "esc",
        "in", "out", "ins", "insb", "insw", "insd",
        "outs", "outsb", "outsw", "outsd",
        "cbw", "cwde", "cwd", "cdq", "cmc",
        "lds", "les", "lfs", "lgs", "lss",
        "jcxz", "jpe", "jpo", "jp", "jnp",
        "jna", "jnae", "jnb", "jnbe", "jng", "jnge", "jnl", "jnle",
        "loopz", "loopnz", "repz", "repnz",
        "seta", "setae", "setb", "setbe", "setc", "setge", "setle",
        "setna", "setnae", "setnb", "setnbe", "setnc", "setng", "setnge",
        "setnl", "setnle", "setno", "setnp", "setns", "setnz", "seto",
        "setp", "setpe", "setpo", "sets", "setz",
        "lodsd", "stosd", "scasd",
        "xlat", "xlatb",
        
        // Bit manipulation
        "shl", "shlb", "shlw", "shll", "shlq",
        "shr", "shrb", "shrw", "shrl", "shrq",
        "sar", "sarb", "sarw", "sarl", "sarq",
        "rol", "rolb", "rolw", "roll", "rolq",
        "ror", "rorb", "rorw", "rorl", "rorq",
        "shld", "shldl", "shldw", "shrd", "shrdl", "shrdw",
        "rcl", "rcr", "sal",
        
        // Phase 6.1: SSE/AVX floating-point instructions
        // SSE scalar single-precision
        "movss", "addss", "subss", "mulss", "divss",
        // SSE scalar double-precision  
        "movsd", "addsd", "subsd", "mulsd", "divsd",
        // SSE packed single-precision
        "movaps", "addps", "subps", "mulps", "divps",
        // SSE packed double-precision
        "movapd", "addpd", "subpd", "mulpd", "divpd",
        // SSE integer operations
        "paddd", "psubd", "pmulld",
        
        // AVX instructions (VEX-encoded)
        "vmovaps", "vmovapd", "vaddps", "vaddpd", "vsubps", "vsubpd",
        "vmulps", "vmulpd",
        
        // Advanced control flow
        "cmove", "cmovne", "cmovl", "cmovge", "cmovle", "cmovg",
        "sete", "setne", "setl", "setge", "setle", "setg",
        "setz", "setnz", "setnge", "setnl", "setnle", "setng",
        "seta", "setnbe", "setae", "setnb", "setnc",
        "setb", "setnae", "setc", "setbe", "setna", "seto", "setno",
        "setp", "setpe", "setnp", "setpo", "sets", "setns",
        "loop", "loope", "loopne",
        
        // Phase 6.2: ARM64 (AArch64) instructions
        // Data processing
        "add", "sub", "and", "orr", "eor", "mov", "mvn",
        "adc", "sbc", "bic", "orn", "lsl", "lsr", "asr", "ror",
        "mul", "div", "udiv", "sdiv", "madd", "msub",
        
        // Load/store
        "ldr", "str", "ldrb", "strb", "ldrh", "strh",
        "ldp", "stp", "ldur", "stur",
        
        // Branch and control
        "b", "bl", "br", "blr", "ret", "eret",
        "cbz", "cbnz", "tbz", "tbnz",
        
        // Floating-point and SIMD
        "fadd", "fsub", "fmul", "fdiv", "fabs", "fneg",
        "fmov", "fcmp", "fcvt",
        
        // System
        "svc", "hvc", "smc", "brk", "hlt", "isb", "dsb", "dmb",
        
        // Phase 6.3: RISC-V instructions
        // Arithmetic immediate instructions
        "addi", "slti", "sltiu", "xori", "ori", "andi",
        "slli", "srli", "srai",
        
        // Register arithmetic instructions  
        "add", "sub", "sll", "slt", "sltu", "xor", "srl", "sra", "or", "and",
        
        // Load instructions
        "lb", "lh", "lw", "ld", "lbu", "lhu", "lwu",
        
        // Store instructions
        "sb", "sh", "sw", "sd",
        
        // Branch instructions
        "beq", "bne", "blt", "bge", "bltu", "bgeu",
        
        // Jump instructions
        "jal", "jalr",
        
        // Upper immediate instructions
        "lui", "auipc",
        
        // System instructions
        "ecall", "ebreak",
        
        NULL
    };
    
    for (int i = 0; instructions[i]; i++) {
        if (strcmp(str, instructions[i]) == 0) {
            return true;
        }
    }
    
    return false;
}

// Check if string is a register (basic check)
bool is_register_token(const char *str) {
    return str && str[0] == '%';
}

// Check if string is a directive
bool is_directive_token(const char *str) {
    return str && str[0] == '.';
}
