#include <stdio.h>
#include "include/lexer.h"

int main() {
    const char *input = "$42 $0x1000 $-5";
    lexer_t *lexer = lexer_create(input, "test");
    
    printf("Testing immediate values: %s\n", input);
    
    for (int i = 0; i < 3; i++) {
        token_t token = lexer_next_token(lexer);
        printf("Token %d: type=%d, value='%s'\n", i+1, token.type, token.value);
        token_free(&token);
    }
    
    lexer_destroy(lexer);
    return 0;
}
