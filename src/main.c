#include <stdio.h>
#include <stdlib.h>
#include "utils.h"

int main(void) {
    printf("Hello, C99 World!\n");
    
    // Test our utility function
    int result = add_numbers(5, 3);
    printf("5 + 3 = %d\n", result);
    
    return EXIT_SUCCESS;
}
