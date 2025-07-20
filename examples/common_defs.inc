# Common definitions for Phase 7 demo
# Shared constants and macros

#define COMMON_BUFFER_SIZE 1024
#define COMMON_SUCCESS 0
#define COMMON_ERROR -1
#define COMMON_VERSION "1.0"

# Utility macros
#define SET_SUCCESS mov %ax, $COMMON_SUCCESS
#define SET_ERROR mov %ax, $COMMON_ERROR
