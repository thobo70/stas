#ifndef UNITY_CONFIG_H
#define UNITY_CONFIG_H

/* Include standard headers */
#include <stdio.h>

/* Configuration for Unity Test Framework */

/* Unity Output Configuration */
#define UNITY_OUTPUT_COLOR

/* Support for different data types */
#define UNITY_INCLUDE_64
#define UNITY_INCLUDE_DOUBLE
#define UNITY_INCLUDE_FLOAT

/* Memory allocation support */
#define UNITY_FIXTURE_NO_EXTRAS

/* Test configuration */
#define UNITY_EXCLUDE_SETJMP_H
#define UNITY_EXCLUDE_MATH_H

/* Line ending configuration */
#ifndef UNITY_LINE_ENDING
  #define UNITY_LINE_ENDING "\n"
#endif

/* Output character function - can be customized */
#ifndef UNITY_OUTPUT_CHAR
  #define UNITY_OUTPUT_CHAR(c) putchar(c)
#endif

/* Start and complete macros */
#ifndef UNITY_OUTPUT_START
  #define UNITY_OUTPUT_START()
#endif

#ifndef UNITY_OUTPUT_COMPLETE
  #define UNITY_OUTPUT_COMPLETE()
#endif

/* Memory alignment */
#ifndef UNITY_SUPPORT_64
  #ifdef UNITY_INCLUDE_64
    #define UNITY_SUPPORT_64
  #endif
#endif

/* Pointer size configuration */
#ifndef UNITY_POINTER_WIDTH
  #if defined(__LP64__) || defined(_WIN64)
    #define UNITY_POINTER_WIDTH 64
  #else
    #define UNITY_POINTER_WIDTH 32
  #endif
#endif

/* Integer size configuration */
#ifndef UNITY_INT_WIDTH
  #define UNITY_INT_WIDTH 32
#endif

#ifndef UNITY_LONG_WIDTH
  #define UNITY_LONG_WIDTH 64
#endif

/* Float precision */
#ifdef UNITY_INCLUDE_FLOAT
  #ifndef UNITY_FLOAT_PRECISION
    #define UNITY_FLOAT_PRECISION 0.00001f
  #endif
#endif

#ifdef UNITY_INCLUDE_DOUBLE
  #ifndef UNITY_DOUBLE_PRECISION
    #define UNITY_DOUBLE_PRECISION 0.0000000001
  #endif
#endif

/* Test running configuration */
#ifndef UNITY_OUTPUT_FLUSH
  #define UNITY_OUTPUT_FLUSH() fflush(stdout)
#endif

#endif /* UNITY_CONFIG_H */
