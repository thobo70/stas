/* =========================================================================
    Unity Configuration for STAS Testing Framework
    This file configures Unity testing framework for optimal STAS testing
========================================================================= */

#ifndef UNITY_CONFIG_H
#define UNITY_CONFIG_H

/* Basic Unity Configuration */
#define UNITY_FIXTURE_NO_EXTRAS

/* Output Configuration */
#define UNITY_OUTPUT_COMPLETE_FAILURE_DETAIL
#define UNITY_OUTPUT_COLOR

/* Memory and Float Support */
#define UNITY_SUPPORT_64
#define UNITY_INCLUDE_DOUBLE
#define UNITY_DOUBLE_PRECISION      1e-12

/* Pointer Support */
#define UNITY_POINTER_WIDTH         64

/* String Comparison */
#define UNITY_MAX_DETAILS           8

/* Custom Assertions for Assembly Testing */
#define UNITY_SHORTHAND_AS_OLD  /* For backward compatibility */

/* Test Result Counting */
#define UNITY_COUNTER_TYPE          unsigned int

/* Memory allocation for dynamic tests */
#define UNITY_OUTPUT_CHAR(a)        putchar(a)
#define UNITY_OUTPUT_FLUSH()        fflush(stdout)
#define UNITY_OUTPUT_START()        /* no-op */
#define UNITY_OUTPUT_COMPLETE()     /* no-op */

/* Platform specific settings for Linux */
#define UNITY_WEAK_ATTRIBUTE        __attribute__((weak))
#define UNITY_WEAK_PRAGMA
#define UNITY_NO_WEAK

/* Include standard headers needed for STAS testing */
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#endif /* UNITY_CONFIG_H */
