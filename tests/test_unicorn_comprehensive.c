/*
 * STAS Unicorn Engine Unity Test
 */

#include "unity.h"
#include <unicorn/unicorn.h>

void setUp(void) {
}

void tearDown(void) {
}

void test_unicorn_basic(void) {
    uc_engine *uc;
    uc_err err = uc_open(UC_ARCH_X86, UC_MODE_64, &uc);
    TEST_ASSERT_EQUAL(UC_ERR_OK, err);
    if (err == UC_ERR_OK) {
        uc_close(uc);
    }
}

int main(void) {
    UNITY_BEGIN();
    RUN_TEST(test_unicorn_basic);
    return UNITY_END();
}
