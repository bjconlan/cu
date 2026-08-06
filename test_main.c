/* cu test runner — runs the tls + http_client suites. */
#include "tests/greatest.h"

extern SUITE(tls_suite);
extern SUITE(http_suite);

GREATEST_MAIN_DEFS();

int main(int argc, char **argv) {
  GREATEST_MAIN_BEGIN();
  RUN_SUITE(tls_suite);
  RUN_SUITE(http_suite);
  GREATEST_MAIN_END();
}
