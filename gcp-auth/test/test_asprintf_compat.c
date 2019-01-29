#include "asprintf-compat.h"
#include <string.h>
#include <criterion/criterion.h>

Test(asprintf, print)
{
  char *str = NULL;
  int r = asprintf(&str, "%s.%d", "abcdef", 1213);
  cr_assert_eq(r, 11);
  cr_assert_eq(strlen(str), 11);
  cr_expect_str_eq(str, "abcdef.1213");
  free(str);
}


