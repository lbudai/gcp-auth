/*
 * Copyright (c) 2019 Budai Laszlo
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to deal
 * in the Software without restriction, including without limitation the rights
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 * 
 * The above copyright notice and this permission notice shall be included in all
 * copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
 * SOFTWARE.
 */

#include "asprintf-compat.h"

#if !HAVE_ASPRINTF || TEST_ASPRINTF
#include <stdlib.h>

int
asprintf(char **strp, const char *fmt, ...)
{
  va_list args;
  va_start(args, fmt);
  int r = vasprintf(strp, fmt, args);
  va_end(args);

  return r;
}

int
vasprintf(char **strp, const char *fmt, va_list ap)
{
  va_list orig_ap;
  va_copy(orig_ap, ap);

  char c[1];
  /*
   * on some platforms not allowed to pass a NULL-buf to [v]snprintf...
   */
  int len = vsnprintf(c, 1, fmt, ap);
  if (len < 0)
    return len;
  ++len;

  *strp = malloc(len);
  if (!*strp)
    return -1;

  int r = vsnprintf(*strp, len, fmt, orig_ap);
  va_end(orig_ap);

  return r;
}

#endif
