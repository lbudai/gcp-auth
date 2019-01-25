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

#include "gcp-access-token.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <getopt.h>

void print_usage(FILE *fp, const char *name)
{
  fprintf(fp, "%s -c credentials json file -s scope [-r] [-h]\n"
      "\t-r : request access token\n"
      "\t-h : help\n", name);
}

static struct
{
  const char *cred_file;
  const char *scope;
  int request_access_token:1;
} goauth_options;

static int
parse_args(int argc, char **argv)
{
  int opt;
  while ((opt = getopt(argc, argv, "c:s:rh")) != -1)
    {
      switch (opt)
      {
        case 'c': goauth_options.cred_file = optarg ; break;
        case 's': goauth_options.scope = optarg; break;
        case 'r': goauth_options.request_access_token = 1; break;
        case 'h': print_usage(stderr, argv[0]); break;
        case '?': print_usage(stderr, argv[0]); return 0;
        default: print_usage(stderr, argv[0]); return 0;
      }
    }
  return optind;
}

int main(int argc, char **argv)
{
  int r = parse_args(argc, argv);
  if (r != argc)
    return r;
  // TODO: check_args (mandatory/optional)

  GcpAccessToken *token = gcp_access_token_new(goauth_options.cred_file, goauth_options.scope);
  gcp_access_token_request(token);
  printf("%s\nexpiration:%d\n", gcp_access_token_to_string(token), gcp_access_token_get_lifetime(token));
  gcp_access_token_free(token);

  return 0;
}
