#include "gcp-credentials.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <getopt.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <sys/mman.h>

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

static GcpCredentials *
_gcp_credentials_load_from_file(const char *path)
{
  int fd = open(path, O_RDONLY);
  if (fd < 0)
    {
      perror(strerror(errno));
      exit(-1);
    }
  struct stat st;
  int r = fstat(fd, &st);
  if (r != 0)
    {
      perror(strerror(errno));
      exit(-1);
    }
  size_t fsize = st.st_size;
  char *content = (char *)mmap(0, fsize, PROT_READ, MAP_PRIVATE, fd, 0);
  GcpCredentials *cred = gcp_cred_new(content);
  munmap(content, fsize);

  return cred;
}

int main(int argc, char **argv)
{
  int r = parse_args(argc, argv);
  if (r != argc)
    return r;
// TODO: check_args (mandatory/optional)

  //jwt_low_level_api:
  //jwt *token = jwt_new("RS256");
  //jwt_set_iss("");
  //jwt_set_scope("");
  //jwt_set_aud("");
  //jwt_set_iat("");
  //jwt_set_lifetime();//iat+lifetime
  //jwt_set_key("key");
  //jwt_free(token);

  // high level api:
/*  GcpCredentials *cred = gcp_load_from_file(goauth_options.cred_file);
  jwt = jwt_gcp_new(cred, goauth_options.scope);
  char *jwt_str = jwt_encode(jwt);*/
  //TODO: send HTTP POST, read answer, parse token/exp/print answer

  GcpCredentials *cred = _gcp_credentials_load_from_file(goauth_options.cred_file);
  printf("project_id:%s\n", gcp_cred_project_id(cred));
  gcp_cred_free(cred);

  return 0;
}
