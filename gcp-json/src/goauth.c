#include "gcp-credentials.h"
#include "gcp-jwt.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <getopt.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <sys/mman.h>
#include <time.h>

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

static GcpJwt *
_create_jwt(GcpCredentials *cred, const char *scope)
{
  GcpJwt *jwt = gcp_jwt_new(gcp_cred_private_key(cred));

  gcp_jwt_set_issuer(jwt, gcp_cred_client_email(cred));
  gcp_jwt_set_scope(jwt, scope);
  gcp_jwt_set_audience(jwt, gcp_cred_token_uri(cred));
  gcp_jwt_set_expiration_time(jwt, 3600);
  gcp_jwt_set_issued_at(jwt, time(NULL));

  return jwt;
}

char *
_request_access_token(const char *jwt, const char *token_uri)
{
  return NULL;
}

int main(int argc, char **argv)
{
  int r = parse_args(argc, argv);
  if (r != argc)
    return r;
  // TODO: check_args (mandatory/optional)
  GcpCredentials *cred = _gcp_credentials_load_from_file(goauth_options.cred_file);

  GcpJwt *jwt = _create_jwt(cred, goauth_options.scope);
  printf("%s\n", gcp_jwt_get_encoded(jwt));
  //TODO: send HTTP POST, read answer, parse token/exp/print answer
  gcp_jwt_free(jwt);
  gcp_cred_free(cred);
 
  return 0;
}
