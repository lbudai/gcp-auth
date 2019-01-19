#include "gcp-credentials.h"
#include "gcp-jwt.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <assert.h>
#include <getopt.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <sys/mman.h>
#include <time.h>
#include <curl/curl.h>

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

typedef struct _http_resp
{
  size_t size;
  char* data;
} http_resp;

static size_t 
_write_data(void *ptr, size_t size, size_t nmemb, http_resp *data)
{
  size_t index = data->size;
  size_t n = (size * nmemb);
  char* tmp;

  data->size += (size * nmemb);

  tmp = realloc(data->data, data->size + 1);
  assert(tmp);
  data->data = tmp;

  memcpy((data->data + index), ptr, n);
  data->data[data->size] = '\0';

  return size * nmemb;
}

char *
_request_access_token(const char *token_uri, const char *jwt)
{
  http_resp response =
  {
    .size = 0,
    .data = calloc(sizeof(char), 4096)
  };

  CURL *curl = curl_easy_init();
  curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, _write_data);
  curl_easy_setopt(curl, CURLOPT_WRITEDATA, &response);

  char *body_temp = "grant_type=urn%3Aietf%3Aparams%3Aoauth%3Agrant-type%3Ajwt-bearer&assertion=";
  char *body = malloc(strlen(body_temp) + strlen(jwt) + 1);
  sprintf(body, "%s%s", body_temp, jwt);
  printf("%s\n", body);

  if (!curl) //TODO: error handling
    goto err;

  printf("token_uri:[%s]\n", token_uri);
  curl_easy_setopt(curl, CURLOPT_URL, token_uri);
  curl_easy_setopt(curl, CURLOPT_POSTFIELDS, body);

  CURLcode ret = curl_easy_perform(curl);

  if (ret != CURLE_OK)
    {
      fprintf(stderr, "%s\n", curl_easy_strerror(ret));
      goto err;
    }

err:
  if (response.size == 0)
  {
    free(response.data);
    response.data = NULL;
  }
exit:
  if (body)
    free(body);
  curl_easy_cleanup(curl);
  return response.data;
}

char *
_get_access_token(char **token, time_t *exp)
{
  GcpCredentials *cred = _gcp_credentials_load_from_file(goauth_options.cred_file);
  GcpJwt *jwt = _create_jwt(cred, goauth_options.scope);
  char *access_token = _request_access_token(gcp_cred_token_uri(cred), gcp_jwt_get_encoded(jwt));
  *token = access_token;

  gcp_jwt_free(jwt);
  gcp_cred_free(cred);

  return access_token;
}

int main(int argc, char **argv)
{
  int r = parse_args(argc, argv);
  if (r != argc)
    return r;
  // TODO: check_args (mandatory/optional)
  time_t exp;
  char *access_token = NULL;
  _get_access_token(&access_token, &exp);
  printf("%s\n", access_token);
  free(access_token);

  return 0;
}
