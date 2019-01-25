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
#include <json.h>

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

typedef struct _AccessToken AccessToken;

struct _AccessToken
{
  char *token;
  unsigned int expiration;
};

AccessToken *
access_token_new(char *token, unsigned int exp)
{
  AccessToken *self = calloc(1, sizeof(AccessToken));
  self->token = token; //dup?
  self->expiration = exp;

  return self;
}

void
access_token_free(AccessToken *self)
{
  if (!self)
    return;

  if (self->token)
    free(self->token);

  free(self);
}

//TODO: renaming, refactors, new class for getting access token + parse (and add verify method)
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
  if (body)
    free(body);
  curl_easy_cleanup(curl);
  return response.data;
}

//TODO: json-wrapper/helper!
static const char *
_json_get_string(const struct json_object *json, const char *key)
{
  struct json_object *val = NULL;

  json_object_object_get_ex(json, key, &val);
  if (!val)
    return NULL;

  enum json_type type = json_object_get_type(val);
  if (type != json_type_string)
    return NULL;

  return json_object_get_string(val);
}

static int32_t
_json_get_int32(const struct json_object *json, const char *key)
{
  struct json_object *val = NULL;

  json_object_object_get_ex(json, key, &val);
  if (!val) //TODO...
    {
      errno = EINVAL;
      return 0;
    }

  return json_object_get_int(val);
}

static AccessToken *
_parse_gauth_response(const char *response, size_t len)
{
  AccessToken *token = NULL;

  struct json_tokener *tokener = json_tokener_new();
  struct json_object *jso = json_tokener_parse_ex(tokener, response, len);
  if (tokener->err != json_tokener_success || !jso)
    goto exit_;

  const char *token_str = _json_get_string(jso, "access_token");
  if (!token_str)
    goto exit_;

  int exp = _json_get_int32(jso, "expires_in");
  if (errno == EINVAL && exp == 0)
    goto exit_;

  token = access_token_new(strdup(token_str), exp);

exit_:
  json_tokener_free(tokener);
  json_object_put(jso);
  return token;
}

static AccessToken *
_get_access_token()
{
  GcpCredentials *cred = _gcp_credentials_load_from_file(goauth_options.cred_file);
  GcpJwt *jwt = _create_jwt(cred, goauth_options.scope);
  char *access_token_response = _request_access_token(gcp_cred_token_uri(cred), gcp_jwt_get_encoded(jwt));

  AccessToken *access_token = _parse_gauth_response(access_token_response, strlen(access_token_response));

  free(access_token_response);
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
  AccessToken *token = _get_access_token();
  printf("%s\nexpiration:%d\n", token->token, token->expiration);
  access_token_free(token);

  return 0;
}
