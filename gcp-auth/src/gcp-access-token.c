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
#include "gcp-credentials.h"
#include "gcp-jwt.h"
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <assert.h>
#include <time.h>
#include <curl/curl.h>
#include <json.h>

typedef struct _AccessToken AccessToken;

struct _GcpAccessToken
{
  GcpCredentials *cred;
  char *scope;
  AccessToken *token;
};

struct _AccessToken
{
  char *token;
  unsigned int exp;
};

AccessToken *
access_token_new(char *token, unsigned int exp)
{
  AccessToken *self = calloc(1, sizeof(AccessToken));
  self->token = token; //dup?
  self->exp = exp;

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

GcpAccessToken *
gcp_access_token_new(const char *credentials_json_path, const char *scope)
{
  GcpCredentials *cred = gcp_cred_new_from_file(credentials_json_path);
  if (!cred)
    return NULL;

  GcpAccessToken *self = calloc(1, sizeof(GcpAccessToken));
  self->cred = cred;
  self->scope = strdup(scope);

  return self;
}

void
gcp_access_token_free(GcpAccessToken *self)
{
  if (!self)
    return;

  gcp_cred_free(self->cred);
  free(self->scope);
  access_token_free(self->token);
  free(self);
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

  static const char *body_temp = "grant_type=urn%3Aietf%3Aparams%3Aoauth%3Agrant-type%3Ajwt-bearer&assertion=";
  char *body = malloc(strlen(body_temp) + strlen(jwt) + 1);
  sprintf(body, "%s%s", body_temp, jwt);

  if (!curl) //TODO: error handling
    goto err;

  curl_easy_setopt(curl, CURLOPT_URL, token_uri);
  curl_easy_setopt(curl, CURLOPT_POSTFIELDS, body);

  CURLcode ret = curl_easy_perform(curl);

  if (ret != CURLE_OK)
    {
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
  if (!val)
    {
      errno = EINVAL;
      return 0;
    }

  return json_object_get_int(val);
}

static AccessToken *
_parse_auth_response(const char *response, size_t len)
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

int 
gcp_access_token_request(GcpAccessToken *self)
{
  access_token_free(self->token);

  GcpJwt *jwt = _create_jwt(self->cred, self->scope);
  if (!jwt)
    return 0;

  char *auth_response = _request_access_token(gcp_cred_token_uri(self->cred), gcp_jwt_get_encoded(jwt));
  gcp_jwt_free(jwt);

  if (!auth_response)
    return 0;

  self->token = _parse_auth_response(auth_response, strlen(auth_response));
  free(auth_response);

  return (self->token != NULL && self->token->token != NULL);
}

const char *
gcp_access_token_to_string(GcpAccessToken *self)
{
  if (!self->token)
    return NULL;

  return self->token->token;
}

unsigned
gcp_access_token_get_lifetime(GcpAccessToken *self)
{
  if (!self->token)
    return 0;

  return self->token->exp;
}

