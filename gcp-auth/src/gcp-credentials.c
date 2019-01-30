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
#include <json.h>
#include <string.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <errno.h>
#include <sys/mman.h>
#include <stdio.h>

struct _GcpCredentials
{
  struct json_object *json_obj;
};

GcpCredentials *gcp_cred_new(const char *credentials_json)
{
  GcpCredentials *self = NULL;

  struct json_tokener *tokener = json_tokener_new();
    {
      struct json_object *jso = json_tokener_parse_ex(tokener, credentials_json, strlen(credentials_json));

      if (tokener->err != json_tokener_success || !jso)
        goto exit_;

      self = (GcpCredentials *)calloc(1, sizeof(GcpCredentials));
      self->json_obj = jso;
    }
exit_:
  json_tokener_free(tokener);

  return self;
}

GcpCredentials* 
gcp_cred_new_from_file(const char *credentials_file_path)
{
  int fd = open(credentials_file_path, O_RDONLY);
  if (fd < 0)
    {
      fprintf(stderr, "open(%s):%s\n", credentials_file_path, strerror(errno));
      return NULL;
    }

  struct stat st;
  int r = fstat(fd, &st);
  if (r != 0)
    {
      fprintf(stderr, "stat(%s):%s\n", credentials_file_path, strerror(errno));
      return NULL;
    }

  size_t fsize = st.st_size;
  char *content = (char *)mmap(0, fsize, PROT_READ, MAP_PRIVATE, fd, 0);
  GcpCredentials *cred = gcp_cred_new(content);
  munmap(content, fsize);

  return cred;
}

static struct json_object *
_get_value_obj(const struct json_object *json, const char *key)
{
  struct json_object *val = NULL;

  json_object_object_get_ex(json, key, &val);
  if (!val)
    return NULL;

  return val;
}

static const char *
_get_string_value(const struct json_object *json, const char *key)
{
  struct json_object *val = _get_value_obj(json, key);
  if (!val)
    return NULL;

  enum json_type type = json_object_get_type(val);
  if (type != json_type_string)
    return NULL;

  return json_object_get_string(val);
}

void gcp_cred_free(GcpCredentials *self)
{
  if (!self)
    return;
  if (self->json_obj)
    json_object_put(self->json_obj);
  free(self);
}

const char* gcp_cred_type(const GcpCredentials *self)
{
  return _get_string_value(self->json_obj, "type");
}

const char* gcp_cred_project_id(const GcpCredentials *self)
{
  return _get_string_value(self->json_obj, "project_id");
}

const char* gcp_cred_private_key_id(const GcpCredentials *self)
{
  return _get_string_value(self->json_obj, "private_key_id");
}

const char* gcp_cred_private_key(const GcpCredentials *self)
{
  return _get_string_value(self->json_obj, "private_key");
}

const char* gcp_cred_client_email(const GcpCredentials *self)
{
  return _get_string_value(self->json_obj, "client_email");
}

const char* gcp_cred_client_id(const GcpCredentials *self)
{
  return _get_string_value(self->json_obj, "client_id");
}

const char* gcp_cred_auth_uri(const GcpCredentials *self)
{
  return _get_string_value(self->json_obj, "auth_uri");
}

const char* gcp_cred_token_uri(const GcpCredentials *self)
{
  return _get_string_value(self->json_obj, "token_uri");
}

const char* gcp_cred_auth_provider_x509_cert_url(const GcpCredentials *self)
{
  return _get_string_value(self->json_obj, "auth_provider_x509_cert_url");
}

const char* gcp_cred_client_x509_cert_url(const GcpCredentials *self)
{
  return _get_string_value(self->json_obj, "client_x509_cert_url");
}

