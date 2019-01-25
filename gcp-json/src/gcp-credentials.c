#include "gcp-credentials.h"
#include <json.h>
#include <string.h>

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

  return json_object_get_string(val); // TODO; check if type is not pre-checked
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

