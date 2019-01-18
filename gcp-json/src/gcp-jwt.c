#include "gcp-jwt.h"
#include "jwt.h"
#include <json.h>

struct _GcpJwt
{
  struct json_object *json_obj;
  const char *key;
  char *jwt_str;
  time_t iat;
  size_t exp;
};

GcpJwt*
gcp_jwt_new(const char *key)
{
  GcpJwt *self = calloc(sizeof(GcpJwt), 1);
  self->json_obj = json_object_new_object();
  self->key = key;

  return self;
}

static void
_free_computed_values(GcpJwt *self)
{
  if (self->jwt_str)
    {
      free(self->jwt_str);
      self->jwt_str = NULL;
    }
}

void
gcp_jwt_free(GcpJwt *self)
{
  if (!self)
    return;

  _free_computed_values(self);

  if (self->json_obj)
    json_object_put(self->json_obj);

  free(self);
}

const char *
gcp_jwt_get_encoded(GcpJwt *self)
{
  if (self->jwt_str)
    return self->jwt_str;

  self->jwt_str = jwt_encode(JWT_ALG_RS256, self->key, gcp_jwt_get_json_str(self, JSON_C_TO_STRING_PLAIN|JSON_C_TO_STRING_NOSLASHESCAPE));

  return self->jwt_str;
}

const char *
gcp_jwt_get_json_str(GcpJwt *self, int json_print_str_flags)
{
  return json_object_to_json_string_ext(self->json_obj, json_print_str_flags);
}

static void
_json_object_object_add(GcpJwt *self, const char *key, struct json_object *value)
{
  _free_computed_values(self);
  json_object_object_add(self->json_obj, key, value);
}

void
gcp_jwt_set_issuer(GcpJwt *self, const char *iss)
{
  _json_object_object_add(self, "iss", json_object_new_string(iss));
}

void
gcp_jwt_set_scope(GcpJwt *self, const char *scope)
{
  _json_object_object_add(self, "scope", json_object_new_string(scope));
}

void
gcp_jwt_set_audience(GcpJwt *self, const char *aud)
{
  _json_object_object_add(self, "aud", json_object_new_string(aud));
}

void
gcp_jwt_set_issued_at(GcpJwt *self, time_t time)
{
  int _need_to_update_exp = 0;
  if (self->iat == 0)
    _need_to_update_exp = 1;
  self->iat = time;
  _json_object_object_add(self, "iat", json_object_new_int(time));
  if (_need_to_update_exp)
    gcp_jwt_set_expiration_time(self, self->exp);
}

void
gcp_jwt_set_expiration_time(GcpJwt *self, size_t seconds)
{
  self->exp = seconds;
  time_t exp = self->iat + seconds;
  _json_object_object_add(self, "exp", json_object_new_int(exp));
}

