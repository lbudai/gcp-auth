#ifndef GCP_JWT_H_INCLUDED
#define GCP_JWT_H_INCLUDED

#include <time.h>

typedef struct _GcpJwt GcpJwt;

GcpJwt *gcp_jwt_new(const char *key);
void gcp_jwt_free(GcpJwt *self);

const char *gcp_jwt_get_encoded(GcpJwt *self);
const char *gcp_jwt_get_json_str(GcpJwt *self, int json_print_str_flags);

void gcp_jwt_set_issuer(GcpJwt *self, const char *iss);
void gcp_jwt_set_scope(GcpJwt *self, const char *scope);
void gcp_jwt_set_audience(GcpJwt *self, const char *aud);
void gcp_jwt_set_issued_at(GcpJwt *self, time_t time);
void gcp_jwt_set_expiration_time(GcpJwt *self, size_t seconds);

#endif
