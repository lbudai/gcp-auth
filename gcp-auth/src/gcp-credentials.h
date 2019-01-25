#ifndef GCP_CREDENTIALS_H_INCLUDED
#define GCP_CREDENTIALS_H_INCLUDED

typedef struct _GcpCredentials GcpCredentials;

GcpCredentials* gcp_cred_new(const char *gcp_credentials_str);
void gcp_cred_free(GcpCredentials *self);

const char* gcp_cred_type(const GcpCredentials *self);
const char* gcp_cred_project_id(const GcpCredentials *self);
const char* gcp_cred_private_key_id(const GcpCredentials *self);
const char* gcp_cred_private_key(const GcpCredentials *self);
const char* gcp_cred_client_email(const GcpCredentials *self);
const char* gcp_cred_client_id(const GcpCredentials *self);
const char* gcp_cred_auth_uri(const GcpCredentials *self);
const char* gcp_cred_token_uri(const GcpCredentials *self);
const char* gcp_cred_auth_provider_x509_cert_url(const GcpCredentials *self);
const char* gcp_cred_client_x509_cert_url(const GcpCredentials *self);

#endif

