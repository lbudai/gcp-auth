#include "gcp-jwt.h"
#include "gcp-credentials.h"
#include <json.h>
#include <criterion/criterion.h>

const char *credentials_json = 
{
"{"
"\"type\": \"service_account\","
"\"project_id\": \"test-project\","
"\"private_key_id\": \"6a24ae31a623bff00a1aa63d20da19a24102ab1f\","
"\"private_key\": \"-----BEGIN RSA PRIVATE KEY-----\n"
"MIICWwIBAAKBgQDdlatRjRjogo3WojgGHFHYLugdUWAY9iR3fy4arWNA1KoS8kVw\n"
"33cJibXr8bvwUAUparCwlvdbH6dvEOfou0/gCFQsHUfQrSDv+MuSUMAe8jzKE4qW\n"
"+jK+xQU9a03GUnKHkkle+Q0pX/g6jXZ7r1/xAK5Do2kQ+X5xK9cipRgEKwIDAQAB\n"
"AoGAD+onAtVye4ic7VR7V50DF9bOnwRwNXrARcDhq9LWNRrRGElESYYTQ6EbatXS\n"
"3MCyjjX2eMhu/aF5YhXBwkppwxg+EOmXeh+MzL7Zh284OuPbkglAaGhV9bb6/5Cp\n"
"uGb1esyPbYW+Ty2PC0GSZfIXkXs76jXAu9TOBvD0ybc2YlkCQQDywg2R/7t3Q2OE\n"
"2+yo382CLJdrlSLVROWKwb4tb2PjhY4XAwV8d1vy0RenxTB+K5Mu57uVSTHtrMK0\n"
"GAtFr833AkEA6avx20OHo61Yela/4k5kQDtjEf1N0LfI+BcWZtxsS3jDM3i1Hp0K\n"
"Su5rsCPb8acJo5RO26gGVrfAsDcIXKC+bQJAZZ2XIpsitLyPpuiMOvBbzPavd4gY\n"
"6Z8KWrfYzJoI/Q9FuBo6rKwl4BFoToD7WIUS+hpkagwWiz+6zLoX1dbOZwJACmH5\n"
"fSSjAkLRi54PKJ8TFUeOP15h9sQzydI8zJU+upvDEKZsZc/UhT/SySDOxQ4G/523\n"
"Y0sz/OZtSWcol/UMgQJALesy++GdvoIDLfJX5GBQpuFgFenRiRDabxrE9MNUZ2aP\n"
"FaFp+DyAe+b4nDwuJaW2LURbr8AEZga7oQj0uYxcYw==\n"
"-----END RSA PRIVATE KEY-----\n\","
"\"client_email\": \"test-service@test-project.iam.gserviceaccount.com\","
"\"client_id\": \"200341631131661168449\","
"\"auth_uri\": \"https://accounts.google.com/o/oauth2/auth\","
"\"token_uri\": \"https://oauth2.googleapis.com/token\","
"\"auth_provider_x509_cert_url\": \"https://www.googleapis.com/oauth2/v1/certs\","
"\"client_x509_cert_url\": \"https://www.googleapis.com/robot/v1/metadata/x509/test-service\%41test-project.iam.gserviceaccount.com\""
"}"
};

Test(gcp_jwt, basic)
{
  GcpCredentials *creds = gcp_cred_new(credentials_json);
  GcpJwt *jwt = gcp_jwt_new(gcp_cred_private_key(creds));

  gcp_jwt_set_issuer(jwt, gcp_cred_client_email(creds));
  gcp_jwt_set_scope(jwt, "https://www.googleapis.com/auth/logging.write");
  gcp_jwt_set_audience(jwt, gcp_cred_token_uri(creds));
  gcp_jwt_set_expiration_time(jwt, 3600);
  gcp_jwt_set_issued_at(jwt, 1547842026);
 
  cr_expect_str_eq(gcp_jwt_get_json_str(jwt, JSON_C_TO_STRING_PLAIN|JSON_C_TO_STRING_NOSLASHESCAPE), "{\"iss\":\"test-service@test-project.iam.gserviceaccount.com\",\"scope\":\"https://www.googleapis.com/auth/logging.write\",\"aud\":\"https://oauth2.googleapis.com/token\",\"exp\":1547845626,\"iat\":1547842026}");

  const char *jwt_str = gcp_jwt_get_encoded(jwt);
  cr_expect_str_eq(gcp_jwt_get_encoded(jwt), "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJpc3MiOiJ0ZXN0LXNlcnZpY2VAdGVzdC1wcm9qZWN0LmlhbS5nc2VydmljZWFjY291bnQuY29tIiwic2NvcGUiOiJodHRwczovL3d3dy5nb29nbGVhcGlzLmNvbS9hdXRoL2xvZ2dpbmcud3JpdGUiLCJhdWQiOiJodHRwczovL29hdXRoMi5nb29nbGVhcGlzLmNvbS90b2tlbiIsImV4cCI6MTU0Nzg0NTYyNiwiaWF0IjoxNTQ3ODQyMDI2fQ.DWqAZ4sTPsjIdRyUK_-pmO4dKxh0Wu-s1mSOX-hdEJzmpINd0wLG-QZ_UP4f8PHqj-Mt6NN1Dgak6iJWT3ZMRffQwMCiyOXdbXegCj099lm4zp-dc3zILL5jPqEYNz9o0oPpn4ahQSD0vdOKLzqy9dqqzyE4rJ9zv63MFeEvFxg");
  gcp_cred_free(creds);
  gcp_jwt_free(jwt);
}
