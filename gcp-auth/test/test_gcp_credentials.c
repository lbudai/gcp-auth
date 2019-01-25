#include "gcp-credentials.h"
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

Test(credentials, basic)
{
  GcpCredentials *cred = gcp_cred_new(credentials_json);
  cr_assert(cred);
  cr_expect_str_eq("service_account", gcp_cred_type(cred));
  cr_expect_str_eq("test-project", gcp_cred_project_id(cred));
  cr_expect_str_eq("6a24ae31a623bff00a1aa63d20da19a24102ab1f", gcp_cred_private_key_id(cred));
  cr_expect_str_eq("test-service@test-project.iam.gserviceaccount.com", gcp_cred_client_email(cred));
  cr_expect_str_eq("200341631131661168449", gcp_cred_client_id(cred));
  cr_expect_str_eq("https://accounts.google.com/o/oauth2/auth", gcp_cred_auth_uri(cred));
  cr_expect_str_eq("https://oauth2.googleapis.com/token", gcp_cred_token_uri(cred));
  cr_expect_str_eq("https://www.googleapis.com/oauth2/v1/certs", gcp_cred_auth_provider_x509_cert_url(cred));
  cr_expect_str_eq("https://www.googleapis.com/robot/v1/metadata/x509/test-service\%41test-project.iam.gserviceaccount.com", gcp_cred_client_x509_cert_url(cred));
  cr_expect_str_eq("-----BEGIN RSA PRIVATE KEY-----\n"
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
"-----END RSA PRIVATE KEY-----\n",
      gcp_cred_private_key(cred));
  gcp_cred_free(cred);
}

Test(credentials, empty)
{
  GcpCredentials *cred = gcp_cred_new("{}");
  cr_assert(cred);
  cr_expect_not(gcp_cred_type(cred));
  gcp_cred_free(cred);
}
