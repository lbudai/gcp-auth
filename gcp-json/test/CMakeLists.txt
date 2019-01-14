add_executable(test_gcp_credentials test_gcp_credentials.c)
target_link_libraries(test_gcp_credentials gcp_auth "${CRITERION_LIBRARIES}")

add_test(test_gcp_credentials test_gcp_credentials)

