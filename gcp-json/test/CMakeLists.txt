add_executable(test_gcp_credentials test_gcp_credentials.c)
target_link_libraries(test_gcp_credentials gcp_auth "${CRITERION_LIBRARIES}")

add_test(test_gcp_credentials test_gcp_credentials)

add_executable(test_jwt test_jwt.c)
target_link_libraries(test_jwt gcp_auth "${CRITERION_LIBRARIES}")

add_test(test_jwt test_jwt)

