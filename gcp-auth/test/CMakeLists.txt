add_executable(test_gcp_credentials test_gcp_credentials.c)
target_link_libraries(test_gcp_credentials gcp_auth "${CRITERION_LIBRARIES}")

add_executable(test_jwt test_jwt.c)
target_link_libraries(test_jwt gcp_auth "${CRITERION_LIBRARIES}")

add_executable(test_gcp_jwt test_gcp_jwt.c)
target_link_libraries(test_gcp_jwt gcp_auth "${CRITERION_LIBRARIES}")

add_executable(test_asprintf_compat test_asprintf_compat.c ${CMAKE_SOURCE_DIR}/src/asprintf-compat.c)
target_link_libraries(test_asprintf_compat "${CRITERION_LIBRARIES}")
add_definitions(-DTEST_ASPRINTF=1)


add_test(test_jwt test_jwt)
add_test(test_gcp_credentials test_gcp_credentials)
add_test(test_gcp_jwt test_gcp_jwt)
add_test(test_asprintf_compat test_asprintf_compat)

