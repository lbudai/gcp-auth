set(SOURCES
  gcp-credentials.c
  jwt.c
  gcp-jwt.c
)

set(SOURCE_GOAUTH
  goauth.c
)

add_library(gcp_auth ${SOURCES})
add_executable(goauth ${SOURCE_GOAUTH})
target_link_libraries(gcp_auth ${JSON-C_LIBRARY} ${OPENSSL_LIBRARIES})
target_link_libraries(goauth gcp_auth)

