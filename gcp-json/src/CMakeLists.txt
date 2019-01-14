set(SOURCES
  gcp-credentials.c
)

set(SOURCE_GOAUTH
  goauth.c
)

add_library(gcp_auth ${SOURCES})
add_executable(goauth ${SOURCE_GOAUTH})
target_link_libraries(gcp_auth ${JSON-C_LIBRARY})
target_link_libraries(goauth gcp_auth)

