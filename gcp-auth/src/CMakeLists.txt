set(LIB_SOURCES
  gcp-credentials.c
  jwt.c
  gcp-jwt.c
  gcp-access-token.c
  asprintf-compat.c
)

set(LIB_HEADERS
  ${CMAKE_SOURCE_DIR}/include/gcp-credentials.h
  ${CMAKE_SOURCE_DIR}/include/jwt.h
  ${CMAKE_SOURCE_DIR}/include/gcp-jwt.h
  ${CMAKE_SOURCE_DIR}/include/gcp-access-token.h
  ${CMAKE_SOURCE_DIR}/include/asprintf-compat.h
  ${CMAKE_SOURCE_DIR}/include/openssl-compat.h
)

set(SOURCE_GOAUTH
  goauth.c
)

add_library(gcp_auth SHARED ${LIB_SOURCES})

target_include_directories(gcp_auth
  SYSTEM PUBLIC
  ${CMAKE_CURRENT_SOURCE_DIR}
  ${CMAKE_CURRENT_BINARY_DIR}
  ${CMAKE_SOURCE_DIR}/include
)

set_target_properties(gcp_auth PROPERTIES VERSION ${PROJECT_VERSION})
set_target_properties(gcp_auth PROPERTIES SOVERSION 0)

add_executable(goauth ${SOURCE_GOAUTH})
target_link_libraries(gcp_auth ${JSON-C_LIBRARY} ${OPENSSL_LIBRARIES} ${CURL_LIBRARIES})
target_link_libraries(goauth gcp_auth ${CURL_LIBRARIES})

install(TARGETS gcp_auth LIBRARY DESTINATION lib)
install(FILES ${LIB_HEADERS} DESTINATION include/gcp-auth)
install(TARGETS goauth DESTINATION bin)

