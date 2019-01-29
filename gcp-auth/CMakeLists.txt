cmake_minimum_required(VERSION 3.1.0)

project(gcp-auth VERSION 0.1.1 DESCRIPTION "example auth lib for requesting access token to GCP" LANGUAGES C)

include(CheckCSourceCompiles)
include(CheckSymbolExists)
include(GNUInstallDirs)

add_definitions(-D_GNU_SOURCE=1)
set(MEMORYCHECK_COMMAND_OPTIONS "${MEMORYCHECK_COMMAND_OPTIONS} --trace-children=yes --leak-check=full --error-exitcode=255")
include (CTest)

set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -Wall -Wextra")
list(APPEND CMAKE_MODULE_PATH "${CMAKE_CURRENT_SOURCE_DIR}/cmake")
find_package(JSON-C 0.13.1 REQUIRED)
find_package(OpenSSL REQUIRED)
find_package(CURL REQUIRED)

include_directories("${JSON-C_INCLUDE_DIR}" "${OPENSSL_INCLUDE_DIR}" "${CURL_INCLUDE_DIRS}" "${CMAKE_CURRENT_SOURCE_DIR}/include" ${CMAKE_CURRENT_BINARY_DIR})

add_subdirectory(src)

set(CMAKE_REQUIRED_DEFINITIONS "-D_GNU_SOURCE")
check_symbol_exists(asprintf "stdio.h" HAVE_ASPRINTF)
message(STATUS "asprintf ${HAVE_ASPRINTF}")

configure_file(${CMAKE_CURRENT_SOURCE_DIR}/src/config.h.in config.h)


add_custom_target(test_memcheck
      COMMAND ${CMAKE_CTEST_COMMAND}
            --force-new-ctest-process --test-action memcheck 
      COMMAND cat "${CMAKE_BINARY_DIR}/Testing/Temporary/MemoryChecker.*.log")
 
option(ENABLE_TESTS "Enable tests" ON)
if (ENABLE_TESTS)
 find_package(Criterion REQUIRED)
  enable_testing()
  add_subdirectory(test)
endif()

set(libdir "\${libdir}")
set(includedir "\${includedir}")
configure_file(${CMAKE_CURRENT_SOURCE_DIR}/gcp_auth.pc.in ${CMAKE_CURRENT_BINARY_DIR}/gcp_auth.pc @ONLY)

install(FILES ${CMAKE_CURRENT_BINARY_DIR}/config.h DESTINATION include/gcp-auth)
install(FILES ${CMAKE_CURRENT_BINARY_DIR}/gcp_auth.pc DESTINATION lib/pkgconfig)

