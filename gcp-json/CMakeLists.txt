cmake_minimum_required(VERSION 3.1.0)

project(gcp-json)

set(MEMORYCHECK_COMMAND_OPTIONS "${MEMORYCHECK_COMMAND_OPTIONS} --trace-children=yes --leak-check=full --error-exitcode=255")
include (CTest)

set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -Wall -Wextra")
list(APPEND CMAKE_MODULE_PATH "${CMAKE_CURRENT_SOURCE_DIR}/cmake")
find_package(JSON-C REQUIRED)
include_directories("${JSON-C_INCLUDE_DIR}" "${CMAKE_CURRENT_SOURCE_DIR}/src")

add_subdirectory(src)
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
