# Some compilers warn that the return value of cr_assert gets converted from an
# int to a unsigned char:1. To avoid this error in those compilers, turn off
# conversion warnings for test code.
set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -Wno-conversion -Wno-int-conversion")

list(APPEND CMAKE_CTEST_ARGUMENTS --verbose)

# CLI test
add_executable(test_cli test_cli.c)
target_link_libraries(test_cli PRIVATE cli criterion)
add_test(NAME test_cli COMMAND test_cli ${CRITERION_FLAGS})

# Dictionary test
add_executable(test_dictionary test_dictionary.c)
target_link_libraries(test_dictionary PRIVATE crypto criterion)
add_test(NAME test_dictionary COMMAND test_dictionary ${CRITERION_FLAGS})

# Brute force test
add_executable(test_brute_force test_brute_force.c)
target_link_libraries(test_brute_force PRIVATE crypto criterion)
add_test(NAME test_brute_force COMMAND test_brute_force ${CRITERION_FLAGS})

# Rainbow table test
add_executable(test_rainbow_table test_rainbow_table.c)
target_link_libraries(test_rainbow_table PRIVATE crypto criterion)
add_test(NAME test_rainbow_table COMMAND test_rainbow_table ${CRITERION_FLAGS})

# Create test data directory in build directory
file(MAKE_DIRECTORY ${CMAKE_BINARY_DIR}/data)

# Copy test data files to build directory
file(COPY ${CMAKE_SOURCE_DIR}/data/
     DESTINATION ${CMAKE_BINARY_DIR}/data
     FILES_MATCHING PATTERN "*.txt")
