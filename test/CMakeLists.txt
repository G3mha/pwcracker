# Some compilers warn that the return value of cr_assert gets converted from an
# int to a unsigned char:1. To avoid this error in those compilers, turn off
# conversion warnings for test code.
set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -Wno-conversion")

list(APPEND CMAKE_CTEST_ARGUMENTS --verbose)

# CLI test
add_executable(test_cli test_cli.c)
target_link_libraries(test_cli
    PRIVATE cli
    PUBLIC ${CRITERION}
)
add_test(
    NAME test_cli
    COMMAND test_cli ${CRITERION_FLAGS}
)

# Create test data directory in build directory
file(MAKE_DIRECTORY ${CMAKE_BINARY_DIR}/data)

# Copy test data files to build directory
file(GLOB TEST_DATA_FILES
    ${CMAKE_SOURCE_DIR}/data/*.txt
)
foreach(TEST_DATA_FILE ${TEST_DATA_FILES})
    get_filename_component(FILE_NAME ${TEST_DATA_FILE} NAME)
    configure_file(${TEST_DATA_FILE} ${CMAKE_BINARY_DIR}/data/${FILE_NAME} COPYONLY)
endforeach()
