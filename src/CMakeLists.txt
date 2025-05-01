# Find required packages
find_package(OpenSSL REQUIRED)
find_library(CRYPT_LIBRARY crypt REQUIRED)
find_package(Threads REQUIRED)

# Define libraries
add_library(util util.c util.h)
target_link_libraries(util PRIVATE OpenSSL::Crypto ${CRYPT_LIBRARY})

add_library(crypto dictionary.c dictionary.h brute_force.c brute_force.h rainbow.c rainbow.h benchmark.c benchmark.h)
target_link_libraries(crypto PRIVATE util ${CMAKE_THREAD_LIBS_INIT})

add_library(cli cli.c cli.h)
target_link_libraries(cli PRIVATE util)

# Define main executable
add_executable(pwcracker main.c)
target_link_libraries(pwcracker PRIVATE crypto cli util)

# Install targets
install(TARGETS pwcracker DESTINATION bin)
