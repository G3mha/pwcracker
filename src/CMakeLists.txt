# If you have a program that's just a .c file and it has a main method, define
# an executable. If it has both a .c and .h file, make it a library. Also, link
# libraries appropriately here. Targets should be added in dependency order - if
# executable bar needs library foo, then you should do
#   add_library(foo foo.c foo.h)
#   add_executable(bar bar.c)
#   target_link_libraries(bar PRIVATE foo)
# or similar. The PRIVATE/INTERFACE/PUBLIC keyword will depend on whether the
# library is used only in function bodies (PRIVATE), only in function
# signatures/types (INTERFACE), or both (PUBLIC).

# Define libraries
add_library(shadow shadow.c shadow.h)
add_library(cli cli.c cli.h)
add_library(dictionary dictionary.c dictionary.h)
add_library(bruteforce bruteforce.c bruteforce.h)
add_library(rainbow rainbow.c rainbow.h)
add_library(benchmark benchmark.c benchmark.h)

# Find required packages
find_package(OpenSSL REQUIRED)
find_library(CRYPT_LIBRARY crypt REQUIRED)
find_package(Threads REQUIRED)

# Link libraries with dependencies
target_link_libraries(shadow PRIVATE OpenSSL::Crypto ${CRYPT_LIBRARY})
target_link_libraries(dictionary PRIVATE shadow ${CMAKE_THREAD_LIBS_INIT})
target_link_libraries(bruteforce PRIVATE shadow ${CMAKE_THREAD_LIBS_INIT})
target_link_libraries(rainbow PRIVATE shadow)
target_link_libraries(benchmark PRIVATE shadow)

# Define main executable
add_executable(pwcracker main.c)
target_link_libraries(pwcracker 
    PRIVATE cli 
    PRIVATE shadow 
    PRIVATE dictionary
    PRIVATE bruteforce
    PRIVATE rainbow
    PRIVATE benchmark
    PRIVATE ${CMAKE_THREAD_LIBS_INIT}
)

# Install targets
install(TARGETS pwcracker DESTINATION bin)
