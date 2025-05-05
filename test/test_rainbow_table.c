#include <criterion/criterion.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "../src/rainbow.h"
#include "../src/util.h"

Test(rainbow_table_attack, basic_functionality) {
    // Create a single shadow entry for testing
    shadow_entry_t entry = {0};
    
    // Set up the entry with a known password
    entry.username = strdup("user1");
    entry.hash = strdup("$1$zUDL$3fe34eba094562325c4e7260409fad83"); // "password" from test data
    entry.salt = strdup("zUDL");
    entry.type = HASH_MD5;
    entry.password = NULL;
    
    // Variables for rainbow_attack function
    FILE *output = tmpfile();
    int verbose = 0;
    size_t cracked_count = 0;
    volatile int timeout_flag = 0;
    
    // Use the existing rainbow table file
    const char* rainbow_file = "../data/test_rainbow_table.txt";
    
    // Call the actual function with a single entry
    int result = rainbow_attack(&entry, 1, rainbow_file, 
                                HASH_MD5, output, verbose,
                                &cracked_count, &timeout_flag);
    
    // Verify results
    cr_assert_eq(result, 0, "rainbow_attack should return 0 on success");
    cr_assert_eq(cracked_count, 1, "The password should be cracked");
    cr_assert_not_null(entry.password, "Password should be found");
    cr_assert_str_eq(entry.password, "password", "Password should be 'password'");
    
    // Clean up
    fclose(output);
    free(entry.username);
    free(entry.hash);
    free(entry.salt);
    free(entry.password);
}
