#include <criterion/criterion.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "../src/rainbow.h"
#include "../src/util.h"

Test(rainbow_table_attack, basic_functionality) {
    // Create shadow entries for testing
    shadow_entry_t entries[3] = {0};
    size_t num_entries = 3;
    
    // Set up the first entry with a known password
    entries[0].username = strdup("user1");
    entries[0].hash = strdup("$1$zUDL$3fe34eba094562325c4e7260409fad83"); // "password" from test data
    entries[0].salt = strdup("zUDL");
    entries[0].type = HASH_MD5;
    entries[0].password = NULL;
    
    // Set up second entry
    entries[1].username = strdup("user2");
    entries[1].hash = strdup("$1$salt$4ed77062b1b6259ad051df508ad64cfd"); // "aaaa" 
    entries[1].salt = strdup("salt");
    entries[1].type = HASH_MD5;
    entries[1].password = NULL;
    
    // Set up third entry - one that won't be in table
    entries[2].username = strdup("user3");
    entries[2].hash = strdup("$1$salt$a very complex hash that won't match");
    entries[2].salt = strdup("salt");
    entries[2].type = HASH_MD5;
    entries[2].password = NULL;
    
    // Variables for rainbow_table_attack function
    FILE *output = tmpfile();
    int verbose = 0;
    size_t cracked_count = 0;
    volatile int timeout_flag = 0;
    
    // Path to rainbow table file (adjust as needed)
    const char *rainbow_table_path = "../data/test_hashed_md5.txt";
    
    // Call the actual function we want to test
    int result = rainbow_attack(entries, num_entries, rainbow_table_path, 
                                output, verbose, &cracked_count, &timeout_flag, 0);
         
    // Verify results
    cr_assert_eq(result, 0, "rainbow_table_attack should return 0 on success");
    cr_assert_gt(cracked_count, 0, "At least one password should be cracked");
    cr_assert_not_null(entries[0].password, "First password should be cracked");
    cr_assert_str_eq(entries[0].password, "password", "First password should be 'password'");
    cr_assert_not_null(entries[1].password, "Second password should be cracked");
    cr_assert_str_eq(entries[1].password, "aaaa", "Second password should be 'aaaa'");
    cr_assert_null(entries[2].password, "Third password should not be cracked");
    
    // Clean up
    fclose(output);
    for (size_t i = 0; i < num_entries; i++) {
        cr_log_info("Username: %s, Hash: %s, Salt: %s, Password: %s", 
               entries[i].username, entries[i].hash, 
               entries[i].salt, entries[i].password ? entries[i].password : "NULL");
        free(entries[i].username);
        free(entries[i].hash);
        free(entries[i].salt);
        free(entries[i].password);
    }
}
