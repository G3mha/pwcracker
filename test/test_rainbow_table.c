#include <criterion/criterion.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

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
    entries[1].hash = strdup("$1$zUDL$9e6ecda6f253031f43027fc163e3912c"); // "123456" 
    entries[1].salt = strdup("zUDL");
    entries[1].type = HASH_MD5;
    entries[1].password = NULL;
    
    // Set up third entry - one that won't be in table, with VALID hash format
    entries[2].username = strdup("user3");
    entries[2].hash = strdup("$1$unknwn$8d5c69bb5a0db765b1b642dc656e4fc9"); // Valid hash format but not in rainbow table
    entries[2].salt = strdup("unknwn");
    entries[2].type = HASH_MD5;
    entries[2].password = NULL;
    
    // Variables for rainbow_table_attack function
    FILE *output = tmpfile();
    int verbose = 0;
    size_t cracked_count = 0;
    volatile int timeout_flag = 0;
    
    // Create a temporary rainbow table file
    char rainbow_file[] = "/tmp/test_rainbow_XXXXXX";
    int fd = mkstemp(rainbow_file);
    FILE *table_file = fdopen(fd, "w");
    
    // Write test entries in the format expected by rainbow_attack
    fprintf(table_file, "$1$zUDL$3fe34eba094562325c4e7260409fad83:password\n");
    fprintf(table_file, "$1$zUDL$9e6ecda6f253031f43027fc163e3912c:123456\n");
    fclose(table_file);
    
    // Call the actual function
    int result = rainbow_attack(entries, num_entries, rainbow_file, 
                             HASH_MD5, output, verbose, &cracked_count, &timeout_flag);
    
    // Verify results
    cr_assert_eq(result, 0, "rainbow_attack should return 0 on success");
    cr_assert_gt(cracked_count, 0, "At least one password should be cracked");
    cr_assert_not_null(entries[0].password, "First password should be cracked");
    cr_assert_str_eq(entries[0].password, "password", "First password should be 'password'");
    cr_assert_not_null(entries[1].password, "Second password should be cracked");
    cr_assert_str_eq(entries[1].password, "123456", "Second password should be '123456'");
    cr_assert_null(entries[2].password, "Third password should not be cracked");
    
    // Clean up
    fclose(output);
    unlink(rainbow_file);
    
    for (size_t i = 0; i < num_entries; i++) {
        free(entries[i].username);
        free(entries[i].hash);
        free(entries[i].salt);
        free(entries[i].password);
    }
}
