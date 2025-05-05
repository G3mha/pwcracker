#include <criterion/criterion.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "../src/brute_force.h"
#include "../src/util.h"

Test(brute_force_attack, simple_password) {
    // Create a shadow entry with a very simple password
    shadow_entry_t entry = {0};
    
    // Set up entry with a simple password "aaaa"
    // You'll need to replace this hash with the actual MD5 hash of "aaaa" with your salt
    entry.username = strdup("testuser");
    entry.salt = strdup("salt");
    entry.hash = strdup("$1$salt$4ed77062b1b6259ad051df508ad64cfd"); // Hash for "aaaa"
    entry.type = HASH_MD5;
    entry.password = NULL;
    
    // Variables for brute_force_attack function
    FILE *output = tmpfile();
    int verbose = 0;
    size_t cracked_count = 0;
    volatile int timeout_flag = 0;
    
    // Set brute force parameters for a very simple case
    // Limit character set to just lowercase 'a' if possible
    // Or set a very small max length (like 4)
    char charset[] = "a";  // Just the letter 'a'
    int min_len = 4;
    int max_len = 4;  // Exactly 4 characters
    
    // Call the function we're testing
    int result = brute_force_attack(&entry, 1, charset, min_len, max_len,
                                  output, verbose, &cracked_count, &timeout_flag);
    
    // Verify results
    cr_assert_eq(result, 0, "brute_force_attack should return 0 on success");
    cr_assert_eq(cracked_count, 1, "The password should be cracked");
    cr_assert_not_null(entry.password, "Password should be found");
    cr_assert_str_eq(entry.password, "aaaa", "Password should be 'aaaa'");
    
    // Clean up
    fclose(output);
    free(entry.username);
    free(entry.hash);
    free(entry.salt);
    free(entry.password);
}
