#include <criterion/criterion.h>
#include <criterion/redirect.h>
#include <stdlib.h>
#include <string.h>
#include "../src/cli.h"
#include "../src/util.h"

/* Mock argc and argv for testing */
static char *create_argv(int *argc, const char *args) {
    *argc = 0;
    
    /* Count number of arguments */
    const char *p = args;
    int in_arg = 0;
    
    while (*p) {
        if (*p == ' ' || *p == '\t') {
            in_arg = 0;
        } else if (!in_arg) {
            in_arg = 1;
            (*argc)++;
        }
        p++;
    }
    
    /* Allocate argv */
    char **argv = (char **)malloc((*argc + 1) * sizeof(char *));
    cr_assert(argv != NULL, "Failed to allocate memory for argv");
    
    /* Parse arguments */
    p = args;
    in_arg = 0;
    int i = 0;
    char *arg_start = NULL;
    
    while (1) {
        if (*p == ' ' || *p == '\t' || *p == '\0') {
            if (in_arg) {
                /* End of argument */
                size_t len = (size_t)(p - arg_start);
                argv[i] = (char *)malloc(len + 1);
                cr_assert(argv[i] != NULL, "Failed to allocate memory for argument");
                
                memcpy(argv[i], arg_start, len);
                argv[i][len] = '\0';
                i++;
                
                in_arg = 0;
            }
            
            if (*p == '\0') {
                break;
            }
        } else if (!in_arg) {
            /* Start of argument */
            in_arg = 1;
            arg_start = (char *)p;
        }
        
        p++;
    }
    
    argv[i] = NULL;
    return (char *)argv;
}

/* Free argv */
static void free_argv(int argc, char **argv) {
    for (int i = 0; i < argc; i++) {
        free(argv[i]);
    }
    free(argv);
}

/* Test default values */
Test(cli, default_values) {
    int argc = 2;
    char *argv[] = {"pwcracker", SHADOW_FILE, NULL};
    
    struct arguments args = parse_arguments(argc, argv);
    
    cr_assert_eq(args.mode, MODE_DICTIONARY, "Default mode should be dictionary");
    cr_assert_str_eq(args.dictionary_file, DICTIONARY_FILE, 
                   "Default dictionary file should be " DICTIONARY_FILE);
    cr_assert_eq(args.max_length, 8, "Default max length should be 8");
    cr_assert_str_eq(args.charset, "abcdefghijklmnopqrstuvwxyz0123456789", 
                   "Default charset should be lowercase alphanumeric");
    cr_assert_str_eq(args.target_file, SHADOW_FILE, "Shadow file should be " SHADOW_FILE);
    cr_assert_eq(args.threads, 1, "Default thread count should be 1");
    cr_assert_eq(args.timeout, 0, "Default timeout should be 0");
    cr_assert_eq(args.verbose, 0, "Default verbose flag should be false");
    cr_assert_eq(args.quiet, 0, "Default quiet flag should be false");
    cr_assert_eq(args.benchmark, 0, "Default benchmark flag should be false");
    cr_assert_eq(args.hash_type, HASH_AUTO, "Default hash type should be auto");
}

/* Test dictionary mode */
Test(cli, dictionary_mode) {
    int argc;
    char **argv = (char **)create_argv(&argc, "pwcracker -d " DICTIONARY_FILE " " SHADOW_FILE);
    
    struct arguments args = parse_arguments(argc, (char **)argv);
    cr_assert_eq(args.mode, MODE_DICTIONARY, "Mode should be dictionary");
    cr_assert_str_eq(args.target_file, SHADOW_FILE, "Shadow file should be " SHADOW_FILE);
    cr_assert_str_eq(args.dictionary_file, DICTIONARY_FILE, 
                   "Dictionary file should be " DICTIONARY_FILE);
    
    free_argv(argc, argv);
}

/* Test brute force mode */
Test(cli, bruteforce_mode) {
    int argc;
    char **argv = (char **)create_argv(&argc, "pwcracker -b -l 4 -c abc " SHADOW_FILE);
    
    struct arguments args = parse_arguments(argc, (char **)argv);
    
    cr_assert_eq(args.mode, MODE_BRUTEFORCE, "Mode should be brute force");
    cr_assert_str_eq(args.target_file, SHADOW_FILE, "Shadow file should be " SHADOW_FILE);
    cr_assert_eq(args.max_length, 4, "Max length should be 4");
    cr_assert_str_eq(args.charset, "abc", "Charset should be abc");
    
    free_argv(argc, argv);
}

/* Test rainbow mode */
Test(cli, rainbow_mode) {
    int argc;
    char **argv = (char **)create_argv(&argc, "pwcracker -r " RAINBOW_FILE " " SHADOW_FILE);
    
    struct arguments args = parse_arguments(argc, (char **)argv);
    
    cr_assert_eq(args.mode, MODE_RAINBOW, "Mode should be rainbow");
    cr_assert_str_eq(args.target_file, SHADOW_FILE, "Shadow file should be " SHADOW_FILE);
    cr_assert_str_eq(args.rainbow_file, RAINBOW_FILE, 
                   "Rainbow file should be " RAINBOW_FILE);
    
    free_argv(argc, argv);
}

/* Test benchmark mode */
Test(cli, benchmark_mode) {
    int argc;
    char **argv = (char **)create_argv(&argc, "pwcracker -B");
    
    struct arguments args = parse_arguments(argc, (char **)argv);
    
    cr_assert_eq(args.benchmark, 1, "Benchmark flag should be true");
    
    free_argv(argc, argv);
}

/* Test verbose and quiet modes */
Test(cli, verbose_quiet_modes) {
    int argc;
    char **argv = (char **)create_argv(&argc, "pwcracker -v -q " SHADOW_FILE);
    
    struct arguments args = parse_arguments(argc, (char **)argv);
    
    cr_assert_eq(args.verbose, 1, "Verbose flag should be true");
    cr_assert_eq(args.quiet, 1, "Quiet flag should be true");
    
    free_argv(argc, argv);
}

/* Test hash type selection */
Test(cli, hash_type) {
    int argc;
    char **argv = (char **)create_argv(&argc, "pwcracker -H md5 " SHADOW_FILE);
    
    struct arguments args = parse_arguments(argc, (char **)argv);
    
    cr_assert_eq(args.hash_type, HASH_MD5, "Hash type should be MD5");
    
    free_argv(argc, argv);
}

/* Test output file */
Test(cli, output_file) {
    int argc;
    char **argv = (char **)create_argv(&argc, "pwcracker -o " OUTPUT_FILE " " SHADOW_FILE);
    
    struct arguments args = parse_arguments(argc, (char **)argv);
    
    cr_assert_str_eq(args.output_file, OUTPUT_FILE, 
                   "Output file should be " OUTPUT_FILE);
    
    free_argv(argc, argv);
}

/* Test threads option */
Test(cli, threads) {
    int argc;
    char **argv = (char **)create_argv(&argc, "pwcracker -t 4 " SHADOW_FILE);
    
    struct arguments args = parse_arguments(argc, (char **)argv);
    
    cr_assert_eq(args.threads, 4, "Thread count should be 4");
    
    free_argv(argc, argv);
}

/* Test timeout option */
Test(cli, timeout) {
    int argc;
    char **argv = (char **)create_argv(&argc, "pwcracker -T 30 " SHADOW_FILE);
    
    struct arguments args = parse_arguments(argc, (char **)argv);
    
    cr_assert_eq(args.timeout, 30, "Timeout should be 30 seconds");
    
    free_argv(argc, argv);
}
