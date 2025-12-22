/*
 * victim.c - Target program for symbol versioning attacks
 *
 * This program uses various libc functions that have multiple
 * versioned implementations. It can be used to demonstrate:
 *   1. Which symbol versions are being used
 *   2. How LD_PRELOAD can hijack versioned symbols
 *   3. Version requirements at runtime
 *
 * Compile: gcc -o victim victim.c
 * Normal:  ./victim
 * Attack:  LD_PRELOAD=./libevil_versioned.so ./victim
 *
 * EDUCATIONAL PURPOSES ONLY
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <limits.h>

/* Color codes */
#define GREEN   "\033[1;32m"
#define BLUE    "\033[1;34m"
#define RESET   "\033[0m"

void display_banner(void) {
    printf("\n");
    printf(BLUE "╔════════════════════════════════════════════════════════════════╗\n" RESET);
    printf(BLUE "║            SYMBOL VERSIONING VICTIM PROGRAM                    ║\n" RESET);
    printf(BLUE "╚════════════════════════════════════════════════════════════════╝\n" RESET);
    printf("\n");
}

void test_realpath(void) {
    printf("[*] Testing realpath()...\n");

    char resolved[PATH_MAX];
    char *result = realpath("/etc/passwd", resolved);

    if (result) {
        printf("    realpath(\"/etc/passwd\") = %s\n", result);
    } else {
        printf("    realpath failed\n");
    }
    printf("\n");
}

void test_memcpy(void) {
    printf("[*] Testing memcpy()...\n");

    char src[] = "Hello, World!";
    char dest[32];

    memcpy(dest, src, sizeof(src));
    printf("    Copied: \"%s\"\n", dest);
    printf("\n");
}

void test_getenv(void) {
    printf("[*] Testing getenv()...\n");

    char *user = getenv("USER");
    char *home = getenv("HOME");
    char *secret = getenv("SECRET_API_KEY");

    if (user) printf("    USER = %s\n", user);
    if (home) printf("    HOME = %s\n", home);
    if (secret) printf("    SECRET_API_KEY = %s\n", secret);
    printf("\n");
}

void test_string_funcs(void) {
    printf("[*] Testing string functions...\n");

    char buffer[64];
    const char *src = "Test string for copying";

    strcpy(buffer, src);
    printf("    strcpy result: \"%s\"\n", buffer);

    size_t len = strlen(buffer);
    printf("    strlen result: %zu\n", len);
    printf("\n");
}

int main(void) {
    display_banner();

    printf("[*] PID: %d\n\n", getpid());

    test_realpath();
    test_memcpy();
    test_getenv();
    test_string_funcs();

    printf(GREEN "[*] All tests completed.\n" RESET);
    printf("\n");

    return 0;
}
