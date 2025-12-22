/*
 * victim.c - Target program for DT_NEEDED injection attacks
 *
 * This is a simple program that demonstrates:
 *   1. Normal execution flow
 *   2. How DT_NEEDED injection affects program startup
 *   3. Environment variable access (target for interception)
 *
 * The program will be modified to include a malicious DT_NEEDED
 * entry that loads an attacker's library before main() runs.
 *
 * Compile: gcc -o victim victim.c
 * Normal:  ./victim
 * Attack:  (after injection) ./victim
 *
 * EDUCATIONAL PURPOSES ONLY
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

/* Color codes */
#define GREEN   "\033[1;32m"
#define BLUE    "\033[1;34m"
#define YELLOW  "\033[1;33m"
#define RESET   "\033[0m"

void display_banner(void) {
    printf("\n");
    printf(BLUE "╔════════════════════════════════════════════════════════════════╗\n" RESET);
    printf(BLUE "║             DT_NEEDED INJECTION VICTIM PROGRAM                 ║\n" RESET);
    printf(BLUE "╚════════════════════════════════════════════════════════════════╝\n" RESET);
    printf("\n");
}

void check_environment(void) {
    printf("[*] Checking environment variables...\n\n");

    /* These will be intercepted if malicious library is loaded */
    char *api_key = getenv("SECRET_API_KEY");
    char *db_pass = getenv("DATABASE_PASSWORD");
    char *token = getenv("AUTH_TOKEN");
    char *user = getenv("USER");
    char *home = getenv("HOME");

    printf("    USER = %s\n", user ? user : "(not set)");
    printf("    HOME = %s\n", home ? home : "(not set)");

    if (api_key) {
        printf("    SECRET_API_KEY = %s\n", api_key);
    }
    if (db_pass) {
        printf("    DATABASE_PASSWORD = %s\n", db_pass);
    }
    if (token) {
        printf("    AUTH_TOKEN = %s\n", token);
    }

    printf("\n");
}

void do_work(void) {
    printf("[*] Performing normal operations...\n\n");

    printf("    Reading configuration...\n");
    printf("    Connecting to database...\n");
    printf("    Processing data...\n");
    printf("    Operation complete.\n\n");
}

void show_dt_needed_info(void) {
    printf("[*] Library dependency information:\n\n");
    printf("    To see DT_NEEDED entries, run:\n");
    printf("    " YELLOW "readelf -d ./victim | grep NEEDED" RESET "\n\n");
    printf("    Or use our explorer:\n");
    printf("    " YELLOW "./dt_needed_explorer ./victim" RESET "\n\n");
}

int main(int argc, char *argv[]) {
    display_banner();

    printf("[*] main() starting - PID: %d\n\n", getpid());

    /* If -q flag, quiet mode */
    int quiet = (argc > 1 && strcmp(argv[1], "-q") == 0);

    if (!quiet) {
        check_environment();
        do_work();
        show_dt_needed_info();
    }

    printf(GREEN "[*] Program completed successfully.\n" RESET);
    printf("\n");

    return 0;
}
