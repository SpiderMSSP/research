/*
 * victim.c - Target program for LD_AUDIT attack demonstrations
 *
 * This program performs operations that will be intercepted
 * by the LD_AUDIT libraries:
 *   - Environment variable lookups (getenv)
 *   - Console output (puts, printf)
 *   - String operations
 *
 * Usage:
 *   Normal:  ./victim
 *   Attack:  LD_AUDIT=./libevil_audit.so ./victim
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
    printf(BLUE "║                LD_AUDIT VICTIM PROGRAM                         ║\n" RESET);
    printf(BLUE "╚════════════════════════════════════════════════════════════════╝\n" RESET);
    printf("\n");
}

void check_environment(void) {
    puts("[*] Checking environment variables...");
    printf("\n");

    /* These getenv calls will be intercepted */
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

void do_operations(void) {
    puts("[*] Performing operations...");
    printf("\n");

    /* These will be traced by LD_AUDIT */
    puts("    Step 1: Initializing...");
    puts("    Step 2: Processing data...");
    puts("    Step 3: Finalizing...");

    printf("\n");
}

void show_audit_info(void) {
    puts("[*] LD_AUDIT Information:");
    printf("\n");

    printf("    LD_AUDIT provides callbacks for:\n");
    printf("      • la_version   - API version negotiation\n");
    printf("      • la_objsearch - Library search interception\n");
    printf("      • la_objopen   - Library load notification\n");
    printf("      • la_preinit   - Pre-initialization hook\n");
    printf("      • la_symbind64 - Symbol binding interception\n");
    printf("\n");

    printf("    " YELLOW "Try running with:" RESET "\n");
    printf("      LD_AUDIT=./libaudit_explorer.so ./victim\n");
    printf("      LD_AUDIT=./libevil_audit.so ./victim\n");
    printf("      LD_AUDIT=./libaudit_hijack.so ./victim\n");
    printf("\n");
}

int main(void) {
    display_banner();

    printf("[*] main() starting - PID: %d\n\n", getpid());

    check_environment();
    do_operations();
    show_audit_info();

    puts(GREEN "[*] Program completed successfully." RESET);
    printf("\n");

    return 0;
}
