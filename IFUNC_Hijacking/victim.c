/*
 * victim.c - Target program for IFUNC hijacking attacks
 *
 * This program uses functions that will be hijacked via IFUNC:
 *   - getenv() - for stealing secrets
 *   - puts() - for output interception
 *   - strlen() - commonly used
 *
 * Normal: ./victim
 * Attack: LD_PRELOAD=./libevil_ifunc.so ./victim
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

/* Constructor to show timing */
__attribute__((constructor))
static void victim_init(void) {
    printf(YELLOW "[VICTIM CONSTRUCTOR] " RESET "Running...\n\n");
}

void display_banner(void) {
    printf("\n");
    printf(BLUE "╔════════════════════════════════════════════════════════════════╗\n" RESET);
    printf(BLUE "║                 IFUNC HIJACKING VICTIM PROGRAM                 ║\n" RESET);
    printf(BLUE "╚════════════════════════════════════════════════════════════════╝\n" RESET);
    printf("\n");
}

void check_environment(void) {
    puts("[*] Checking environment variables...");
    printf("\n");

    /* These getenv calls will be intercepted by IFUNC hooks */
    char *api_key = getenv("SECRET_API_KEY");
    char *db_pass = getenv("DATABASE_PASSWORD");
    char *token = getenv("AUTH_TOKEN");
    char *user = getenv("USER");

    printf("    USER = %s\n", user ? user : "(not set)");

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

    puts("    Step 1: Initializing system...");
    puts("    Step 2: Processing data...");
    puts("    Step 3: Completing tasks...");

    printf("\n");
}

void show_ifunc_info(void) {
    puts("[*] IFUNC Information:");
    printf("\n");

    printf("    IFUNC (Indirect Functions) allow runtime function selection.\n");
    printf("    The resolver function runs DURING dynamic linking.\n");
    printf("\n");
    printf("    " YELLOW "This is EARLIER than:" RESET "\n");
    printf("      • LD_PRELOAD constructors\n");
    printf("      • LD_AUDIT la_preinit\n");
    printf("      • Library constructors\n");
    printf("      • Program constructors\n");
    printf("      • main()\n");
    printf("\n");
    printf("    " YELLOW "Try:" RESET "\n");
    printf("      LD_PRELOAD=./libevil_ifunc.so ./victim\n");
    printf("      LD_PRELOAD=./libresolver_attack.so ./victim\n");
    printf("\n");
}

int main(void) {
    display_banner();

    printf("[*] main() starting - PID: %d\n\n", getpid());

    check_environment();
    do_operations();
    show_ifunc_info();

    puts(GREEN "[*] Program completed successfully." RESET);
    printf("\n");

    return 0;
}
