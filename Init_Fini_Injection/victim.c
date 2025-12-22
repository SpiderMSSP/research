/*
 * victim.c - Target program for init/fini injection demonstration
 *
 * This innocent program has its own constructors/destructors
 * but can be hijacked via LD_PRELOAD or other injection methods.
 *
 * Compile: gcc -o victim victim.c
 * Normal:  ./victim
 * Attack:  LD_PRELOAD=./evil_constructor.so ./victim
 *
 * EDUCATIONAL PURPOSES ONLY
 */

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

/* Color codes */
#define GREEN   "\033[1;32m"
#define BLUE    "\033[1;34m"
#define RESET   "\033[0m"

/* Legitimate constructor */
__attribute__((constructor))
void victim_init(void) {
    printf(GREEN "[VICTIM CONSTRUCTOR] " RESET "Initializing application...\n");
}

/* Legitimate destructor */
__attribute__((destructor))
void victim_cleanup(void) {
    printf(GREEN "[VICTIM DESTRUCTOR]  " RESET "Cleaning up application...\n");
}

int main(void) {
    printf("\n");
    printf(BLUE "╔════════════════════════════════════════════════════════════════╗\n" RESET);
    printf(BLUE "║             INNOCENT VICTIM APPLICATION                        ║\n" RESET);
    printf(BLUE "╚════════════════════════════════════════════════════════════════╝\n" RESET);
    printf("\n");

    printf("[MAIN] PID: %d\n", getpid());
    printf("[MAIN] Doing important work...\n");
    printf("[MAIN] Processing sensitive data...\n");
    printf("[MAIN] Work complete.\n");

    printf("\n");

    return 0;
}
