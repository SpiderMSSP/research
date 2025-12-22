/*
 * victim.c - An innocent program that will be targeted
 *
 * This represents any dynamically-linked binary on the system.
 * We'll modify its INTERP header to use our trojanized loader.
 */

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

void do_sensitive_work(void) {
    printf("[VICTIM] Processing sensitive data...\n");
    printf("[VICTIM] Connecting to database...\n");
    printf("[VICTIM] Transaction complete!\n");
}

int main(int argc, char *argv[]) {
    printf("\n");
    printf("╔══════════════════════════════════════════════════╗\n");
    printf("║         LEGITIMATE BANKING APPLICATION           ║\n");
    printf("╚══════════════════════════════════════════════════╝\n");
    printf("\n");

    printf("[VICTIM] PID: %d\n", getpid());
    printf("[VICTIM] Program starting normally...\n");
    printf("[VICTIM] Initializing secure connection...\n");

    do_sensitive_work();

    printf("[VICTIM] Shutting down cleanly.\n");
    printf("\n");

    return 0;
}
