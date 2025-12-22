/*
 * victim.c - Target program for GOT/PLT Hijacking demonstration
 *
 * This program makes calls to standard library functions through the PLT.
 * We'll demonstrate how GOT entries can be overwritten to hijack execution.
 *
 * Compile WITHOUT RELRO to make GOT writable:
 *   gcc -no-pie -Wl,-z,norelro -o victim victim.c
 *
 * Compile WITH partial RELRO (default):
 *   gcc -no-pie -o victim_partial victim.c
 *
 * Compile WITH full RELRO (GOT is read-only):
 *   gcc -no-pie -Wl,-z,relro,-z,now -o victim_full victim.c
 *
 * EDUCATIONAL PURPOSES ONLY
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

/* Function pointer type for our hooks */
typedef int (*puts_func_t)(const char *);

void display_banner(void) {
    puts("");
    puts("╔════════════════════════════════════════════════════════╗");
    puts("║         GOT/PLT HIJACKING DEMONSTRATION                ║");
    puts("╚════════════════════════════════════════════════════════╝");
    puts("");
}

void normal_operation(void) {
    printf("[*] Performing normal operations...\n");
    puts("[*] This message comes from puts()");
    printf("[*] Current PID: %d\n", getpid());
}

void sensitive_operation(void) {
    printf("\n[!] Entering sensitive operation...\n");
    puts("[!] Processing confidential data...");
    puts("[!] Sending data to secure server...");
    printf("[!] Operation complete.\n\n");
}

int main(int argc, char *argv[]) {
    display_banner();

    printf("[*] Program started (PID: %d)\n", getpid());
    printf("[*] This demonstrates normal PLT/GOT function calls\n\n");

    /* These calls go through the PLT → GOT mechanism */
    normal_operation();
    sensitive_operation();

    puts("[*] Program finished normally.");

    return 0;
}
