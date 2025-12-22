/*
 * version_explorer.c - Symbol Versioning Explorer
 *
 * Demonstrates how symbol versioning works and shows the ELF sections
 * involved. Uses system tools for reliable parsing.
 *
 * EDUCATIONAL PURPOSES ONLY
 */

#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <dlfcn.h>

/* Color codes */
#define RED     "\033[1;31m"
#define GREEN   "\033[1;32m"
#define YELLOW  "\033[1;33m"
#define BLUE    "\033[1;34m"
#define MAGENTA "\033[1;35m"
#define CYAN    "\033[1;36m"
#define RESET   "\033[0m"

void print_versioning_explanation(void) {
    printf("\n");
    printf(RED "╔════════════════════════════════════════════════════════════════════╗\n" RESET);
    printf(RED "║" YELLOW "              SYMBOL VERSIONING EXPLORER                            " RED "║\n" RESET);
    printf(RED "║" RESET "                                                                    " RED "║\n" RESET);
    printf(RED "║" RESET "  Exploring GNU symbol versioning in ELF binaries                   " RED "║\n" RESET);
    printf(RED "║" RESET "  Used by glibc for backwards compatibility                         " RED "║\n" RESET);
    printf(RED "╚════════════════════════════════════════════════════════════════════╝\n" RESET);
    printf("\n");

    printf(CYAN "═══════════════════════════════════════════════════════════════════\n" RESET);
    printf(CYAN "  HOW GNU SYMBOL VERSIONING WORKS\n" RESET);
    printf(CYAN "═══════════════════════════════════════════════════════════════════\n" RESET);
    printf("\n");

    printf("  Symbol versioning allows multiple versions of the same function\n");
    printf("  to exist in a shared library. This enables:\n");
    printf("    • Backwards compatibility (old binaries keep working)\n");
    printf("    • Bug fixes without breaking ABI\n");
    printf("    • Multiple implementations coexisting\n\n");

    printf(YELLOW "  EXAMPLE: realpath() in glibc\n" RESET);
    printf("  ─────────────────────────────────────────────────────────────────\n");
    printf("    realpath@GLIBC_2.2.5  → Original version (has bugs)\n");
    printf("    realpath@GLIBC_2.3    → Fixed version\n");
    printf("\n");
    printf("    Binary compiled against old glibc → gets GLIBC_2.2.5 version\n");
    printf("    Binary compiled against new glibc → gets GLIBC_2.3 version\n");
    printf("\n");

    printf(YELLOW "  ELF SECTIONS INVOLVED:\n" RESET);
    printf("  ─────────────────────────────────────────────────────────────────\n");
    printf("    .gnu.version    → Maps each symbol to a version index\n");
    printf("    .gnu.version_r  → Version requirements (VERNEED)\n");
    printf("    .gnu.version_d  → Version definitions (VERDEF)\n");
    printf("\n");

    printf(YELLOW "  SYMBOL RESOLUTION WITH VERSIONING:\n" RESET);
    printf("  ─────────────────────────────────────────────────────────────────\n");
    printf("\n");
    printf("    Binary needs:     printf@@GLIBC_2.2.5\n");
    printf("                           │\n");
    printf("                           ▼\n");
    printf("    ld.so looks for:  printf with version GLIBC_2.2.5\n");
    printf("                           │\n");
    printf("                           ▼\n");
    printf("    libc provides:    printf@@GLIBC_2.2.5 (default)\n");
    printf("                      printf@GLIBC_2.2.5  (compat, hidden)\n");
    printf("                           │\n");
    printf("                           ▼\n");
    printf("    Match found!      Uses printf@@GLIBC_2.2.5\n");
    printf("\n");

    printf(YELLOW "  ATTACK SURFACE:\n" RESET);
    printf("  ─────────────────────────────────────────────────────────────────\n");
    printf("    1. " RED "Version Hijacking" RESET " - Provide matching versioned symbols\n");
    printf("       via LD_PRELOAD to intercept specific function versions\n\n");
    printf("    2. " RED "Version Downgrade" RESET " - Force use of older, vulnerable\n");
    printf("       versions of functions by providing them first\n\n");
    printf("    3. " RED "Targeted Interception" RESET " - Only intercept calls from\n");
    printf("       binaries linked against specific glibc versions\n");
    printf("\n");
}

void demonstrate_versioning(void) {
    printf(CYAN "═══════════════════════════════════════════════════════════════════\n" RESET);
    printf(CYAN "  DEMONSTRATING VERSIONED SYMBOL CALLS\n" RESET);
    printf(CYAN "═══════════════════════════════════════════════════════════════════\n" RESET);
    printf("\n");

    /* Show that we're using versioned functions */
    printf("  Calling versioned glibc functions:\n\n");

    /* realpath - has versions in glibc */
    printf("    " YELLOW "realpath()" RESET ":\n");
    char resolved[4096];
    char *result = realpath("/etc/passwd", resolved);
    if (result) {
        printf("      Result: %s\n", result);
    }
    printf("      This binary links to: realpath@GLIBC_X.X\n");
    printf("      (Check with: objdump -T ./version_explorer | grep realpath)\n\n");

    /* memcpy - has version GLIBC_2.14 on modern systems */
    printf("    " YELLOW "memcpy()" RESET ":\n");
    char src[] = "test";
    char dst[16];
    memcpy(dst, src, sizeof(src));
    printf("      Result: \"%s\"\n", dst);
    printf("      This binary links to: memcpy@GLIBC_2.14\n");
    printf("      (Version changed behavior between 2.2.5 and 2.14)\n\n");

    /* getenv - common target for hijacking */
    printf("    " YELLOW "getenv()" RESET ":\n");
    char *user = getenv("USER");
    if (user) {
        printf("      USER = %s\n", user);
    }
    printf("      Can be hijacked to steal sensitive env vars!\n\n");
}

int main(int argc, char *argv[]) {
    print_versioning_explanation();
    demonstrate_versioning();

    /* Optionally show version info using system tools */
    if (argc > 1 && strcmp(argv[1], "-v") == 0) {
        printf(CYAN "═══════════════════════════════════════════════════════════════════\n" RESET);
        printf(CYAN "  VERSION REQUIREMENTS (via readelf)\n" RESET);
        printf(CYAN "═══════════════════════════════════════════════════════════════════\n" RESET);
        printf("\n");

        char cmd[256];
        snprintf(cmd, sizeof(cmd), "readelf -V %s 2>/dev/null | head -50", argv[0]);
        printf("  Running: %s\n\n", cmd);
        system(cmd);
    }

    printf(GREEN "[✓] Explorer complete.\n" RESET);
    printf("\n");
    printf("  " YELLOW "Try the hijacking demo:" RESET "\n");
    printf("    make hijack\n\n");

    return 0;
}
