/*
 * versioned_lib.c - Demonstration of Creating Versioned Symbols
 *
 * This library demonstrates how to:
 *   1. Define your own symbol versions
 *   2. Create multiple versions of the same function
 *   3. Set default versions for linking
 *
 * Use with the .map version script to define versions.
 *
 * Compile:
 *   gcc -shared -fPIC -Wl,--version-script=versioned_lib.map \
 *       -o libversioned.so versioned_lib.c
 *
 * EDUCATIONAL PURPOSES ONLY
 */

#include <stdio.h>
#include <string.h>

/* Color codes */
#define RED     "\033[1;31m"
#define GREEN   "\033[1;32m"
#define YELLOW  "\033[1;33m"
#define BLUE    "\033[1;34m"
#define RESET   "\033[0m"

/* ═══════════════════════════════════════════════════════════════════════════
 * VERSION 1.0 - Original implementation (has vulnerabilities)
 * ═══════════════════════════════════════════════════════════════════════════ */

/*
 * process_input_v1 - Old vulnerable version
 * "Bug": Uses unsafe strcpy
 */
char *process_input_v1(char *dest, const char *src) {
    printf(YELLOW "[libversioned V1.0] " RESET "process_input called (OLD VERSION)\n");
    printf("  " RED "Warning: This version uses unsafe strcpy!" RESET "\n");

    /* Simulated vulnerability - no bounds checking */
    strcpy(dest, src);

    return dest;
}

/*
 * get_version_v1 - Returns version string
 */
const char *get_version_v1(void) {
    return "1.0 (vulnerable)";
}

/* ═══════════════════════════════════════════════════════════════════════════
 * VERSION 2.0 - Fixed implementation
 * ═══════════════════════════════════════════════════════════════════════════ */

/*
 * process_input_v2 - Fixed version with bounds checking
 */
char *process_input_v2(char *dest, const char *src, size_t n) {
    printf(GREEN "[libversioned V2.0] " RESET "process_input called (FIXED VERSION)\n");
    printf("  Using strncpy with bounds checking\n");

    strncpy(dest, src, n - 1);
    dest[n - 1] = '\0';

    return dest;
}

/*
 * get_version_v2 - Returns version string
 */
const char *get_version_v2(void) {
    return "2.0 (fixed)";
}

/* ═══════════════════════════════════════════════════════════════════════════
 * VERSION SYMBOL DEFINITIONS
 * ═══════════════════════════════════════════════════════════════════════════
 *
 * The .symver directive creates versioned symbols:
 *   .symver old_name, exported_name@VERSION      (non-default)
 *   .symver new_name, exported_name@@VERSION     (default for linking)
 *
 * Note: @@ means default version (what new programs link against)
 *       @  means compat version (for old binaries)
 */

/* Version 1.0 symbols - compatibility */
__asm__(".symver process_input_v1, process_input@VERS_1.0");
__asm__(".symver get_version_v1, get_version@VERS_1.0");

/* Version 2.0 symbols - default for new binaries */
__asm__(".symver process_input_v2, process_input@@VERS_2.0");
__asm__(".symver get_version_v2, get_version@@VERS_2.0");

/* ═══════════════════════════════════════════════════════════════════════════
 * CONSTRUCTOR - Library initialization
 * ═══════════════════════════════════════════════════════════════════════════ */

__attribute__((constructor))
void libversioned_init(void) {
    printf(BLUE "╔════════════════════════════════════════════════════════════════╗\n" RESET);
    printf(BLUE "║" RESET "  libversioned.so loaded                                        " BLUE "║\n" RESET);
    printf(BLUE "║" RESET "  Provides: process_input@VERS_1.0 (compat)                    " BLUE "║\n" RESET);
    printf(BLUE "║" RESET "            process_input@@VERS_2.0 (default)                  " BLUE "║\n" RESET);
    printf(BLUE "╚════════════════════════════════════════════════════════════════╝\n" RESET);
}
