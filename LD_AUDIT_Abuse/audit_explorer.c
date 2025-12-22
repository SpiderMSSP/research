/*
 * audit_explorer.c - LD_AUDIT Interface Explorer
 *
 * This audit library demonstrates all the callbacks available
 * in the rtld-audit interface. When loaded via LD_AUDIT, it
 * receives notifications about:
 *
 *   - la_version()     : API version negotiation
 *   - la_objsearch()   : Library search path modification
 *   - la_activity()    : Linking activity notifications
 *   - la_objopen()     : Library load notifications
 *   - la_objclose()    : Library unload notifications
 *   - la_preinit()     : Before .init functions run
 *   - la_symbind32/64(): Symbol binding notifications
 *   - la_pltenter()    : PLT entry interception
 *   - la_pltexit()     : PLT exit interception
 *
 * Usage:
 *   LD_AUDIT=./libaudit_explorer.so ./target_program
 *
 * Compile:
 *   gcc -shared -fPIC -o libaudit_explorer.so audit_explorer.c -ldl
 *
 * EDUCATIONAL PURPOSES ONLY
 */

#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <link.h>
#include <dlfcn.h>

/* Color codes */
#define RED     "\033[1;31m"
#define GREEN   "\033[1;32m"
#define YELLOW  "\033[1;33m"
#define BLUE    "\033[1;34m"
#define MAGENTA "\033[1;35m"
#define CYAN    "\033[1;36m"
#define RESET   "\033[0m"

/* Track statistics */
static int libs_loaded = 0;
static int symbols_bound = 0;
static int plt_calls = 0;

/* ═══════════════════════════════════════════════════════════════════════════
 * LA_VERSION - Called first to negotiate API version
 * ═══════════════════════════════════════════════════════════════════════════
 *
 * This MUST be implemented. Returns the audit API version we support.
 * If we return 0 or an unsupported version, the linker ignores us.
 */

unsigned int la_version(unsigned int version) {
    fprintf(stderr, "\n");
    fprintf(stderr, RED "╔════════════════════════════════════════════════════════════════════╗\n" RESET);
    fprintf(stderr, RED "║" YELLOW "              LD_AUDIT INTERFACE EXPLORER                          " RED "║\n" RESET);
    fprintf(stderr, RED "║" RESET "                                                                    " RED "║\n" RESET);
    fprintf(stderr, RED "║" RESET "  Demonstrating the rtld-audit interface callbacks                  " RED "║\n" RESET);
    fprintf(stderr, RED "║" RESET "  This library sees ALL dynamic linking activity!                   " RED "║\n" RESET);
    fprintf(stderr, RED "╚════════════════════════════════════════════════════════════════════╝\n" RESET);
    fprintf(stderr, "\n");

    fprintf(stderr, CYAN "[la_version]" RESET " Linker API version: %u, We support: %u\n\n",
            version, LAV_CURRENT);

    /* Return the version we support */
    return LAV_CURRENT;
}

/* ═══════════════════════════════════════════════════════════════════════════
 * LA_OBJSEARCH - Called when searching for a library
 * ═══════════════════════════════════════════════════════════════════════════
 *
 * We can MODIFY the library search path here!
 * Return NULL to skip this path, or return a different path to redirect.
 */

char *la_objsearch(const char *name, uintptr_t *cookie, unsigned int flag) {
    (void)cookie;

    const char *flag_str;
    switch (flag) {
        case LA_SER_ORIG:     flag_str = "ORIG (original name)"; break;
        case LA_SER_LIBPATH:  flag_str = "LIBPATH (LD_LIBRARY_PATH)"; break;
        case LA_SER_RUNPATH:  flag_str = "RUNPATH (DT_RUNPATH)"; break;
        case LA_SER_CONFIG:   flag_str = "CONFIG (ld.so.cache)"; break;
        case LA_SER_DEFAULT:  flag_str = "DEFAULT (/lib, /usr/lib)"; break;
        case LA_SER_SECURE:   flag_str = "SECURE (secure path)"; break;
        default:              flag_str = "UNKNOWN"; break;
    }

    fprintf(stderr, BLUE "[la_objsearch]" RESET " Searching: %s [%s]\n", name, flag_str);

    /* ATTACK POINT: We could redirect to a malicious library here!
     *
     * Example:
     *   if (strstr(name, "libcrypto")) {
     *       return "/tmp/evil_libcrypto.so";  // Redirect!
     *   }
     */

    return (char *)name;  /* Return original (no modification) */
}

/* ═══════════════════════════════════════════════════════════════════════════
 * LA_ACTIVITY - Called when linking state changes
 * ═══════════════════════════════════════════════════════════════════════════
 */

void la_activity(uintptr_t *cookie, unsigned int flag) {
    (void)cookie;

    const char *activity;
    switch (flag) {
        case LA_ACT_CONSISTENT: activity = "CONSISTENT (linking complete)"; break;
        case LA_ACT_ADD:        activity = "ADD (adding library)"; break;
        case LA_ACT_DELETE:     activity = "DELETE (removing library)"; break;
        default:                activity = "UNKNOWN"; break;
    }

    fprintf(stderr, MAGENTA "[la_activity]" RESET " %s\n", activity);
}

/* ═══════════════════════════════════════════════════════════════════════════
 * LA_OBJOPEN - Called when a library is loaded
 * ═══════════════════════════════════════════════════════════════════════════
 *
 * Returns flags indicating which notifications we want for this library.
 */

unsigned int la_objopen(struct link_map *map, Lmid_t lmid, uintptr_t *cookie) {
    (void)lmid;
    (void)cookie;

    const char *name = map->l_name;
    if (!name || name[0] == '\0') name = "(main executable)";

    libs_loaded++;
    fprintf(stderr, GREEN "[la_objopen]" RESET " #%d Loaded: " GREEN "%s" RESET " @ 0x%lx\n",
            libs_loaded, name, map->l_addr);

    /* ATTACK POINT: We can inspect every library loaded!
     * - Check for security libraries
     * - Detect if running in a sandbox
     * - Identify target application
     */

    /* Return LA_FLG_BINDTO | LA_FLG_BINDFROM to get symbind notifications */
    return LA_FLG_BINDTO | LA_FLG_BINDFROM;
}

/* ═══════════════════════════════════════════════════════════════════════════
 * LA_OBJCLOSE - Called when a library is unloaded
 * ═══════════════════════════════════════════════════════════════════════════
 */

unsigned int la_objclose(uintptr_t *cookie) {
    (void)cookie;
    fprintf(stderr, RED "[la_objclose]" RESET " Library unloaded\n");
    return 0;
}

/* ═══════════════════════════════════════════════════════════════════════════
 * LA_PREINIT - Called before .init functions run
 * ═══════════════════════════════════════════════════════════════════════════
 *
 * This is called AFTER all libraries are loaded but BEFORE any
 * constructors run. Perfect for early code execution!
 */

void la_preinit(uintptr_t *cookie) {
    (void)cookie;

    fprintf(stderr, "\n");
    fprintf(stderr, YELLOW "╔════════════════════════════════════════════════════════════════╗\n" RESET);
    fprintf(stderr, YELLOW "║  [la_preinit] All libraries loaded - .init about to run       ║\n" RESET);
    fprintf(stderr, YELLOW "╚════════════════════════════════════════════════════════════════╝\n" RESET);
    fprintf(stderr, "\n");

    fprintf(stderr, "  Statistics so far:\n");
    fprintf(stderr, "    Libraries loaded: " GREEN "%d" RESET "\n", libs_loaded);
    fprintf(stderr, "    Symbols bound:    " GREEN "%d" RESET "\n", symbols_bound);
    fprintf(stderr, "\n");

    /* ATTACK POINT: Execute code before ANY constructors!
     * Even before LD_PRELOAD library constructors.
     */
}

/* ═══════════════════════════════════════════════════════════════════════════
 * LA_SYMBIND64 - Called for each symbol binding (64-bit)
 * ═══════════════════════════════════════════════════════════════════════════
 *
 * This is where we see EVERY symbol resolution!
 * We can even modify where symbols resolve to!
 */

uintptr_t la_symbind64(Elf64_Sym *sym, unsigned int ndx,
                       uintptr_t *refcook, uintptr_t *defcook,
                       unsigned int *flags, const char *symname) {
    (void)ndx;
    (void)refcook;
    (void)defcook;

    symbols_bound++;

    /* Only show interesting symbols (skip internal ones) */
    if (symname && symname[0] != '_' && strlen(symname) > 2) {
        fprintf(stderr, CYAN "[la_symbind64]" RESET " #%d %s @ 0x%lx\n",
                symbols_bound, symname, (unsigned long)sym->st_value);
    }

    /* ATTACK POINT: We can redirect ANY symbol!
     *
     * Example:
     *   if (strcmp(symname, "getenv") == 0) {
     *       *flags |= LA_SYMB_ALTVALUE;
     *       return (uintptr_t)evil_getenv;  // Redirect!
     *   }
     *
     * Note: For PLT redirection, use la_pltenter instead.
     */

    /* Setting flags:
     * LA_SYMB_NOPLTENTER - Don't call la_pltenter for this symbol
     * LA_SYMB_NOPLTEXIT  - Don't call la_pltexit for this symbol
     * LA_SYMB_ALTVALUE   - We're returning an alternate address
     */

    return sym->st_value;  /* Return original address */
}

/* ═══════════════════════════════════════════════════════════════════════════
 * DESTRUCTOR - Print summary when program exits
 * ═══════════════════════════════════════════════════════════════════════════
 */

__attribute__((destructor))
static void audit_fini(void) {
    fprintf(stderr, "\n");
    fprintf(stderr, RED "╔════════════════════════════════════════════════════════════════════╗\n" RESET);
    fprintf(stderr, RED "║" YELLOW "              LD_AUDIT SESSION COMPLETE                             " RED "║\n" RESET);
    fprintf(stderr, RED "╚════════════════════════════════════════════════════════════════════╝\n" RESET);
    fprintf(stderr, "\n");
    fprintf(stderr, "  Final Statistics:\n");
    fprintf(stderr, "    Libraries loaded: " GREEN "%d" RESET "\n", libs_loaded);
    fprintf(stderr, "    Symbols bound:    " GREEN "%d" RESET "\n", symbols_bound);
    fprintf(stderr, "    PLT calls traced: " GREEN "%d" RESET "\n", plt_calls);
    fprintf(stderr, "\n");
}
